/*

Copyright (C) 2017 Sergej Schumilo

This file is part of QEMU-PT (kAFL).

QEMU-PT is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

QEMU-PT is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with QEMU-PT.  If not, see <http://www.gnu.org/licenses/>.

*/

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/cutils.h"
#include "hw/hw.h"
#include "hw/i386/pc.h"
#include "hw/pci/pci.h"
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"
#include "sysemu/kvm.h"
#include "migration/migration.h"
#include "qemu/error-report.h"
#include "qemu/event_notifier.h"
#include "qom/object_interfaces.h"
#include "sysemu/char.h"
#include "sysemu/hostmem.h"
#include "sysemu/qtest.h"
#include "qapi/visitor.h"
#include "exec/ram_addr.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include "pt.h"
#include "pt/hypercall.h"
#include "pt/filter.h"
#include "pt/interface.h"
#include <time.h>

#define CONVERT_UINT64(x) (uint64_t)(strtoull(x, NULL, 16))

#define TYPE_KAFLMEM "kafl"
#define KAFLMEM(obj) \
		OBJECT_CHECK(kafl_mem_state, (obj), TYPE_KAFLMEM)

uint32_t kafl_bitmap_size = DEFAULT_KAFL_BITMAP_SIZE;

static void pci_kafl_guest_realize(PCIDevice *dev, Error **errp);

typedef struct kafl_mem_state {
	PCIDevice parent_obj;

	Chardev *kafl_chr_drv_state;
	CharBackend chr;
	
	char* data_bar_fd_0;
	char* data_bar_fd_1;
	char* data_bar_fd_2;
	char* bitmap_file;

	char* filter_bitmap[4];
	char* ip_filter[4][2];

	bool irq_filter;
	uint64_t bitmap_size;
	
} kafl_mem_state;

static void kafl_guest_event(void *opaque, int event){
}

static void send_char(char val, void* tmp_s){
	kafl_mem_state *s = tmp_s;
	qemu_chr_fe_write(&s->chr, (const uint8_t *) &val, 1);
}

static int kafl_guest_can_receive(void * opaque){
	return sizeof(int64_t);
}

static void kafl_guest_receive(void *opaque, const uint8_t * buf, int size){
	kafl_mem_state *s = opaque;
	int i;				
	for(i = 0; i < size; i++){
		switch(buf[i]){
			case KAFL_PROTO_ACQUIRE:
				hypercall_unlock();
				break;

			case KAFL_PROTO_RELOAD:
				send_char(KAFL_PROTO_RELOAD, s);
				hypercall_reload();
				break;

			/* active sampling mode */
			case KAFL_PROTO_ENABLE_SAMPLING:	
				hypercall_enable_filter();
				break;

			/* deactivate sampling mode */
			case KAFL_PROTO_DISABLE_SAMPLING:
				hypercall_disable_filter();
				break;

			/* commit sampling result */
			case KAFL_PROTO_COMMIT_FILTER:
				hypercall_commit_filter();
				break;

			/* finalize iteration (dump and decode PT data) in case of timeouts */
			case KAFL_PROTO_FINALIZE:
				pt_disable_wrapper(qemu_get_cpu(0));
				send_char('F', s);
				break;
		}
	}
}

static int kafl_guest_create_memory_bar(kafl_mem_state *s, int region_num, uint64_t bar_size, const char* file, Error **errp){
	void * ptr;
	int fd;
	struct stat st;
	
	fd = open(file, O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);
	assert(ftruncate(fd, bar_size) == 0);
	stat(file, &st);
	printf("%lu %lu\n", bar_size, st.st_size);
	
	assert(bar_size == st.st_size);
	ptr = mmap(0, bar_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED) {
		error_setg_errno(errp, errno, "Failed to mmap memory");
		return -1;
	}

	switch(region_num){
		case 1:	pt_setup_program((void*)ptr);
				break;
		case 2:	pt_setup_payload((void*)ptr);
				break;
	}

	pt_setup_snd_handler(&send_char, s);

	return 0;
}

static void kafl_guest_setup_bitmap(kafl_mem_state *s, uint32_t bitmap_size){
	void * ptr;
	int fd;
	struct stat st;
	
	fd = open(s->bitmap_file, O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);
	assert(ftruncate(fd, bitmap_size) == 0);
	stat(s->bitmap_file, &st);
	assert(bitmap_size == st.st_size);
	ptr = mmap(0, bitmap_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	pt_setup_bitmap((void*)ptr);
}

static void* kafl_guest_setup_filter_bitmap(kafl_mem_state *s, char* filter, uint64_t size){
	void * ptr;
	int fd;
	struct stat st;
	
	printf("FILE: %s\n", filter);
	fd = open(filter, O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);
	stat(filter, &st);
	if (st.st_size != size){
		assert(ftruncate(fd, size) == 0);
	}
	ptr = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	printf("SIZE: %lx, %p\n", size, ptr);
	return ptr;
	//pt_setup_bitmap((void*)ptr);
}

static void pci_kafl_guest_realize(PCIDevice *dev, Error **errp){
	uint64_t tmp0, tmp1;
	kafl_mem_state *s = KAFLMEM(dev);
	void* tmp = NULL;

	void* tfilter = kafl_guest_setup_filter_bitmap(s, (char*) "/dev/shm/kafl_tfilter", DEFAULT_EDGE_FILTER_SIZE);

	if(s->bitmap_size <= 0){
		s->bitmap_size = DEFAULT_KAFL_BITMAP_SIZE;
	}
	kafl_bitmap_size = (uint32_t)s->bitmap_size;
	
	if (s->data_bar_fd_0 != NULL)
		kafl_guest_create_memory_bar(s, 1, PROGRAM_SIZE, s->data_bar_fd_0, errp);
	if (s->data_bar_fd_1 != NULL)
		kafl_guest_create_memory_bar(s, 2, PAYLOAD_SIZE, s->data_bar_fd_1, errp);
	
	if(&s->chr)
		qemu_chr_fe_set_handlers(&s->chr, kafl_guest_can_receive, kafl_guest_receive, kafl_guest_event, s, NULL, true);
	if(s->bitmap_file)
		kafl_guest_setup_bitmap(s, kafl_bitmap_size);

	for(uint8_t i = 0; i < INTEL_PT_MAX_RANGES; i++){
		if(s->ip_filter[i][0] && s->ip_filter[i][1]){
			tmp0 = CONVERT_UINT64(s->ip_filter[i][0]);
			tmp1 = CONVERT_UINT64(s->ip_filter[i][1]);
			if (tmp0 < tmp1){
				tmp = NULL;
				if(s->filter_bitmap[i]){
					tmp = kafl_guest_setup_filter_bitmap(s, s->filter_bitmap[i], (uint64_t)(tmp1-tmp0));
				}
				pt_setup_ip_filters(i, tmp0, tmp1, tmp, tfilter);
			}
		}
	}

	if(s->irq_filter){
	}

	pt_setup_enable_hypercalls();
}

static Property kafl_guest_properties[] = {
	DEFINE_PROP_CHR("chardev", kafl_mem_state, chr),
	DEFINE_PROP_STRING("shm0", kafl_mem_state, data_bar_fd_0),
	DEFINE_PROP_STRING("shm1", kafl_mem_state, data_bar_fd_1),
	DEFINE_PROP_STRING("bitmap", kafl_mem_state, bitmap_file),
	DEFINE_PROP_STRING("filter0", kafl_mem_state, filter_bitmap[0]),
	DEFINE_PROP_STRING("filter1", kafl_mem_state, filter_bitmap[1]),
	DEFINE_PROP_STRING("filter2", kafl_mem_state, filter_bitmap[2]),
	DEFINE_PROP_STRING("filter3", kafl_mem_state, filter_bitmap[3]),
	/* 
	 * Since DEFINE_PROP_UINT64 is somehow broken (signed/unsigned madness),
	 * let's use DEFINE_PROP_STRING and post-process all values by strtol...
	 */
	DEFINE_PROP_STRING("ip0_a", kafl_mem_state, ip_filter[0][0]),
	DEFINE_PROP_STRING("ip0_b", kafl_mem_state, ip_filter[0][1]),
	DEFINE_PROP_STRING("ip1_a", kafl_mem_state, ip_filter[1][0]),
	DEFINE_PROP_STRING("ip1_b", kafl_mem_state, ip_filter[1][1]),
	DEFINE_PROP_STRING("ip2_a", kafl_mem_state, ip_filter[2][0]),
	DEFINE_PROP_STRING("ip2_b", kafl_mem_state, ip_filter[2][1]),
	DEFINE_PROP_STRING("ip3_a", kafl_mem_state, ip_filter[3][0]),
	DEFINE_PROP_STRING("ip3_b", kafl_mem_state, ip_filter[3][1]),
	DEFINE_PROP_BOOL("irq_filter", kafl_mem_state, irq_filter, false),
	DEFINE_PROP_UINT64("bitmap_size", kafl_mem_state, bitmap_size, DEFAULT_KAFL_BITMAP_SIZE),
	
	DEFINE_PROP_END_OF_LIST(),
};

static void kafl_guest_class_init(ObjectClass *klass, void *data){
	DeviceClass *dc = DEVICE_CLASS(klass);
	PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);
	k->realize = pci_kafl_guest_realize;
	k->class_id = PCI_CLASS_MEMORY_RAM;
	dc->props = kafl_guest_properties;
	set_bit(DEVICE_CATEGORY_MISC, dc->categories);
	dc->desc = "KAFL Inter-VM shared memory";
}

static void kafl_guest_init(Object *obj){
}

static const TypeInfo kafl_guest_info = {
	.name          = TYPE_KAFLMEM,
	.parent        = TYPE_PCI_DEVICE,
	.instance_size = sizeof(kafl_mem_state),
	.instance_init = kafl_guest_init,
	.class_init    = kafl_guest_class_init,
};

static void kafl_guest_register_types(void){
	type_register_static(&kafl_guest_info);
}

type_init(kafl_guest_register_types)
