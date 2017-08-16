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
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include "qemu-common.h"
#include "exec/memory.h"
#include "sysemu/kvm_int.h"
#include "sysemu/kvm.h"
#include "pt.h"
#include "pt/hypercall.h"
#include "pt/filter.h"
#include "pt/memory_access.h"
#include "pt/interface.h"

bool hypercall_enabled = false;
void* payload_buffer = NULL;
void* payload_buffer_guest = NULL;
void* program_buffer = NULL;
char info_buffer[INFO_SIZE];
void* argv = NULL;

static bool mutex_init = false;
static bool mutex_locked = false;
static bool init_state = true;
pthread_mutex_t lock;

void (*handler)(char, void*) = NULL; 
void* s = NULL;

uint64_t filter[INTEL_PT_MAX_RANGES][2];
bool filter_enabled[INTEL_PT_MAX_RANGES] = {false, false, false, false};
/* vertex filter */
filter_t *det_filter[INTEL_PT_MAX_RANGES] = {NULL, NULL, NULL, NULL};
/* edge filter */
filter_t *det_tfilter = NULL;
bool det_filter_enabled[INTEL_PT_MAX_RANGES] = {false, false, false, false};

static void hypercall_lock(void);
static bool hypercall_snd_char(char val);

bool pt_hypercalls_enabled(void){
	return hypercall_enabled;
}

void pt_setup_enable_hypercalls(void){
	hypercall_enabled = true;
}

void pt_setup_snd_handler(void (*tmp)(char, void*), void* tmp_s){
	s = tmp_s;
	handler = tmp;
}

static bool hypercall_snd_char(char val){
	if (handler != NULL){
		handler(val, s);
		return true;
	}
	return false;
}

void pt_setup_ip_filters(uint8_t filter_id, uint64_t start, uint64_t end, void* filter_bitmap, void* tfilter_bitmap){
	if (filter_id < INTEL_PT_MAX_RANGES){
		filter_enabled[filter_id] = true;
		filter[filter_id][0] = start;
		filter[filter_id][1] = end;
		if (filter_bitmap){
			det_filter[filter_id] = new_filter(start, end, filter_bitmap);
			//printf("det_filter enabled\n");
			if(!det_tfilter){
				det_tfilter = new_filter(0, DEFAULT_EDGE_FILTER_SIZE, tfilter_bitmap);
				//printf("det_tfilter enabled\n");
			}
		}
	}
}

static inline void init_det_filter(void){
	int i;
	for(i = 0; i < INTEL_PT_MAX_RANGES; i++){
		if (det_filter_enabled[i]){
			filter_init_new_exec(det_filter[i]);
			filter_init_new_exec(det_tfilter);
		}	
	}
}

static inline void fin_det_filter(void){
	//printf("%s \n", __func__);
	for(int i = 0; i < INTEL_PT_MAX_RANGES; i++){
		if (det_filter_enabled[i]){
			filter_finalize_exec(det_filter[i]);
			filter_finalize_exec(det_tfilter);
		}
	}
}

void hypercall_submit_address(uint64_t address){
	for(int i = 0; i < INTEL_PT_MAX_RANGES; i++){
		if(det_filter[i] && det_filter_enabled[i]){
			//printf("%s %lx \n", __func__, address);
			filter_add_address(det_filter[i], address);
		}
	}
}

void hypercall_submit_transition(uint32_t value){
	for(int i = 0; i < INTEL_PT_MAX_RANGES; i++){
		if(det_tfilter && det_filter_enabled[i]){
			//printf("%s %lx \n", __func__, value);
			filter_add_address(det_tfilter, value);
		}
	}
}

bool hypercall_check_tuple(uint64_t current_addr, uint64_t prev_addr){
	for(int i = 0; i < INTEL_PT_MAX_RANGES; i++){
		if(det_filter[i]){
			if(filter_is_address_nondeterministic(det_filter[i], current_addr) ||  filter_is_address_nondeterministic(det_filter[i], prev_addr)){
				return true;
			}
		}
	}
	return false;
}

bool hypercall_check_transition(uint64_t value){
	for(int i = 0; i < INTEL_PT_MAX_RANGES; i++){
		if(det_tfilter){
			if(filter_is_address_nondeterministic(det_tfilter, value)){
				return true;
			}
		}
	}
	return false;
}


void hypercall_check_in_range(uint64_t* addr){
	for(int i = 0; i < INTEL_PT_MAX_RANGES; i++){
		if (*addr < filter[i][0]){
			*addr = filter[i][0];
			return;
		}

		if (*addr > filter[i][1]){
			*addr = filter[i][1];
			return;
		}
	}
}

void hypercall_enable_filter(void){
	for(int i = 0; i < INTEL_PT_MAX_RANGES; i++){
		if(det_filter[i] && !det_filter_enabled[i]){
			//printf("%s (%d)\n", __func__, i);
			det_filter_enabled[i] = true;
			filter_init_determinism_run(det_filter[i]);
			filter_init_determinism_run(det_tfilter);
		}
	}
}

void hypercall_disable_filter(void){
	for(int i = 0; i < INTEL_PT_MAX_RANGES; i++){
		if(det_filter[i] && det_filter_enabled[i]){
			//printf("%s (%d)\n", __func__, i);
			filter_finalize_determinism_run(det_filter[i]);
			if(!filter_count_new_addresses(det_filter[i])){
				filter_finalize_determinism_run(det_tfilter);
			}
			det_filter_enabled[i] = false;
		}
	}
}

void hypercall_commit_filter(void){
	fin_det_filter();
}

void hypercall_unlock(void){
	if (mutex_locked){
		mutex_locked = false;
		pthread_mutex_unlock(&lock);
	}
}

void hypercall_reload(void){
	CPUState *cpu = qemu_get_cpu(0);
	cpu->reload_pending = true;
	hypercall_unlock();
	//cpu_synchronize_state(cpu);
	kvm_cpu_synchronize_state(cpu);
	init_state = true;
}

/* ToDO: Mutual exclusion */
static void hypercall_lock(void){
	if(!mutex_init){
		//pthread_mutex_init(&lock, NULL);
		pthread_mutex_lock(&lock);
		mutex_init = true;
	}
	if(!mutex_locked){
		mutex_locked = true;
		hypercall_snd_char(KAFL_PROTO_ACQUIRE);
		pthread_mutex_lock(&lock);
	}
}

void pt_setup_program(void* ptr){
	program_buffer = ptr;
}

void pt_setup_payload(void* ptr){
	payload_buffer = ptr;
}

void pt_disable_wrapper(CPUState *cpu){
	int ret = pt_disable(cpu, false);
	//fin_det_filter();
	if (ret > 0){
		pt_dump(cpu, ret);
		cpu->pt_enabled = false;
	}
}

void handle_hypercall_kafl_next_payload(struct kvm_run *run, CPUState *cpu){
	if(hypercall_enabled){
		if (init_state){
			hypercall_lock();
		} else {
			hypercall_lock();
			write_virtual_memory((uint64_t)payload_buffer_guest, payload_buffer, PAYLOAD_SIZE, cpu);
		}
	}
}

void handle_hypercall_kafl_acquire(struct kvm_run *run, CPUState *cpu){
	if(hypercall_enabled){
		if (!init_state){
			init_det_filter();
			if (pt_enable(cpu, false) == 0){
				cpu->pt_enabled = true;
			}
		}
	}
}

void handle_hypercall_get_payload(struct kvm_run *run, CPUState *cpu){
	if(hypercall_enabled){
		if(payload_buffer){
			payload_buffer_guest = (void*)run->hypercall.args[0];
			write_virtual_memory((uint64_t)payload_buffer_guest, payload_buffer, PAYLOAD_SIZE, cpu);
		}
	}
}

void handle_hypercall_get_program(struct kvm_run *run, CPUState *cpu){
	if(hypercall_enabled){
		if(program_buffer){
			printf("Program: %lx\n", (uint64_t)run->hypercall.args[0]);
			write_virtual_memory((uint64_t)run->hypercall.args[0], program_buffer, PROGRAM_SIZE, cpu);
			//printf("Done!\n");
		}
	}
}

void handle_hypercall_kafl_release(struct kvm_run *run, CPUState *cpu){
	if(hypercall_enabled){
		if (init_state){
			init_state = false;	
			for(int i = 0; i < INTEL_PT_MAX_RANGES; i++){
				if(filter_enabled[i]){
					pt_enable_ip_filtering(cpu, i, filter[i][0], filter[i][1], false);
				}
			}
			hypercall_snd_char(KAFL_PROTO_RELEASE);
		} else {
			pt_disable_wrapper(cpu);
		}
	}
}

void handle_hypercall_kafl_cr3(struct kvm_run *run, CPUState *cpu){
	if(hypercall_enabled){
		printf("CR3: %lx\n", (uint64_t)run->hypercall.args[0]);
		pt_set_cr3(cpu, run->hypercall.args[0], false);
	}
}

void handle_hypercall_kafl_submit_panic(struct kvm_run *run, CPUState *cpu){
	if(hypercall_enabled){
		printf("PANIC: %lx\n", (uint64_t)run->hypercall.args[0]);
		write_virtual_memory((uint64_t)run->hypercall.args[0], (uint8_t*)PANIC_PAYLOAD, PAYLOAD_BUFFER_SIZE, cpu);
	}
}

void handle_hypercall_kafl_submit_kasan(struct kvm_run *run, CPUState *cpu){
	if(hypercall_enabled){
		printf("KASAN: %lx\n", (uint64_t)run->hypercall.args[0]);
		write_virtual_memory((uint64_t)run->hypercall.args[0], (uint8_t*)KASAN_PAYLOAD, PAYLOAD_BUFFER_SIZE, cpu);
	}
}

void handle_hypercall_kafl_panic(struct kvm_run *run, CPUState *cpu){
	printf("PANIC!\n");
	if(hypercall_enabled){
		pt_disable_wrapper(cpu);
		hypercall_snd_char(KAFL_PROTO_CRASH);
		//hypercall_reload();
	}
}

void handle_hypercall_kafl_kasan(struct kvm_run *run, CPUState *cpu){
	printf("KASAN!\n");
	if(hypercall_enabled){
		pt_disable_wrapper(cpu);
		hypercall_snd_char(KAFL_PROTO_KASAN);
		//hypercall_reload();
	}
}

void handle_hypercall_kafl_lock(struct kvm_run *run, CPUState *cpu){
	printf("kAFL: VM PAUSED - CREATE SNAPSHOT NOW!\n");
	vm_stop(RUN_STATE_PAUSED);
}

void handle_hypercall_kafl_info(struct kvm_run *run, CPUState *cpu){
	read_virtual_memory((uint64_t)run->hypercall.args[0], (uint8_t*)info_buffer, INFO_SIZE, cpu);
	FILE* info_file_fd = fopen(INFO_FILE, "w");
	fprintf(info_file_fd, "%s\n", info_buffer);
	fclose(info_file_fd);
	if(hypercall_enabled){
		hypercall_snd_char(KAFL_PROTO_INFO);
	}
	qemu_system_shutdown_request();
}
