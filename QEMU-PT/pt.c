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
#include "cpu.h"
#include "pt.h"
#include "pt/decoder.h"
#include "exec/memory.h"
#include "sysemu/kvm_int.h"
#include "sysemu/kvm.h"
#include "sysemu/cpus.h"
#include "pt/hypercall.h"
#include "pt/logger.h"
#include "pt/memory_access.h"
#include "pt/interface.h"

extern uint32_t kafl_bitmap_size;
uint8_t* bitmap = NULL;
uint64_t last_ip = 0ULL;

static void pt_set(CPUState *cpu, run_on_cpu_data arg){
	asm volatile("" ::: "memory");
}

static inline int pt_cmd_hmp_context(CPUState *cpu, uint64_t cmd){
	cpu->pt_ret = -1;
	if(pt_hypercalls_enabled()){
		printf("Error: HMP commands are ignored if kafl tracing mode is enabled (-kafl)!\n");
	}
	else{
		cpu->pt_cmd = cmd;
		run_on_cpu(cpu, pt_set, RUN_ON_CPU_NULL);
	}
	return cpu->pt_ret;
}

static int pt_cmd(CPUState *cpu, uint64_t cmd, bool hmp_mode){
	if (hmp_mode){
		return pt_cmd_hmp_context(cpu, cmd);
	}
	else {
		cpu->pt_cmd = cmd;
		pt_pre_kvm_run(cpu);
		return cpu->pt_ret;
	}
}

static inline int pt_ioctl(int fd, unsigned long request, unsigned long arg){
	if (!fd){
		return -EINVAL;
	}
	return ioctl(fd, request, arg);
}

void pt_setup_bitmap(void* ptr){
	bitmap = (uint8_t*)ptr;
}

static void pt_reset_bitmap(void){
	uint32_t i;
	if(bitmap){
		last_ip = 0ULL;
		for(i = 0; i < kafl_bitmap_size; i++){
			bitmap[i] = 0xff;
		}
	}
}

static inline uint64_t mix_bits(uint64_t v) {
  v ^= (v >> 31);
  v *= 0x7fb5d329728ea185;
  v ^= (v >> 27);
  v *= 0x81dadef4bc2dd44d;
  v ^= (v >> 33);
  return v;
}

static void pt_bitmap(uint64_t addr){
	uint32_t transition_value = 0;
	#ifdef SAMPLE_DECODED
	sample_decoded(addr);
	#endif
	if(bitmap){		
		/* vertex filter */
		hypercall_submit_address(addr);
		if(!hypercall_check_tuple(addr, last_ip)){
			/* edge filter */
			addr = mix_bits(addr);
			transition_value = (addr ^ (last_ip >> 1)) & 0xffffff;
			hypercall_submit_transition(transition_value);
			if(!hypercall_check_transition(transition_value)){
				/* apply transition to kAFL bitmap */
				bitmap[transition_value & (kafl_bitmap_size-1)]++;
			}
		}
		else{
			return;
		}
	}
	last_ip = addr; 
}

void pt_dump(CPUState *cpu, int bytes){
#ifdef SAMPLE_RAW
	sample_raw(cpu->pt_mmap, bytes);
#endif
#ifdef SAMPLE_RAW_SINGLE
	sample_raw_single(cpu->pt_mmap, bytes);
#endif
	for(uint8_t i = 0; i < INTEL_PT_MAX_RANGES; i++){
		if(cpu->pt_ip_filter_enabled[i]){
			if (cpu->pt_target_file){
				fwrite(cpu->pt_mmap, sizeof(char), bytes, cpu->pt_target_file);
			}
			decode_buffer(cpu->pt_decoder_state[i], cpu->pt_mmap, bytes);
		}
	}
	cpu->trace_size += bytes;
}


int pt_enable(CPUState *cpu, bool hmp_mode){
#ifdef SAMPLE_RAW
	init_sample_raw();
#endif
#ifdef SAMPLE_RAW_SINGLE
	init_sample_raw_single(getpid());
#endif
#ifdef SAMPLE_DECODED
	init_sample_decoded();
#endif
#ifdef SAMPLE_DECODED_DETAILED
	init_sample_decoded_detailed();
#endif
	pt_reset_bitmap();
	return pt_cmd(cpu, KVM_VMX_PT_ENABLE, hmp_mode);
}
	
int pt_disable(CPUState *cpu, bool hmp_mode){
	for(uint8_t i = 0; i < INTEL_PT_MAX_RANGES; i++){
		if(cpu->pt_ip_filter_enabled[i]){
			pt_decoder_flush(cpu->pt_decoder_state[i]);
		}
	}
	return pt_cmd(cpu, KVM_VMX_PT_DISABLE, hmp_mode);
	
}

int pt_set_cr3(CPUState *cpu, uint64_t val, bool hmp_mode){
	int r = 0;
	if (cpu->pt_enabled){
		return -EINVAL;
	}
	cpu->pt_c3_filter = val;
	r += pt_cmd(cpu, KVM_VMX_PT_CONFIGURE_CR3, hmp_mode);
	r += pt_cmd(cpu, KVM_VMX_PT_ENABLE_CR3, hmp_mode);
	return r;
}

int pt_enable_ip_filtering(CPUState *cpu, uint8_t addrn, uint64_t ip_a, uint64_t ip_b, bool hmp_mode){
	int r = 0;
	uint8_t* buf;

	if(addrn > 3){
		return -1;
	}

	if (cpu->pt_enabled){
		return -EINVAL;
	}
		
	if(ip_a > ip_b){
		printf("FAIL 1\n");
		return -EINVAL;
	}

	if(cpu->pt_ip_filter_enabled[addrn]){
		pt_disable_ip_filtering(cpu, addrn, hmp_mode);
	}

	buf = malloc(ip_b-ip_a);
	if(!read_virtual_memory(ip_a, buf, ip_b-ip_a, cpu)){
		printf("FAIL 2\n");
		free(buf);
		return -EINVAL;
	}

#ifdef CREATE_VM_IMAGE
	FILE* pt_file = fopen(DECODER_MEMORY_IMAGE, "wb");
	fwrite(buf, sizeof(uint8_t), ip_b-ip_a, pt_file);
	fclose(pt_file);
#endif


	printf("--> %d %lx %lx\n", addrn, ip_a, ip_b);
	
	switch(addrn){
		case 0:
		case 1:
		case 2:
		case 3:
			cpu->pt_ip_filter_a[addrn] = ip_a;
			cpu->pt_ip_filter_b[addrn] = ip_b;
			r += pt_cmd(cpu, KVM_VMX_PT_CONFIGURE_ADDR0+addrn, hmp_mode);
			r += pt_cmd(cpu, KVM_VMX_PT_ENABLE_ADDR0+addrn, hmp_mode);
			cpu->pt_ip_filter_enabled[addrn] = true;
			cpu->pt_decoder_state[addrn] = pt_decoder_init(buf, ip_a, ip_b, &pt_bitmap);
			break;
		default:
			r = -EINVAL;
	}
	return r;
}

int pt_disable_ip_filtering(CPUState *cpu, uint8_t addrn, bool hmp_mode){
	int r = 0;
	switch(addrn){
		case 0:
		case 1:
		case 2:
		case 3:
			r = pt_cmd(cpu, KVM_VMX_PT_DISABLE_ADDR0+addrn, hmp_mode);
			if(cpu->pt_ip_filter_enabled[addrn]){
				cpu->pt_ip_filter_enabled[addrn] = false;
				pt_decoder_destroy(cpu->pt_decoder_state[addrn]);
			}
			break;
		default:
			r = -EINVAL;
	}
	return r;
}

void pt_kvm_init(CPUState *cpu){
	int i;

	cpu->pt_cmd = 0;
	cpu->pt_arg = 0;
	cpu->pt_enabled = false;
	cpu->pt_fd = 0;
	cpu->pt_features = 0;

	for(i = 0; i < INTEL_PT_MAX_RANGES; i++){
		cpu->pt_ip_filter_enabled[i] = false;
		cpu->pt_ip_filter_a[i] = 0x0;
		cpu->pt_ip_filter_b[i] = 0x0;
		cpu->pt_decoder_state[i] = NULL;
	}

	cpu->pt_c3_filter = 0;
	cpu->pt_target_file = NULL;
	cpu->overflow_counter = 0;
	cpu->trace_size = 0;
	cpu->reload_pending = false;
}

struct vmx_pt_filter_iprs {
	__u64 a;
	__u64 b;
};

void pt_pre_kvm_run(CPUState *cpu){
	int ret;
	struct vmx_pt_filter_iprs filter_iprs;
	
	if (!cpu->pt_fd) {
		cpu->pt_fd = kvm_vcpu_ioctl(cpu, KVM_VMX_PT_SETUP_FD, (unsigned long)0);
		ret = ioctl(cpu->pt_fd, KVM_VMX_PT_GET_TOPA_SIZE, (unsigned long)0x0);
		cpu->pt_mmap = mmap(0, ret, PROT_READ, MAP_SHARED, cpu->pt_fd, 0);
	}
	
	if (cpu->pt_cmd){
		switch(cpu->pt_cmd){
			case KVM_VMX_PT_ENABLE:
				if (cpu->pt_fd){
					if (!ioctl(cpu->pt_fd, cpu->pt_cmd, cpu->pt_arg)){
						cpu->pt_enabled = true;
					}
				}
				break;
			case KVM_VMX_PT_DISABLE:
				if (cpu->pt_fd){
					ret = ioctl(cpu->pt_fd, cpu->pt_cmd, cpu->pt_arg);
					if (ret > 0){
						pt_dump(cpu, ret);
						cpu->pt_enabled = false;
					}
				}
				break;
			
			/* ip filtering configuration */	
			case KVM_VMX_PT_CONFIGURE_ADDR0:
			case KVM_VMX_PT_CONFIGURE_ADDR1:
			case KVM_VMX_PT_CONFIGURE_ADDR2:
			case KVM_VMX_PT_CONFIGURE_ADDR3:
				filter_iprs.a = cpu->pt_ip_filter_a[(cpu->pt_cmd)-KVM_VMX_PT_CONFIGURE_ADDR0];
	   			filter_iprs.b = cpu->pt_ip_filter_b[(cpu->pt_cmd)-KVM_VMX_PT_CONFIGURE_ADDR0];
				ret = pt_ioctl(cpu->pt_fd, cpu->pt_cmd, (unsigned long)&filter_iprs);
				break;
			case KVM_VMX_PT_ENABLE_ADDR0:
			case KVM_VMX_PT_ENABLE_ADDR1:
			case KVM_VMX_PT_ENABLE_ADDR2:
			case KVM_VMX_PT_ENABLE_ADDR3:
				ret = pt_ioctl(cpu->pt_fd, cpu->pt_cmd, (unsigned long)0);
				break;
			case KVM_VMX_PT_CONFIGURE_CR3:
				ret = pt_ioctl(cpu->pt_fd, cpu->pt_cmd, cpu->pt_c3_filter);
				break;
			case KVM_VMX_PT_ENABLE_CR3:
				ret = pt_ioctl(cpu->pt_fd, cpu->pt_cmd, (unsigned long)0);
				break;
			default:
				if (cpu->pt_fd){
					ioctl(cpu->pt_fd, cpu->pt_cmd, cpu->pt_arg);  
				}
				break;
			}
		cpu->pt_cmd = 0;
		cpu->pt_ret = 0;
	}
}

void pt_post_kvm_run(CPUState *cpu){
	int overflow;
	if (cpu->pt_enabled){
		overflow = ioctl(cpu->pt_fd, KVM_VMX_PT_CHECK_TOPA_OVERFLOW, (unsigned long)0);
		if (overflow > 0){
			cpu->overflow_counter++;
			pt_dump(cpu, overflow);
		}    
	}
}
