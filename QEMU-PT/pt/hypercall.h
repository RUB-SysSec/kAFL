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

#ifndef HYPERCALL_H
#define HYPERCALL_H

#define KAFL_NEXT_PAYLOAD

#define PAYLOAD_BUFFER_SIZE		26

/*
 * Panic Notifier Payload (x86-64)
 * fa                      cli
 * 48 c7 c0 1f 00 00 00    mov    rax,0x1f
 * 48 c7 c3 08 00 00 00    mov    rbx,0x8
 * 48 c7 c1 00 00 00 00    mov    rcx,0x0
 * 0f 01 c1                vmcall
 * f4                      hlt
 */
#define PANIC_PAYLOAD "\xFA\x48\xC7\xC0\x1F\x00\x00\x00\x48\xC7\xC3\x08\x00\x00\x00\x48\xC7\xC1\x00\x00\x00\x00\x0F\x01\xC1\xF4"

/*
 * KASAN Notifier Payload (x86-64)
 * fa                      cli
 * 48 c7 c0 1f 00 00 00    mov    rax,0x1f
 * 48 c7 c3 08 00 00 00    mov    rbx,0x9
 * 48 c7 c1 00 00 00 00    mov    rcx,0x0
 * 0f 01 c1                vmcall
 * f4                      hlt
 */
#define KASAN_PAYLOAD "\xFA\x48\xC7\xC0\x1F\x00\x00\x00\x48\xC7\xC3\x09\x00\x00\x00\x48\xC7\xC1\x00\x00\x00\x00\x0F\x01\xC1\xF4"

void pt_setup_program(void* ptr);
void pt_setup_payload(void* ptr);
void pt_setup_snd_handler(void (*tmp)(char, void*), void* tmp_s);
void pt_setup_ip_filters(uint8_t filter_id, uint64_t start, uint64_t end, void* filter_bitmap, void* tfilter_bitmap);
void pt_setup_enable_hypercalls(void);

void pt_disable_wrapper(CPUState *cpu);

void hypercall_submit_address(uint64_t address);
bool hypercall_check_tuple(uint64_t current_addr, uint64_t prev_addr);
void hypercall_check_in_range(uint64_t* addr);


bool hypercall_check_transition(uint64_t value);
void hypercall_submit_transition(uint32_t value);

void hypercall_enable_filter(void);
void hypercall_disable_filter(void);
void hypercall_commit_filter(void);

bool pt_hypercalls_enabled(void);

void hypercall_unlock(void);
void hypercall_reload(void);

void handle_hypercall_kafl_acquire(struct kvm_run *run, CPUState *cpu);
void handle_hypercall_get_payload(struct kvm_run *run, CPUState *cpu);
void handle_hypercall_get_program(struct kvm_run *run, CPUState *cpu);
void handle_hypercall_kafl_release(struct kvm_run *run, CPUState *cpu);
void handle_hypercall_kafl_cr3(struct kvm_run *run, CPUState *cpu);
void handle_hypercall_kafl_submit_panic(struct kvm_run *run, CPUState *cpu);
void handle_hypercall_kafl_submit_kasan(struct kvm_run *run, CPUState *cpu);
void handle_hypercall_kafl_panic(struct kvm_run *run, CPUState *cpu);
void handle_hypercall_kafl_kasan(struct kvm_run *run, CPUState *cpu);
void handle_hypercall_kafl_lock(struct kvm_run *run, CPUState *cpu);
void handle_hypercall_kafl_info(struct kvm_run *run, CPUState *cpu);

#ifdef KAFL_NEXT_PAYLOAD
void handle_hypercall_kafl_next_payload(struct kvm_run *run, CPUState *cpu);
#endif

#endif