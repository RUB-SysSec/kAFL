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

#ifndef PT_H
#define PT_H

void pt_setup_bitmap(void* ptr);

int pt_enable(CPUState *cpu, bool hmp_mode);
int pt_disable(CPUState *cpu, bool hmp_mode);
int pt_enable_ip_filtering(CPUState *cpu, uint8_t addrn, uint64_t ip_a, uint64_t ip_b, bool hmp_mode);
int pt_disable_ip_filtering(CPUState *cpu, uint8_t addrn, bool hmp_mode);
int pt_set_cr3(CPUState *cpu, uint64_t val, bool hmp_mode);

void pt_kvm_init(CPUState *cpu);
void pt_pre_kvm_run(CPUState *cpu);
void pt_post_kvm_run(CPUState *cpu);

void pt_dump(CPUState *cpu, int bytes);
#endif