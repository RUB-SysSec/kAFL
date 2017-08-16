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

#include "memory_access.h"

#define x86_64_PAGE_SIZE    	0x1000
#define x86_64_PAGE_MASK   		~(x86_64_PAGE_SIZE - 1)

bool read_virtual_memory(uint64_t address, uint8_t* data, uint32_t size, CPUState *cpu){
	uint8_t tmp_buf[x86_64_PAGE_SIZE];
	MemTxAttrs attrs;
	hwaddr phys_addr;
	int asidx;
	uint64_t counter, l;
	int i = 0;
	
	counter = size;
	
	//cpu_synchronize_state(cpu);
	kvm_cpu_synchronize_state(cpu);

	/* copy per page */
	while(counter != 0){
		
		l = x86_64_PAGE_SIZE;
		if (l > counter)
		    l = counter;
		
		asidx = cpu_asidx_from_attrs(cpu, MEMTXATTRS_UNSPECIFIED);
		attrs = MEMTXATTRS_UNSPECIFIED;
		phys_addr = cpu_get_phys_page_attrs_debug(cpu, (address & x86_64_PAGE_MASK), &attrs);
		
		phys_addr += (address & ~x86_64_PAGE_MASK);	
		address_space_rw(cpu_get_address_space(cpu, asidx), phys_addr, MEMTXATTRS_UNSPECIFIED, tmp_buf, l, 0);
		
		memcpy(data+(i*x86_64_PAGE_SIZE), tmp_buf, l);
		
		i++;
		address += l;
		counter -= l;
	}
	
	return true;
}


bool write_virtual_memory(uint64_t address, uint8_t* data, uint32_t size, CPUState *cpu)
{
	/* Todo: later &address_space_memory + phys_addr -> mmap SHARED */
	int asidx;
	MemTxAttrs attrs;
    hwaddr phys_addr;
    MemTxResult res;

    uint64_t counter, l, i;

    counter = size;
	while(counter != 0){
		l = x86_64_PAGE_SIZE;
        if (l > counter)
            l = counter;

	kvm_cpu_synchronize_state(cpu);
        //cpu_synchronize_state(cpu);
        asidx = cpu_asidx_from_attrs(cpu, MEMTXATTRS_UNSPECIFIED);
        attrs = MEMTXATTRS_UNSPECIFIED;
        phys_addr = cpu_get_phys_page_attrs_debug(cpu, (address & x86_64_PAGE_MASK), &attrs);

        if (phys_addr == -1){
            printf("FAIL 1 (%lx)!\n", address);
            return false;
        }
        
        phys_addr += (address & ~x86_64_PAGE_MASK);   
        res = address_space_rw(cpu_get_address_space(cpu, asidx), phys_addr, MEMTXATTRS_UNSPECIFIED, data, l, true);
        if (res != MEMTX_OK){
            printf("FAIL 1 (%lx)!\n", address);
            return false;
        }   

        i++;
        data += l;
        address += l;
        counter -= l;
	}

	return true;
}
