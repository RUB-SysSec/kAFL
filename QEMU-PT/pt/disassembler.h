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

#ifndef DISASSEMBLER_H
#define DISASSEMBLER_H

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/time.h>
#include <inttypes.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "qemu/osdep.h"
#include "pt/khash.h"
#include "pt/tnt_cache.h"
#include "pt/logger.h"

KHASH_MAP_INIT_INT(ADDR0, uint64_t)

typedef struct{
	uint16_t opcode;
	uint8_t modrm;
	uint8_t opcode_prefix;
} cofi_ins;

typedef enum cofi_types{
	COFI_TYPE_CONDITIONAL_BRANCH, 
	COFI_TYPE_UNCONDITIONAL_DIRECT_BRANCH, 
	COFI_TYPE_INDIRECT_BRANCH, 
	COFI_TYPE_NEAR_RET, 
	COFI_TYPE_FAR_TRANSFERS,
	NO_COFI_TYPE
} cofi_type;


typedef struct {
	uint64_t ins_addr;
	uint64_t target_addr;
	cofi_type type;
} cofi_header;

typedef struct cofi_list {
	struct cofi_list *list_ptr;
	struct cofi_list *cofi_ptr;
	cofi_header *cofi;
} cofi_list;

typedef struct disassembler_s{
	uint8_t* code;
	uint64_t min_addr;
	uint64_t max_addr;
	void (*handler)(uint64_t);
	khash_t(ADDR0) *map;
	cofi_list* list_head;
	cofi_list* list_element;
	bool debug;
} disassembler_t;

disassembler_t* init_disassembler(uint8_t* code, uint64_t min_addr, uint64_t max_addr, void (*handler)(uint64_t));
bool trace_disassembler(disassembler_t* self, uint64_t entry_point, bool isr, tnt_cache_t* tnt_cache_state);
void destroy_disassembler(disassembler_t* self);

#endif