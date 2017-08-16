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

#ifndef DECODER_H
#define DECODER_H

#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/time.h>
#include <stdbool.h>
#include "pt/tnt_cache.h"
#include "pt/disassembler.h"
#include "pt/logger.h"

//#define DECODER_LOG

typedef struct decoder_s{
	uint8_t* code;
	uint64_t min_addr;
	uint64_t max_addr;
	void (*handler)(uint64_t);
	uint64_t last_tip;
	uint64_t last_ip2;
	bool fup_pkt;
	bool isr;
	bool in_range;
	bool pge_enabled;
	disassembler_t* disassembler_state;
	tnt_cache_t* tnt_cache_state;
#ifdef DECODER_LOG
	struct decoder_log_s{
		uint64_t tnt64;
		uint64_t tnt8;
		uint64_t pip;
		uint64_t cbr;
		uint64_t ts;
		uint64_t ovf;
		uint64_t psbc;
		uint64_t psbend;
		uint64_t mnt;
		uint64_t tma;
		uint64_t vmcs;
		uint64_t pad;
		uint64_t tip;
		uint64_t tip_pge;
		uint64_t tip_pgd;
		uint64_t tip_fup;
		uint64_t mode;
	} log;
#endif
} decoder_t;

decoder_t* pt_decoder_init(uint8_t* code, uint64_t min_addr, uint64_t max_addr, void (*handler)(uint64_t));
void decode_buffer(decoder_t* self, uint8_t* map, size_t len);
void pt_decoder_destroy(decoder_t* self);
void pt_decoder_flush(decoder_t* self);

#endif