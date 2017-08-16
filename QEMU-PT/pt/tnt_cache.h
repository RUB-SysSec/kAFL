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

#ifndef TNT_CACHE_H
#define TNT_CACHE_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#define NOT_TAKEN			0
#define TAKEN				1
#define TNT_EMPTY			2

#define SHORT_TNT_OFFSET	1
#define SHORT_TNT_MAX_BITS	8-1-SHORT_TNT_OFFSET

#define LONG_TNT_OFFSET		16
#define LONG_TNT_MAX_BITS	64-1-LONG_TNT_OFFSET

typedef struct tnt_cache_obj{
	uint8_t bits;
	uint64_t data;
	uint8_t processed;
	struct tnt_cache_obj* next;
}tnt_cache_obj;

typedef struct tnt_cache_s{
	tnt_cache_obj* head;
	tnt_cache_obj* next_node;
	uint8_t counter;
} tnt_cache_t;

tnt_cache_t* tnt_cache_init(void);
void tnt_cache_destroy(tnt_cache_t* self);

bool is_empty_tnt_cache(tnt_cache_t* self);
int count_tnt(tnt_cache_t* self);
uint8_t process_tnt_cache(tnt_cache_t* self);
void append_tnt_cache(tnt_cache_t* self, bool short_tnt, uint64_t data);

#endif 