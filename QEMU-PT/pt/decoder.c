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

Note: 
This Intel PT software decoder is partially inspired and based on Andi 
Kleen's fastdecode.c (simple-pt). 
See: https://github.com/andikleen/simple-pt/blob/master/fastdecode.c

 * Simple PT dumper
 *
 * Copyright (c) 2015, Intel Corporation
 * Author: Andi Kleen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#define _GNU_SOURCE 1
#include "pt/decoder.h"

#define LEFT(x) ((end - p) >= (x))
#define BIT(x) (1U << (x))

#define BENCHMARK 				1

#define PT_PKT_GENERIC_LEN		2
#define PT_PKT_GENERIC_BYTE0	0b00000010

#define PT_PKT_LTNT_LEN			8
#define PT_PKT_LTNT_BYTE0		PT_PKT_GENERIC_BYTE0
#define PT_PKT_LTNT_BYTE1		0b10100011

#define PT_PKT_PIP_LEN			8
#define PT_PKT_PIP_BYTE0		PT_PKT_GENERIC_BYTE0
#define PT_PKT_PIP_BYTE1		0b01000011

#define PT_PKT_CBR_LEN			4
#define PT_PKT_CBR_BYTE0		PT_PKT_GENERIC_BYTE0
#define PT_PKT_CBR_BYTE1		0b00000011

#define PT_PKT_OVF_LEN			8
#define PT_PKT_OVF_BYTE0		PT_PKT_GENERIC_BYTE0
#define PT_PKT_OVF_BYTE1		0b11110011

#define PT_PKT_PSB_LEN			16
#define PT_PKT_PSB_BYTE0		PT_PKT_GENERIC_BYTE0
#define PT_PKT_PSB_BYTE1		0b10000010

#define PT_PKT_PSBEND_LEN		2
#define PT_PKT_PSBEND_BYTE0		PT_PKT_GENERIC_BYTE0
#define PT_PKT_PSBEND_BYTE1		0b00100011

#define PT_PKT_MNT_LEN			11
#define PT_PKT_MNT_BYTE0		PT_PKT_GENERIC_BYTE0
#define PT_PKT_MNT_BYTE1		0b11000011
#define PT_PKT_MNT_BYTE2		0b10001000

#define PT_PKT_TMA_LEN			7
#define PT_PKT_TMA_BYTE0		PT_PKT_GENERIC_BYTE0
#define PT_PKT_TMA_BYTE1		0b01110011

#define PT_PKT_VMCS_LEN			7
#define PT_PKT_VMCS_BYTE0		PT_PKT_GENERIC_BYTE0
#define PT_PKT_VMCS_BYTE1		0b11001000

#define	PT_PKT_TS_LEN			2
#define PT_PKT_TS_BYTE0			PT_PKT_GENERIC_BYTE0
#define PT_PKT_TS_BYTE1			0b10000011

#define PT_PKT_MODE_LEN			2
#define PT_PKT_MODE_BYTE0		0b10011001

#define PT_PKT_TIP_LEN			8
#define PT_PKT_TIP_SHIFT		5
#define PT_PKT_TIP_MASK			0b00011111
#define PT_PKT_TIP_BYTE0		0b00001101
#define PT_PKT_TIP_PGE_BYTE0	0b00010001
#define PT_PKT_TIP_PGD_BYTE0	0b00000001
#define PT_PKT_TIP_FUP_BYTE0	0b00011101

//#define DEBUG

static uint8_t psb[16] = {
	0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
	0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82
};

#ifdef DECODER_LOG
static void flush_log(decoder_t* self){
	self->log.tnt64 = 0;
	self->log.tnt8 = 0;
	self->log.pip = 0;
	self->log.cbr = 0;
	self->log.ts = 0;
	self->log.ovf = 0;
	self->log.psbc = 0;
	self->log.psbend = 0;
	self->log.mnt = 0;
	self->log.tma = 0;
	self->log.vmcs = 0;
	self->log.pad = 0;
	self->log.tip = 0;
	self->log.tip_pge = 0;
	self->log.tip_pgd = 0;
	self->log.tip_fup = 0;
	self->log.mode = 0;
}
#endif

decoder_t* pt_decoder_init(uint8_t* code, uint64_t min_addr, uint64_t max_addr, void (*handler)(uint64_t)){
	decoder_t* res = malloc(sizeof(decoder_t));
	res->code = code;
	res->min_addr = min_addr;
	res->max_addr = max_addr;
	res->handler = handler;

	res->last_tip = 0;
	res->last_ip2 = 0;
	res->fup_pkt = false;
	res->isr = false;
	res->in_range = false;
#ifdef DECODER_LOG
	flush_log(res);
#endif
	res->disassembler_state = init_disassembler(code, min_addr, max_addr, handler);
	res->tnt_cache_state = tnt_cache_init();
	return res;
}

void pt_decoder_destroy(decoder_t* self){
	if(self->tnt_cache_state){
		destroy_disassembler(self->disassembler_state);
		tnt_cache_destroy(self->tnt_cache_state);
		self->tnt_cache_state = NULL;
	}
	free(self);
}

void pt_decoder_flush(decoder_t* self){
	self->last_tip = 0;
	self->last_ip2 = 0;
	self->fup_pkt = false;
	self->isr = false;
	self->in_range = false;
#ifdef DECODER_LOG
	flush_log(self);
#endif
	/* ugly hack */
	if(self->tnt_cache_state){
		tnt_cache_destroy(self->tnt_cache_state);
	}
	self->tnt_cache_state = tnt_cache_init();
}


static inline uint64_t get_ip_val(unsigned char **pp, unsigned char *end, int len, uint64_t *last_ip)
{
	unsigned char *p = *pp;
	uint64_t v = *last_ip;
	int i;
	unsigned shift = 0;

	if (len == 0) {
		return 0; /* out of context */
	}
	if (len < 4) {
		if (!LEFT(len)) {
			*last_ip = 0;
			return 0; /* XXX error */
		}
		for (i = 0; i < len; i++, shift += 16, p += 2) {
			uint64_t b = *(uint16_t *)p;
			v = (v & ~(0xffffULL << shift)) | (b << shift);
		}
		v = ((int64_t)(v << (64 - 48))) >> (64 - 48); /* sign extension */
	} else {
		return 0; /* XXX error */
	}
	*pp = p;
	*last_ip = v;
	return v;
}

static void print_unknown(unsigned char *p, unsigned char *end, unsigned char *map)
{
	printf("unknown packet: ");
	unsigned len = end - p;
	int i;
	if (len > 16)
		len = 16;
	for (i = 0; i < len; i++)
		printf("%02x ", p[i]);
	printf("\n");
}

/* Caller must have checked length */
static uint64_t get_val(unsigned char **pp, int len)
{
	unsigned char *p = *pp;
	uint64_t v = 0;
	int i;
	unsigned shift = 0;

	for (i = 0; i < len; i++, shift += 8)
		v |= ((uint64_t)(*p++)) << shift;
	*pp = p;
	return v;
}

static inline void pad_handler(decoder_t* self, uint8_t** p){
	(*p)++;
#ifdef DECODER_LOG
	self->log.pad++;
#endif
}

static inline void tnt8_handler(decoder_t* self, uint8_t** p){
	append_tnt_cache(self->tnt_cache_state, true, (uint64_t)(**p));
	(*p)++;
#ifdef DECODER_LOG
	self->log.tnt8++;
#endif
}

static inline void cbr_handler(decoder_t* self, uint8_t** p){
	(*p) += PT_PKT_CBR_LEN;
#ifdef DECODER_LOG
	self->log.cbr++;
#endif
}

static inline void mode_handler(decoder_t* self, uint8_t** p){
	sample_decoded_detailed("MODE\n");
	(*p) += PT_PKT_MODE_LEN;
#ifdef DECODER_LOG
	self->log.mode++;
#endif
}

static inline void tip_handler(decoder_t* self, uint8_t** p, uint8_t** end){
	//if (self->fup_pkt){
	//	sample_decoded_detailed("INTERRUPT!\n");
	//	self->fup_pkt = false;
	//	self->isr = true;
	//}
	if (count_tnt(self->tnt_cache_state)){
		//if (trace_disassembler(self->last_tip, self->min_addr, self->max_addr, self->code, self->handler, (self->isr &!self->in_range))){
		if (trace_disassembler(self->disassembler_state, self->last_tip, (self->isr &!self->in_range), self->tnt_cache_state)){
			sample_decoded_detailed("IRET!\n");
			//self->isr = false;
		}
	}
	self->last_tip = get_ip_val(p, *end, (*(*p)++ >> PT_PKT_TIP_SHIFT), &self->last_ip2);
	if(!self->last_tip)
		printf("tip trashed 1\n");
	sample_decoded_detailed("TIP    \t%lx\n", self->last_tip);
#ifdef DECODER_LOG
	self->log.tip++;
#endif
}

static inline void tip_pge_handler(decoder_t* self, uint8_t** p, uint8_t** end){
	self->pge_enabled = true;
	self->last_tip = get_ip_val(p, *end, (*(*p)++ >> PT_PKT_TIP_SHIFT), &self->last_ip2);
	if(!self->last_tip)
		sample_decoded_detailed("tip trashed 2\n");
	sample_decoded_detailed("TIP.PGE\t%lx\n", self->last_tip);
	//trace_disassembler(self->last_tip, self->min_addr, self->max_addr, self->code, self->handler, (self->isr &!self->in_range));
	trace_disassembler(self->disassembler_state, self->last_tip, (self->isr &!self->in_range), self->tnt_cache_state);
#ifdef DECODER_LOG
	self->log.tip_pge++;
#endif
}

static inline void tip_pgd_handler(decoder_t* self, uint8_t** p, uint8_t** end){
	//if (self->fup_pkt){
	//	sample_decoded_detailed("WRITE MSR / READ MSR \n");
	//	self->fup_pkt = false;
	//}
	self->pge_enabled = false;
	if (count_tnt(self->tnt_cache_state)){
		//if (trace_disassembler(self->last_tip, self->min_addr, self->max_addr, self->code, self->handler, (self->isr &!self->in_range))){
		if (trace_disassembler(self->disassembler_state, self->last_tip, (self->isr &!self->in_range), self->tnt_cache_state)){
			sample_decoded_detailed("SYSRET!\n");
			//self->in_range = false;
		}
	}
	self->last_tip = get_ip_val(p, *end, (*(*p)++ >> PT_PKT_TIP_SHIFT), &self->last_ip2);
	sample_decoded_detailed("TIP.PGD\t%lx (%d)\n", self->last_tip, count_tnt(self->tnt_cache_state));
#ifdef DECODER_LOG
	self->log.tip_pgd++;
#endif
}

static inline void tip_fup_handler(decoder_t* self, uint8_t** p, uint8_t** end){
	if (count_tnt(self->tnt_cache_state)){
		//trace_disassembler(self->last_tip, self->min_addr, self->max_addr, self->code, self->handler, (self->isr &!self->in_range));
		trace_disassembler(self->disassembler_state, self->last_tip, (self->isr &!self->in_range), self->tnt_cache_state);
	}
	self->last_tip = get_ip_val(p, *end, (*(*p)++ >> PT_PKT_TIP_SHIFT), &self->last_ip2);
	if(!self->last_tip)
		sample_decoded_detailed("tip trashed 4\n");
	sample_decoded_detailed("TIP.FUP\t%lx\n", self->last_tip);

	/* What's next ? */
	//self->fup_pkt = true;
#ifdef DECODER_LOG
	self->log.tip_fup++;
#endif
}

static inline void pip_handler(decoder_t* self, uint8_t** p){
	//if(self->fup_pkt){
	//	sample_decoded_detailed("CONTEXT SWITCH -> IGNORE\n");
	//	self->fup_pkt = false;
	//}
	(*p) += PT_PKT_PIP_LEN-6;
	sample_decoded_detailed("PIP\t%llx\n", (get_val(p, 6) >> 1) << 5);
#ifdef DECODER_LOG
	self->log.pip++;
#endif
}

static inline void psb_handler(decoder_t* self, uint8_t** p){
#ifdef DEBUG
	sample_decoded_detailed("PSB\n");
#endif
	(*p) += PT_PKT_PSB_LEN;
#ifdef DECODER_LOG
	self->log.psbc++;
#endif
	pt_decoder_flush(self);
	//int fd = open("/tmp/psb", O_WRONLY | O_CREAT | O_APPEND, S_IRWXU);
	//write(fd, "A", 1);
	//close(fd);
}

static inline void psbend_handler(decoder_t* self, uint8_t** p){
#ifdef DEBUG
	sample_decoded_detailed("PSBEND\n");
#endif
	(*p) += PT_PKT_PSBEND_LEN;
#ifdef DECODER_LOG
	self->log.psbend++;
#endif
}

static inline void long_tnt_handler(decoder_t* self, uint8_t** p){
	if (self->pge_enabled)
		append_tnt_cache(self->tnt_cache_state, false, (uint64_t)*p);
	(*p) += PT_PKT_LTNT_LEN;
#ifdef DECODER_LOG
	self->log.tnt64++;
#endif
}

static inline void ts_handler(decoder_t* self, uint8_t** p){
	(*p) += PT_PKT_TS_LEN;
#ifdef DECODER_LOG
	self->log.ts++;
#endif
}

static inline void ovf_handler(decoder_t* self, uint8_t** p){
	sample_decoded_detailed("Overflow!\n");
	(*p) += PT_PKT_OVF_LEN;
#ifdef DECODER_LOG
	self->log.ovf++;
#endif
}

static inline void mnt_handler(decoder_t* self, uint8_t** p){
	(*p) += PT_PKT_MNT_LEN;
#ifdef DECODER_LOG
	self->log.mnt++;
#endif
}

static inline void tma_handler(decoder_t* self, uint8_t** p){
	(*p) += PT_PKT_TMA_LEN;
#ifdef DECODER_LOG
	self->log.tma++;
#endif
}

static inline void vmcs_handler(decoder_t* self, uint8_t** p){
	sample_decoded_detailed("VMCS\n");
	(*p) += PT_PKT_VMCS_LEN;
#ifdef DECODER_LOG
	self->log.vmcs++;
#endif
}

void decode_buffer(decoder_t* self, uint8_t* map, size_t len){
	unsigned char *end = map + len;
	unsigned char *p;
	uint8_t byte0;

#ifdef DECODER_LOG
	flush_log(self);
#endif

	for (p = map; p < end; ) {
		p = memmem(p, end - p, psb, PT_PKT_PSB_LEN);
		if (!p) {
			p = end;
			break;
		}
		
		while (p < end) {			
			byte0 = *p;
				
			/* pad */
			if (byte0 == 0) { 
				pad_handler(self, &p);
				continue;
			}
			
			/* tnt8 */
			if ((byte0 & BIT(0)) == 0 && byte0 != 2){
				tnt8_handler(self, &p);
				continue;
			}
			
			/* CBR */
			if (*p == PT_PKT_GENERIC_BYTE0 && LEFT(PT_PKT_CBR_LEN) && p[1] == PT_PKT_CBR_BYTE1) {
				cbr_handler(self, &p);
				continue;
			}
			
			/* MODE */
			if (byte0 == PT_PKT_MODE_BYTE0 && LEFT(PT_PKT_MODE_LEN)) {
				mode_handler(self, &p);
				continue;
			}

			switch (byte0 & PT_PKT_TIP_MASK) {

				/* tip */
				case PT_PKT_TIP_BYTE0:
					tip_handler(self, &p, &end);
					continue;

				/* tip.pge */
				case PT_PKT_TIP_PGE_BYTE0:
					tip_pge_handler(self, &p, &end);
					continue;

				/* tip.pgd */
				case PT_PKT_TIP_PGD_BYTE0:
					tip_pgd_handler(self, &p, &end);
					continue;

				/* tip.fup */
				case PT_PKT_TIP_FUP_BYTE0:
					tip_fup_handler(self, &p, &end);
					continue;
				default:
					break;
			}

			if (*p == PT_PKT_GENERIC_BYTE0 && LEFT(PT_PKT_GENERIC_LEN)) {

				/* PIP */
				if (p[1] == PT_PKT_PIP_BYTE1 && LEFT(PT_PKT_PIP_LEN)) {
					pip_handler(self, &p);
					continue;
				}

				/* PSB */
				if (p[1] == PT_PKT_PSB_BYTE1 && LEFT(PT_PKT_PSB_LEN) && !memcmp(p, psb, PT_PKT_PSB_LEN)) {
					psb_handler(self, &p);
					continue;
				}

				/* PSBEND */
				if (p[1] == PT_PKT_PSBEND_BYTE1) {
					psbend_handler(self, &p);
					continue;
				}

				/* long TNT */
				if (p[1] == PT_PKT_LTNT_BYTE1 && LEFT(PT_PKT_LTNT_LEN)) {
					long_tnt_handler(self, &p);
					continue;
				}

				/* TS */
				if (p[1] == PT_PKT_TS_BYTE1) {
					ts_handler(self, &p);
					continue;
				}

				/* OVF */
				if (p[1] == PT_PKT_OVF_BYTE1 && LEFT(PT_PKT_OVF_LEN)) {
					ovf_handler(self, &p);
					continue;
				}

				/* MNT */
				if (p[1] == PT_PKT_MNT_BYTE1 && LEFT(PT_PKT_MNT_LEN) && p[2] == PT_PKT_MNT_BYTE2) {
					mnt_handler(self, &p);
					continue;
				}

				/* TMA */
				if (p[1] == PT_PKT_TMA_BYTE1 && LEFT(PT_PKT_TMA_LEN)) {
					tma_handler(self, &p);
					continue;
				}

				/* VMCS */
				if (p[1] == PT_PKT_VMCS_BYTE1 && LEFT(PT_PKT_VMCS_LEN)) {
					vmcs_handler(self, &p);
					continue;
				}
			}

			print_unknown(p, end, map);
			return;
		}
	}
	if(count_tnt(self->tnt_cache_state))
		sample_decoded_detailed("\tTNT %d (PGE: %d)\n", count_tnt(self->tnt_cache_state), self->pge_enabled);
}
