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

#ifndef LOGGER_H
#define LOGGER_H

	#define CREATE_VM_IMAGE
	//#define SAMPLE_RAW
	//#define SAMPLE_DECODED
	//#define SAMPLE_DECODED_DETAILED
	//#define SAMPLE_RAW_SINGLE

	#ifdef CREATE_VM_IMAGE
		#define DECODER_MEMORY_IMAGE "/tmp/data"
	#endif

	#ifdef SAMPLE_RAW_SINGLE
		void init_sample_raw_single(uint32_t id);
		void sample_raw_single(void* buffer, int bytes);
	#endif
	
	#ifdef SAMPLE_RAW
		void init_sample_raw(void);
		void sample_raw(void* buffer, int bytes);
	#endif

	#ifdef SAMPLE_DECODED
		void init_sample_decoded(void);
		void sample_decoded(uint64_t addr);
	#endif

	#ifdef SAMPLE_DECODED_DETAILED
		void init_sample_decoded_detailed(void);
	#endif

	void sample_decoded_detailed(const char *format, ...);

#endif
