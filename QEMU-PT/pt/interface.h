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

#ifndef INTERFACE_H
#define INTERFACE_H

#define INTEL_PT_MAX_RANGES			4

#define DEFAULT_KAFL_BITMAP_SIZE	0x10000
#define DEFAULT_EDGE_FILTER_SIZE	0x1000000

#define PROGRAM_SIZE				(16  << 20)	/* 16MB Application Data */
#define PAYLOAD_SIZE				(128 << 10)	/* 128KB Payload Data */
#define INFO_SIZE					(128 << 10)	/* 128KB Info Data */

#define INFO_FILE					"/tmp/kAFL_info.txt"

#define HOOK_INSTRUCTION			0xee

#define KAFL_PROTO_ACQUIRE			'R'
#define KAFL_PROTO_RELEASE			'D'

#define KAFL_PROTO_RELOAD			'L'
#define KAFL_PROTO_ENABLE_SAMPLING	'S'
#define KAFL_PROTO_DISABLE_SAMPLING	'O'
#define KAFL_PROTO_COMMIT_FILTER	'T'
#define KAFL_PROTO_FINALIZE			'F'

#define KAFL_PROTO_ENABLE_RQI_MODE	'A'
#define KAFL_PROTO_DISABLE_RQI_MODE	'B'

#define KAFL_PROTO_CRASH			'C'
#define KAFL_PROTO_KASAN			'K'
#define KAFL_PROTO_INFO				'I'

#endif
