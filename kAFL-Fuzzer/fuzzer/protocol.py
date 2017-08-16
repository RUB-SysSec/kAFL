"""
Copyright (C) 2017 Sergej Schumilo

This file is part of kAFL Fuzzer (kAFL).

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
"""

class FuzzingResult:
    def __init__(self, pos, crash, timeout, kasan, affected_bytes, slave_id, performance, reloaded=False, new_bits=True, qid=0):
        self.pos = pos
        self.crash = crash
        self.timeout = timeout
        self.kasan = kasan
        self.affected_bytes = affected_bytes
        self.slave_id = slave_id
        self.reloaded = reloaded
        self.performance = performance
        self.new_bits = new_bits
        self.qid = qid

KAFL_TAG_REQ =              0
KAFL_TAG_JOB =              1
KAFL_TAG_OUTPUT =           2
KAFL_TAG_START =            3
KAFL_TAG_RESULT =           4
KAFL_TAG_MAP_INFO =         5
KAFL_TAG_NXT_FIN =          6
KAFL_TAG_NXT_UNFIN =        7
KAFL_TAG_UNTOUCHED_NODES =  8
KAFL_TAG_REQ_BITMAP =       9
KAFL_TAG_REQ_EFFECTOR =     10
KAFL_TAG_GET_EFFECTOR =     11
KAFL_INIT_BITMAP =          12
KAFL_TAG_REQ_SAMPLING =     13
KAFL_TAG_REQ_BENCHMARK =    14
KAFL_TAG_ABORT_REQ =        15

