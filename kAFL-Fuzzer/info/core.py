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

from __future__ import print_function
import time
import os
from common.config import InfoConfiguration
from common.qemu import qemu
from common.debug import log_info, enable_logging
from common.self_check import post_self_check

__author__ = 'Sergej Schumilo'

def start():
    config = InfoConfiguration()

    if not post_self_check(config):
        return -1

    if config.argument_values['v']:
        enable_logging()

    log_info("Dumping kernel addresses...")
    if os.path.exists("/tmp/kAFL_info.txt"):
        os.remove("/tmp/kAFL_info.txt")
    q = qemu(0, config)
    q.start()
    q.__del__()
    try:
        for line in open("/tmp/kAFL_info.txt"):
            print(line, end=" ")
        os.remove("/tmp/kAFL_info.txt")
    except:
        pass
    return 0
