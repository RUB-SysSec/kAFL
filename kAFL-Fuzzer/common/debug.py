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

import sys
from datetime import timedelta
import time
import collections
from multiprocessing import Manager


__author__ = 'sergej'

try:
    xrange          # Python 2
except NameError:
    xrange = range  # Python 3

def hexdump(src, length=16):
    hexdump_filter = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex_value = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and hexdump_filter[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex_value, printable))
    return ''.join(lines)


logging_is_enabled = False
output_file = None
init_time = 0.0

manager = Manager()
shared_list = manager.list()

def __init_logger():
    global output_file, init_time
    init_time = time.time()
    output_file = open("debug.log", 'w')

def logger(msg):
    global logging_is_enabled, output_file, init_time, shared_list

    try:
        if(len(shared_list) >= 9):
            shared_list.pop(0)
        shared_list.append(msg.replace("\n", " "))
    except:
        pass
    if logging_is_enabled:
        if not output_file:
            __init_logger()
        output_file.write("[" + str(timedelta(seconds=time.time()-init_time)) + "] " + msg + "\n")
        output_file.flush()

def get_rbuf_content():
    global shared_list
    try:
        return list(shared_list)
    except:
        return None

def enable_logging():
    global logging_is_enabled
    logging_is_enabled = True
    
def log_master(msg):
    logger("[MASTER]        " + msg)

def log_mapserver(msg):
    logger("[MAPSERV]       " + msg)

def log_update(msg):
    logger("[UPDATE]        " + msg)

def log_slave(msg, qid):
    if qid < 10:
        logger("[SLAVE " + str(qid) + "]       " + msg)
    elif qid > 10 and qid < 100:
        logger("[SLAVE " + str(qid) + "]      " + msg)
    else:
        logger("[SLAVE " + str(qid) + "]     " + msg)

def log_tree(msg):
    logger("[TREE]          " + msg)

def log_eval(msg):
    logger("[EVAL]          " + msg)

def log_qemu(msg, qid):
    if qid < 10:
        logger("[QEMU " + str(qid) + "]           " + msg)
    elif qid > 10 and qid < 100:
        logger("[QEMU " + str(qid) + "]         " + msg)
    else:
        logger("[QEMU " + str(qid) + "]        " + msg)

def log_core(msg):
    logger("[CORE]          " + msg)

def log_info(msg):
    logger("[INFO]          " + msg)



