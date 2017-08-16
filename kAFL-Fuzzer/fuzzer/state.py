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

import time
import base64
from collections import deque

class MapserverState:
    def __init__(self):
        self.level = 1
        self.timeout = 0
        self.unique_timeout = 0
        self.kasan = 0
        self.unique_kasan = 0
        self.crashes = 0
        self.unique = 0
        self.timeout = 0
        self.hashes = 0
        self.pending = 0
        self.cycles = 0
        self.favorites = 0
        self.last_hash_time = None

        self.ratio_coverage = 0.0
        self.ratio_bits = 0.0

        self.path_pending = 0
        self.path_unfinished = 0
        self.fav_pending = 0
        self.fav_unfinished = 0

    def save_data(self):
        tmp = {}
        for key, value in self.__dict__.iteritems():
            if key == "last_hash_time":
                if value:
                    tmp[key] = (time.time() - value)
            else:
                tmp[key] = value
        return tmp

    def load_data(self, data):
        for key, value in data.iteritems():
            if key == "last_hash_time":
                setattr(self, key, (time.time() - value))
            else:
                setattr(self, key, value)


class State:
    def __init__(self):

        self.loading = True
        self.reload = False
        self.slaves_ready = 0

        self.interface_str = ""
        self.target_str = ""
        self.technique = ""
        self.total = 0
        self.performance = 0
        self.performance_rb = deque(maxlen=5)
        self.max_performance_rb = deque(maxlen=100)
        self.runtime = time.time()
        self.last_hash_time = time.time()
        self.level = 0
        self.max_level = 0
        self.cycles = 0
        self.hashes = 0
        self.favorites = 0
        self.pending = 0
        self.payload_size = 0

        self.panics = 0
        self.panics_unique = 0

        self.kasan = 0
        self.kasan_unique = 0

        self.reloads = 0
        self.reloads_unique = 0

        self.progress_bitflip = 0
        self.progress_arithmetic = 0
        self.progress_interesting = 0
        self.progress_havoc = 0
        self.progress_specific = 0

        self.progress_requeen_amount = 0
        self.progress_bitflip_amount = 0
        self.progress_arithmetic_amount = 0
        self.progress_interesting_amount = 0
        self.progress_havoc_amount = 0
        self.progress_specific_amount = 0

        self.ratio_coverage = 0.0
        self.ratio_bits = 0.0

        self.path_pending = 0
        self.path_unfinished = 0
        self.fav_pending = 0
        self.fav_unfinished = 0

        self.payload = ""

    def get_performance(self):
        if len(self.performance_rb) == 0:
            return 0
        else:
            return (sum(self.performance_rb)/len(self.performance_rb))

    def get_max_performance(self):
        if len(self.max_performance_rb) == 0:
            return 0
        else:
            return (sum(self.max_performance_rb)/len(self.max_performance_rb))

    def save_data(self):
        tmp = {}
        for key, value in self.__dict__.iteritems():
            if key == "runtime" or key == "last_hash_time":
                tmp[key] = (time.time() - value)
            elif key == "performance_rb" or key == "max_performance_rb":
                tmp[key] = list(value)
            elif key == "payload":
                tmp[key] = base64.b64encode(value)
            elif not str(key).startswith("progress"):
                tmp[key] = value
        return tmp

    def load_data(self, data):
        for key, value in data.iteritems():
            if key == "runtime" or key == "last_hash_time":
                setattr(self, key, (time.time() - value))
            elif key == "performance_rb":
                for element in value:
                    self.performance_rb.append(element)
            elif key == "max_performance_rb":
                for element in value:
                    self.max_performance_rb.append(element)
            elif key == "payload":
                setattr(self, key, base64.b64decode(value))
            elif not str(key).startswith("progress"):
                setattr(self, key, value)
        self.slaves_ready = 0

