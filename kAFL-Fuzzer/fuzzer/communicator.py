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

import multiprocessing
import os
import mmap
import Queue
from common.debug import logger

class Communicator:
    def __init__(self, num_processes=1, tasks_per_requests=1, bitmap_size=(64 << 10)):
        self.to_update_queue = multiprocessing.Queue()
        self.to_master_queue = multiprocessing.Queue()
        self.to_master_from_mapserver_queue = multiprocessing.Queue()
        self.to_master_from_slave_queue = multiprocessing.Queue()
        self.to_mapserver_queue = multiprocessing.Queue()

        self.to_slave_queues = []
        for i in range(num_processes):
            self.to_slave_queues.append(multiprocessing.Queue())

        self.slave_locks_A = []
        self.slave_locks_B = []
        for i in range(num_processes):
            self.slave_locks_A.append(multiprocessing.Lock())
            self.slave_locks_B.append(multiprocessing.Lock())
            self.slave_locks_B[i].acquire()

        self.reload_semaphore = multiprocessing.Semaphore(multiprocessing.cpu_count()/2)
        self.num_processes = num_processes
        self.tasks_per_requests = tasks_per_requests

        self.stage_abortion_notifier = multiprocessing.Value('b', False)
        self.slave_termination = multiprocessing.Value('b', False, lock=False)
        self.sampling_failed_notifier = multiprocessing.Value('b', False)
        self.effector_mode = multiprocessing.Value('b', False)

        self.files = ["/dev/shm/kafl_fuzzer_master_", "/dev/shm/kafl_fuzzer_mapserver_", "/dev/shm/kafl_fuzzer_bitmap_"]
        self.sizes = [(65 << 10), (65 << 10), bitmap_size]
        self.tmp_shm = [{}, {}, {}]

    def get_master_payload_shm(self, slave_id):
        return self.__get_shm(0, slave_id)

    def get_mapserver_payload_shm(self, slave_id):
        return self.__get_shm(1, slave_id)

    def get_bitmap_shm(self, slave_id):
        return self.__get_shm(2, slave_id)

    def get_master_payload_shm_size(self):
        return self.sizes[0]

    def get_mapserver_payload_shm_size(self):
        return self.sizes[1]

    def get_bitmap_shm_size(self):
        return self.sizes[2]

    def create_shm(self):
        for j in range(len(self.files)):
            for i in range(self.num_processes):
                shm_f = os.open(self.files[j]+str(i), os.O_CREAT | os.O_RDWR | os.O_SYNC)
                os.ftruncate(shm_f, self.sizes[j]*self.tasks_per_requests)
                os.close(shm_f)

    def __get_shm(self, type_id, slave_id):
        if slave_id in self.tmp_shm[type_id]:
            shm = self.tmp_shm[type_id][slave_id]
        else:
            shm_fd = os.open(self.files[type_id] + str(slave_id), os.O_RDWR | os.O_SYNC)
            shm = mmap.mmap(shm_fd, self.sizes[type_id]*self.tasks_per_requests, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)
            self.tmp_shm[type_id][slave_id] = shm
        return shm


class Message():
    def __init__(self, tag, data, source=None):
        self.tag = tag
        self.data = data
        self.source = source

def msg_pending(queue):
    return queue.empty()

def send_msg(tag, data, queue, source=None):
    msg = Message(tag, data, source=source)
    queue.put(msg)

def recv_msg(queue, timeout=None):
    if timeout:
        try:
            return queue.get(timeout=timeout)
        except Queue.Empty:
            return None
    return queue.get()

def recv_tagged_msg(queue, tag):
    tmp_list = []
    tmp_obj = None

    while True:
        tmp_obj = recv_msg(queue)
        if tmp_obj.tag == tag:
            return tmp_obj
        else:
            queue.put(tmp_obj)
       