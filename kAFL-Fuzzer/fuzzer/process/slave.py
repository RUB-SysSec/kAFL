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

import os, signal, sys
import time
import mmh3
import subprocess
from fuzzer.communicator import send_msg, recv_msg
from fuzzer.protocol import *
from common.config import FuzzerConfiguration
from common.qemu import qemu
from common.debug import log_slave
__author__ = 'Sergej Schumilo'

def slave_loader(comm, slave_id):
    log_slave("PID: " + str(os.getpid()), slave_id)

    slave_process = SlaveProcess(comm, slave_id)
    try:
        slave_process.loop()
    except KeyboardInterrupt:
        comm.slave_termination.value = True
    log_slave("Killed!", slave_id)


class SlaveProcess:

    def __init__(self, comm, slave_id, auto_reload=False):
        self.config = FuzzerConfiguration()
        self.comm = comm
        self.slave_id = slave_id
        self.counter = 0
        self.q = qemu(self.slave_id, self.config)
        self.false_positiv_map = set()
        self.stage_tick_treshold = 0
        self.timeout_tick_factor = self.config.config_values["TIMEOUT_TICK_FACTOR"]
        self.auto_reload = auto_reload
        self.soft_reload_counter = 0

    def __restart_vm(self):
        if self.comm.slave_termination.value:
            return False
        self.comm.reload_semaphore.acquire()
        try:
            #raise Exception("!")
            # QEMU is full of memory leaks...fixing it that way...
            if self.soft_reload_counter >= 32:
                self.soft_reload_counter = 0
                raise Exception("...")
            self.q.soft_reload()
            self.soft_reload_counter += 1
        except:
            while True:
                self.q.__del__()
                self.q = qemu(self.slave_id, self.config)
                if self.q.start():
                    break
                else:
                    time.sleep(0.5)
                    log_slave("Fail Reload", self.slave_id)
        self.comm.reload_semaphore.release()
        self.q.set_tick_timeout_treshold(self.stage_tick_treshold * self.timeout_tick_factor)
        if self.comm.slave_termination.value:
            return False
        return True

    def __respond_job_req(self, response):
        results = []
        performance = 0.0
        counter = 0
        self.comm.slave_locks_A[self.slave_id].acquire()
        for i in range(len(response.data)):
            if not self.comm.stage_abortion_notifier.value:
                new_bits = True
                vm_reloaded = False
                self.reloaded = False
                bitmap = ""
                payload = ""
                payload_size = 0
                if self.comm.slave_termination.value:
                    self.comm.slave_locks_B[self.slave_id].release()
                    send_msg(KAFL_TAG_RESULT, results, self.comm.to_mapserver_queue, source=self.slave_id)
                    return 
                while True:
                    while True:
                        try:
                            payload, payload_size = self.q.copy_master_payload(self.comm.get_master_payload_shm(self.slave_id), i,
                                                       self.comm.get_master_payload_shm_size())
                            start_time = time.time()
                            bitmap = self.q.send_payload()
                            performance = time.time() - start_time
                            break
                        except:
                            if not self.__restart_vm():
                                return
                            self.reloaded = True
                    if not bitmap:
                        log_slave("SHM ERROR....", self.slave_id)
                        if not self.__restart_vm():
                            self.comm.slave_locks_B[self.slave_id].release()
                            send_msg(KAFL_TAG_RESULT, results, self.comm.to_mapserver_queue, source=self.slave_id)
                            return
                    else:
                        break
                self.q.finalize_iteration()
                new_bits = self.q.copy_bitmap(self.comm.get_bitmap_shm(self.slave_id), i, self.comm.get_bitmap_shm_size(), bitmap, payload, payload_size, effector_mode=self.comm.effector_mode.value)
                if new_bits:
                    self.q.copy_mapserver_payload(self.comm.get_mapserver_payload_shm(self.slave_id), i, self.comm.get_mapserver_payload_shm_size())

                if self.comm.slave_termination.value:
                    self.comm.slave_locks_B[self.slave_id].release()
                    send_msg(KAFL_TAG_RESULT, results, self.comm.to_mapserver_queue, source=self.slave_id)
                    return 

                if self.q.timeout and not (self.q.crashed or self.q.kasan):
                    vm_reloaded = True
                    if mmh3.hash64(bitmap) not in self.false_positiv_map:
                        while True:
                            try:
                                if not self.__restart_vm():
                                    return
                                start_time = time.time()
                                bitmap = self.q.send_payload()
                                performance = time.time() - start_time
                                break
                            except:
                                pass
                    if not self.q.timeout:
                        #false positiv timeout
                        self.false_positiv_map.add(mmh3.hash64(bitmap))
                        self.reloaded = False
                    else:
                        #false positiv timeout (already seen)
                        self.reloaded = False
                        counter += 1
                
                if self.q.crashed or self.q.timeout or self.q.kasan or self.reloaded:
                    vm_reloaded = True
                    results.append(FuzzingResult(i, self.q.crashed, (self.q.timeout or self.reloaded), self.q.kasan, response.data[i],
                                                 self.slave_id, performance, reloaded=vm_reloaded, qid=self.slave_id))
                    if not self.__restart_vm():
                        self.comm.slave_locks_B[self.slave_id].release()
                        send_msg(KAFL_TAG_RESULT, results, self.comm.to_mapserver_queue, source=self.slave_id)
                        return
                    self.reloaded = True
                else:
                    results.append(FuzzingResult(i, self.q.crashed, (self.q.timeout or self.reloaded), self.q.kasan, response.data[i],
                                                 self.slave_id, performance, reloaded=vm_reloaded, new_bits=new_bits, qid=self.slave_id))
                    if new_bits and self.auto_reload:
                        self.__restart_vm()
                    self.reloaded = False

            else:
                results.append(FuzzingResult(i, False, False, False, response.data[i], self.slave_id, 0.0, reloaded=False, new_bits=False, qid=self.slave_id))

        if self.comm.slave_termination.value:
            self.comm.slave_locks_B[self.slave_id].release()
            send_msg(KAFL_TAG_RESULT, results, self.comm.to_mapserver_queue, source=self.slave_id)
            return 

        self.comm.slave_locks_B[self.slave_id].release()
        send_msg(KAFL_TAG_RESULT, results, self.comm.to_mapserver_queue, source=self.slave_id)

    def __check_filter_bitmaps(self):
        p = subprocess.Popen(["md5sum", "/dev/shm/kafl_filter0", "/dev/shm/kafl_tfilter"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return p.stdout.read()

    def __respond_sampling_req(self, response):
        payload = response.data[0]
        sampling_rate = response.data[1]

        self.stage_tick_treshold = 0
        sampling_counter = 0
        sampling_ticks = 0
        error_counter = 0

        round_checker = 0
        self.__restart_vm()
        self.q.set_payload(payload)

        filter_hash = self.__check_filter_bitmaps()

        while True:
            error = False
            while True:
                try:
                    self.q.enable_sampling_mode()
                    bitmap = self.q.send_payload()
                    break
                except:
                    log_slave("Sampling fail...", self.slave_id)
                    if not self.__restart_vm():
                        return

            for i in range(5):
                try:

                    if error_counter >= 2:
                        log_slave("Abort sampling...", self.slave_id)
                        error = False
                        break

                    new_bitmap = self.q.send_payload()
                    if self.q.crashed or self.q.timeout or self.q.kasan:
                        log_slave("Sampling timeout...", self.slave_id)
                        error_counter += 1
                        if not self.__restart_vm():
                            error = False
                            break
                    else:
                        self.q.submit_sampling_run()
                        sampling_counter += 1
                        sampling_ticks = self.q.end_ticks - self.q.start_ticks

                except:
                    log_slave("Sampling wtf??!", self.slave_id)
                    if not self.__restart_vm():
                        return

            while True:
                try:
                    self.q.disable_sampling_mode()
                    break
                except:
                    if not self.__restart_vm():
                        return


            tmp_hash = self.__check_filter_bitmaps()
            if tmp_hash == filter_hash:
                round_checker += 1
            else:
                round_checker = 0

            filter_hash = tmp_hash
            if round_checker == 5:
                break

        log_slave("Sampling findished!", self.slave_id)
        
        if sampling_counter == 0:
            sampling_counter = 1
        self.stage_tick_treshold = sampling_ticks / sampling_counter
        log_slave("sampling_ticks: " + str(sampling_ticks), self.slave_id)
        log_slave("sampling_counter: " + str(sampling_counter), self.slave_id)
        log_slave("STAGE_TICK_TRESHOLD: " + str(self.stage_tick_treshold), self.slave_id)

        if self.stage_tick_treshold == 0.0:
            self.stage_tick_treshold = 1.0
        self.q.set_tick_timeout_treshold(3 * self.stage_tick_treshold * self.timeout_tick_factor)

        send_msg(KAFL_TAG_REQ_SAMPLING, bitmap, self.comm.to_master_from_slave_queue, source=self.slave_id)

    def __respond_bitmap_req(self, response):
        self.q.set_payload(response.data)
        while True:
            try:
                bitmap = self.q.send_payload()
                break
            except:
                log_slave("__respond_bitmap_req failed...", self.slave_id)
                self.__restart_vm()
        send_msg(KAFL_TAG_REQ_BITMAP, bitmap, self.comm.to_master_from_slave_queue, source=self.slave_id)


    def __respond_benchmark_req(self, response):
        payload = response.data[0]
        benchmark_rate = response.data[1]
        for i in range(benchmark_rate):
            self.q.set_payload(payload)
            self.q.send_payload()
            if self.q.crashed or self.q.timeout or self.q.kasan:
                self.__restart_vm()
        send_msg(KAFL_TAG_REQ_BENCHMARK, None, self.comm.to_master_from_slave_queue, source=self.slave_id)

    def interprocess_proto_handler(self):
        response = recv_msg(self.comm.to_slave_queues[self.slave_id])

        if response.tag == KAFL_TAG_JOB:
            self.__respond_job_req(response)
            send_msg(KAFL_TAG_REQ, self.q.qemu_id, self.comm.to_master_queue, source=self.slave_id)

        elif response.tag == KAFL_TAG_REQ_BITMAP:
            self.__respond_bitmap_req(response)

        elif response.tag == KAFL_TAG_REQ_SAMPLING:
            self.__respond_sampling_req(response)

        elif response.tag == KAFL_TAG_REQ_BENCHMARK:
            self.__respond_benchmark_req(response)  

        else:
            log_slave("Received TAG: " + str(response.tag), self.slave_id)

    def loop(self):
        self.comm.reload_semaphore.acquire()
        self.q.start()
        self.comm.reload_semaphore.release()
            
        send_msg(KAFL_TAG_START, self.q.qemu_id, self.comm.to_master_queue, source=self.slave_id)
        send_msg(KAFL_TAG_REQ, self.q.qemu_id, self.comm.to_master_queue, source=self.slave_id)
        while True:
            #try:
            if self.comm.slave_termination.value:
                return
            self.interprocess_proto_handler()
            #except:
            #    return
