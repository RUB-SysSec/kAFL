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

import json
import base64

from fuzzer.communicator import *
from fuzzer.protocol import *
from fuzzer.state import *
from fuzzer.technique.arithmetic import *
from fuzzer.technique.bitflip import *
from fuzzer.technique.havoc import *
from fuzzer.technique.interesting_values import *
from fuzzer.technique.debug import *
from fuzzer.tree import KaflNodeType
from common.util import get_seed_files, check_state_exists, json_dumper
from common.config import FuzzerConfiguration
from common.debug import log_master
from shutil import copyfile


import os, mmap
__author__ = 'Sergej Schumilo'


class MasterProcess:

    HAVOC_MULTIPLIER = 1.0

    def __init__(self, comm):
        self.comm = comm
        self.kafl_state = State()
        self.payload = ""

        self.counter = 0
        self.round_counter = 0
        self.start = time.time()
        self.benchmark_time = time.time()
        self.counter_offset = 0
        self.payload_buffer = []
        self.byte_map = []
        self.stage_abortion = False
        self.abortion_counter = 0

        self.mapserver_status_pending = False

        self.config = FuzzerConfiguration()
        self.skip_zero = self.config.argument_values['s']
        self.refresh_rate = self.config.config_values['UI_REFRESH_RATE']
        self.use_effector_map = self.config.argument_values['d']
        self.arith_max = FuzzerConfiguration().config_values["ARITHMETIC_MAX"]

        if not self.config.argument_values['D']:
            self.use_effector_map = False

        if self.config.load_old_state:
            self.load_data()

        log_master("Use effector maps: " + str(self.use_effector_map))

    def __start_processes(self):
        for i in range(self.comm.num_processes):
            start_time = time.time()
            recv_tagged_msg(self.comm.to_master_queue, KAFL_TAG_START)
            self.kafl_state.slaves_ready += 1
            if (time.time() - start_time) >= 0.1:
                send_msg(KAFL_TAG_OUTPUT, self.kafl_state, self.comm.to_update_queue)

        self.kafl_state.loading = False
        if not self.config.load_old_state:
            self.kafl_state.runtime = time.time()
        send_msg(KAFL_TAG_OUTPUT, self.kafl_state, self.comm.to_update_queue)


    def __bitflip_handler(self, payload, no_data=False, affected_bytes=None):
        if not no_data:
            self.kafl_state.progress_bitflip += 1
            self.kafl_state.total += 1
            self.__buffered_handler(payload, affected_bytes=affected_bytes)

    def __arithmetic_handler(self, payload, no_data=False):
        if not no_data:
            self.kafl_state.progress_arithmetic += 1
            self.kafl_state.total += 1
            self.__buffered_handler(payload)

    def __interesting_handler(self, payload, no_data=False):
        if not no_data:
            self.kafl_state.progress_interesting += 1
            self.kafl_state.total += 1
            self.__buffered_handler(payload)

    def __havoc_handler(self, payload, no_data=False):
        if not no_data:
            self.kafl_state.progress_havoc += 1
            self.kafl_state.total += 1
            self.__buffered_handler(payload)

    def __splicing_handler(self, payload, no_data=False):
        if not no_data:
            self.kafl_state.progress_specific += 1
            self.kafl_state.total += 1
            self.__buffered_handler(payload)

    def __buffered_handler(self, payload, affected_bytes=None, last_payload=False):
        if not self.stage_abortion:
            #self.abortion_counter += 1
            if not last_payload:
                self.payload_buffer.append(payload)
                if affected_bytes:
                    self.byte_map.append(affected_bytes)
                if len(self.payload_buffer) == self.comm.tasks_per_requests:
                    self.__master_handler()
                    self.payload_buffer = []
                    self.byte_map = []
            else:
                if len(self.payload_buffer) != 0:
                    self.__master_handler()
                    self.payload_buffer = []
                    self.byte_map = []

    def __process_mapserver_state(self, msg):
        map_state = msg.data
        self.kafl_state.level = map_state.level
        if map_state.level > self.kafl_state.max_level:
            self.kafl_state.max_level = map_state.level
        self.kafl_state.reloads = map_state.timeout
        self.kafl_state.reloads_unique = map_state.unique_timeout
        self.kafl_state.kasan = map_state.kasan
        self.kafl_state.kasan_unique = map_state.unique_kasan
        self.kafl_state.panics = map_state.crashes
        self.kafl_state.panics_unique = map_state.unique
        self.kafl_state.hashes = map_state.hashes
        self.kafl_state.pending = map_state.pending
        self.kafl_state.cycles = map_state.cycles
        self.kafl_state.reloads = map_state.timeout
        self.kafl_state.favorites = map_state.favorites
        self.kafl_state.ratio_coverage = map_state.ratio_coverage
        self.kafl_state.ratio_bits = map_state.ratio_bits

        self.kafl_state.path_pending = map_state.path_pending
        self.kafl_state.path_unfinished = map_state.path_unfinished
        self.kafl_state.fav_pending = map_state.fav_pending
        self.kafl_state.fav_unfinished = map_state.fav_unfinished

        if map_state.last_hash_time:
            self.kafl_state.last_hash_time = map_state.last_hash_time
        send_msg(KAFL_TAG_OUTPUT, self.kafl_state, self.comm.to_update_queue)     

    def __master_handler(self):
        if (time.time() - self.start) >= self.refresh_rate and not self.mapserver_status_pending:
            send_msg(KAFL_TAG_MAP_INFO, None, self.comm.to_mapserver_queue)
            end = time.time()
            #self.kafl_state.performance = int(((self.counter * 1.0) / (end - self.start)))
            self.kafl_state.performance_rb.append(int(((self.counter * 1.0) / (end - self.start))))
            self.kafl_state.max_performance_rb.append(int(((self.counter * 1.0) / (end - self.start))))
            self.start = time.time()
            self.counter = 0
            self.mapserver_status_pending = True

        while True:
            msg = recv_msg(self.comm.to_master_queue)
            if msg.tag == KAFL_TAG_REQ:
                self.__task_send(self.payload_buffer, msg.data, self.comm.to_slave_queues[int(msg.data)])
                self.abortion_counter += len(self.payload_buffer)
                self.counter += len(self.payload_buffer)
                self.round_counter += len(self.payload_buffer)
                break
            elif msg.tag == KAFL_TAG_ABORT_REQ:
                log_master("Abortion request received...")
                self.stage_abortion = True
                self.payload_buffer = []
                self.byte_map = []
                return
            elif msg.tag == KAFL_TAG_MAP_INFO:
                self.__process_mapserver_state(msg)
                self.mapserver_status_pending = False
                send_msg(KAFL_TAG_OUTPUT, self.kafl_state, self.comm.to_update_queue)
            else:
                raise Exception("Unknown msg-tag received in master process...")

    def __get_num_of_finds(self):
        if self.stage_abortion:
            send_msg(KAFL_TAG_UNTOUCHED_NODES, self.abortion_counter, self.comm.to_mapserver_queue)
        else:
            send_msg(KAFL_TAG_UNTOUCHED_NODES, self.round_counter, self.comm.to_mapserver_queue)
        result = recv_msg(self.comm.to_master_from_mapserver_queue).data
        log_master("Current findings: " + str(result))
        return result

    def __recv_next(self, finished, performance):
        if finished or self.stage_abortion:
            send_msg(KAFL_TAG_NXT_FIN, [self.round_counter, performance], self.comm.to_mapserver_queue)
        else:
            send_msg(KAFL_TAG_NXT_UNFIN, [self.round_counter, performance], self.comm.to_mapserver_queue)
        msg = recv_msg(self.comm.to_master_from_mapserver_queue)
        payload = msg.data
        if msg.tag == KAFL_TAG_NXT_FIN:
            return payload, False
        else:
            return payload, True

    def __task_send(self, tasks, qid, dest):
        fs_shm = self.comm.get_master_payload_shm(int(qid))
        size = self.comm.get_master_payload_shm_size()
        for i in range(len(tasks)):
            fs_shm.seek(size * i)
            input_len = to_string_32(len(tasks[i]))
            fs_shm.write_byte(input_len[3])
            fs_shm.write_byte(input_len[2])
            fs_shm.write_byte(input_len[1])
            fs_shm.write_byte(input_len[0])
            fs_shm.write(tasks[i])
        if self.byte_map:
            data = self.byte_map
        else:
            data = []
            for i in range(len(tasks)):
                data.append(None)
        send_msg(KAFL_TAG_JOB, data, dest)

    def __request_bitmap(self, payload):
        send_msg(KAFL_TAG_REQ_BITMAP, payload, self.comm.to_slave_queues[0])
        msg = recv_tagged_msg(self.comm.to_master_from_slave_queue, KAFL_TAG_REQ_BITMAP)
        return msg.data

    def __commission_effector_map(self, bitmap):
        log_master("__commission_effector_map")
        send_msg(KAFL_TAG_REQ_EFFECTOR, bitmap, self.comm.to_mapserver_queue)

    def __get_effector_map(self, bitflip_amount):
        send_msg(KAFL_TAG_GET_EFFECTOR, bitflip_amount, self.comm.to_mapserver_queue)
        msg = recv_msg(self.comm.to_master_from_mapserver_queue)
        return msg.data

    def __benchmarking(self, payload):
        c = 0
        runs = 3
        log_master("Initial benchmark...")
        start_run = time.time()
        send_msg(KAFL_TAG_REQ_BENCHMARK, [payload, runs], self.comm.to_slave_queues[0])
        recv_tagged_msg(self.comm.to_master_from_slave_queue, KAFL_TAG_REQ_BENCHMARK)

        multiplier = int(5 / (time.time()-start_run))
        if multiplier == 0:
        	multiplier = 1

        log_master("Initial benchmark multiplier: " + str(multiplier))

        self.__start_benchmark(0)
        for slave in self.comm.to_slave_queues:
            send_msg(KAFL_TAG_REQ_BENCHMARK, [payload, multiplier*runs], slave)
            c += 1
        for i in range(c):
            recv_tagged_msg(self.comm.to_master_from_slave_queue, KAFL_TAG_REQ_BENCHMARK)
            self.round_counter += multiplier*runs

        value = self.__stop_benchmark()
        self.round_counter = 0
        log_master("Initial benchmark result: " + str(value) + " t/s")
        for i in range(2):
        	self.kafl_state.performance_rb.append(value)
        	self.kafl_state.max_performance_rb.append(value)

    def __sampling(self, payload, initial_run=False):
        c = 0
        max_slaves = multiprocessing.cpu_count()/2
        for slave in self.comm.to_slave_queues:
            if(initial_run):
                send_msg(KAFL_TAG_REQ_SAMPLING, [payload, int(self.kafl_state.get_performance()/self.comm.num_processes)*3], slave)
            else:
                send_msg(KAFL_TAG_REQ_SAMPLING, [payload, int(self.kafl_state.get_performance()/self.comm.num_processes)], slave)
            c += 1
            if c == max_slaves:
                break
        for i in range(c):
            msg = recv_tagged_msg(self.comm.to_master_from_slave_queue, KAFL_TAG_REQ_SAMPLING)
        return msg.data

    def __start_benchmark(self, counter_offset):
        self.benchmark_time = time.time()
        self.counter_offset = counter_offset

    def __stop_benchmark(self):
        end = time.time()
        return int((((self.round_counter-self.counter_offset) * 1.0) / (end - self.benchmark_time)))

    def __init_fuzzing_loop(self):
        self.kafl_state.cycles = 0
        self.__start_processes()

        if self.config.load_old_state:
            log_master("State exists!")
        else:
            log_master("State does not exist!")
            payloads = get_seed_files(self.config.argument_values['work_dir'] + "/corpus")
            data = []
            for payload in payloads:
                bitmap = self.__request_bitmap(payload)
                data.append((payload, bitmap))
            send_msg(KAFL_INIT_BITMAP, data, self.comm.to_mapserver_queue)
            self.payload = payloads[0]

    def __calc_stage_iterations(self):
        self.kafl_state.progress_bitflip = 0
        self.kafl_state.progress_arithmetic = 0
        self.kafl_state.progress_interesting = 0
        self.kafl_state.progress_havoc = 0
        self.kafl_state.progress_specific = 0
        self.kafl_state.payload_size = len(self.payload)
        self.kafl_state.payload = self.payload

        limiter_map = []
        for i in range(len(self.payload)):
            limiter_map.append(True)
        if self.config.argument_values['i']:
            for ignores in self.config.argument_values['i']:
                log_master("Ignore-range 0: " + str(ignores[0]) + " " + str(min(ignores[0], len(self.payload))))
                log_master("Ignore-range 1: " + str(ignores[1]) + " " + str(min(ignores[1], len(self.payload))))
                for i in range(min(ignores[0], len(self.payload)), min(ignores[1], len(self.payload))):
                    #log_master("IGN: " + str(i))
                    limiter_map[i] = False

        if self.config.argument_values['D']:
            self.kafl_state.progress_bitflip_amount = bitflip_range(self.payload, skip_null=self.skip_zero, effector_map=limiter_map)
            self.kafl_state.progress_arithmetic_amount = arithmetic_range(self.payload, skip_null=self.skip_zero,  effector_map=limiter_map, set_arith_max=self.arith_max)
            self.kafl_state.progress_interesting_amount = interesting_range(self.payload, skip_null=self.skip_zero,  effector_map=limiter_map)
        else:
            self.kafl_state.progress_bitflip_amount = 0
            self.kafl_state.progress_arithmetic_amount = 0
            self.kafl_state.progress_interesting_amount = 0

        self.kafl_state.progress_havoc_amount = havoc_range(self.kafl_state.get_performance() * self.HAVOC_MULTIPLIER)
        self.kafl_state.progress_specific_amount = havoc_range(self.kafl_state.get_performance() * self.HAVOC_MULTIPLIER)

        self.__start_benchmark(self.round_counter)
        return limiter_map

    def __perform_bechmark(self):
        if self.config.argument_values['n']:
            self.kafl_state.technique = "BENCHMARKING"
            send_msg(KAFL_TAG_OUTPUT, self.kafl_state, self.comm.to_update_queue)
            self.__benchmarking(self.payload)

    def __perform_sampling(self):
        if self.config.argument_values['n']:
            self.kafl_state.technique = "PRE-SAMPLING"
            send_msg(KAFL_TAG_OUTPUT, self.kafl_state, self.comm.to_update_queue)
            if self.kafl_state.total == 0:
                self.__sampling(self.payload, initial_run=True)
            #else:
            #    self.__sampling(self.payload)

    def __perform_deterministic(self, payload_array, limiter_map):
        if self.config.argument_values['D']:

            if not self.comm.sampling_failed_notifier.value:
                if self.use_effector_map:
                    self.comm.effector_mode.value = True
                    log_master("Request effector map")
                    bitmap = self.__request_bitmap(self.payload)
                    self.__commission_effector_map(bitmap)

            if self.comm.sampling_failed_notifier.value:
                self.stage_abortion = True
                self.comm.sampling_failed_notifier.value = False

            log_master("Bit Flip...")
            mutate_seq_walking_bits_array(payload_array,          self.__bitflip_handler, skip_null=self.skip_zero, kafl_state=self.kafl_state, effector_map=limiter_map)
            mutate_seq_two_walking_bits_array(payload_array,      self.__bitflip_handler, skip_null=self.skip_zero, kafl_state=self.kafl_state, effector_map=limiter_map)
            mutate_seq_four_walking_bits_array(payload_array,     self.__bitflip_handler, skip_null=self.skip_zero, kafl_state=self.kafl_state, effector_map=limiter_map)
            mutate_seq_walking_byte_array(payload_array,          self.__bitflip_handler, skip_null=self.skip_zero, kafl_state=self.kafl_state, effector_map=limiter_map)
            mutate_seq_two_walking_bytes_array(payload_array,     self.__bitflip_handler, kafl_state=self.kafl_state, effector_map=limiter_map)
            mutate_seq_four_walking_bytes_array(payload_array,    self.__bitflip_handler, kafl_state=self.kafl_state, effector_map=limiter_map)
            self.__buffered_handler(None, last_payload=True)

            log_master("progress_bitflip: " + str(self.kafl_state.progress_bitflip))
            log_master("progress_bitflip_amount: " + str(self.kafl_state.progress_bitflip_amount))
            #self.kafl_state.progress_bitflip = self.kafl_state.progress_bitflip_amount
            self.kafl_state.progress_bitflip_amount = self.kafl_state.progress_bitflip
            log_master("Bit Flip done...")
            #self.use_effector_map = False
            if not self.stage_abortion:
                if self.use_effector_map:
                    log_master("tUse Effector Map...")
                    effector_map = self.__get_effector_map(self.kafl_state.progress_bitflip)
                    self.comm.effector_mode.value = False
                    self.byte_map = []
                    self.kafl_state.progress_arithmetic_amount = arithmetic_range(self.payload, skip_null=self.skip_zero, effector_map=effector_map)
                    self.kafl_state.progress_interesting_amount = interesting_range(self.payload, skip_null=self.skip_zero, effector_map=effector_map)
                    self.kafl_state.technique = "EFF-SYNC"
                    send_msg(KAFL_TAG_OUTPUT, self.kafl_state, self.comm.to_update_queue)
                    log_master("Effectormap size is " + str(sum(x is True for x in effector_map)))
                    log_master("Effector arihmetic size is " + str(arithmetic_range(self.payload, skip_null=self.skip_zero, effector_map=effector_map)))
                    log_master("Effector intersting size is " + str(interesting_range(self.payload, skip_null=self.skip_zero, effector_map=effector_map)))
                    new_effector_map = []
                    for i in range(len(effector_map)):
                        if effector_map[i] and limiter_map[i]:
                            new_effector_map.append(True)
                        else:
                            new_effector_map.append(False)
                    effector_map = new_effector_map
                else:
                    log_master("No effector map!")
                    effector_map = limiter_map
                    self.kafl_state.progress_arithmetic_amount = arithmetic_range(self.payload, skip_null=self.skip_zero, effector_map=effector_map)
                    self.kafl_state.progress_interesting_amount = interesting_range(self.payload, skip_null=self.skip_zero, effector_map=effector_map)
                    send_msg(KAFL_TAG_OUTPUT, self.kafl_state, self.comm.to_update_queue)
                    
                self.comm.effector_mode.value = False
                log_master("Arithmetic...")
                mutate_seq_8_bit_arithmetic_array(payload_array,      self.__arithmetic_handler, skip_null=self.skip_zero, kafl_state=self.kafl_state, effector_map=effector_map, set_arith_max=self.arith_max)
                mutate_seq_16_bit_arithmetic_array(payload_array,     self.__arithmetic_handler, skip_null=self.skip_zero, kafl_state=self.kafl_state, effector_map=effector_map, set_arith_max=self.arith_max)
                mutate_seq_32_bit_arithmetic_array(payload_array,     self.__arithmetic_handler, skip_null=self.skip_zero, kafl_state=self.kafl_state, effector_map=effector_map, set_arith_max=self.arith_max)
                self.__buffered_handler(None, last_payload=True)
                self.kafl_state.progress_arithmetic = self.kafl_state.progress_arithmetic_amount

                log_master("Intesting...")

                mutate_seq_8_bit_interesting_array(payload_array,     self.__interesting_handler, skip_null=self.skip_zero, kafl_state=self.kafl_state, effector_map=effector_map)
                mutate_seq_16_bit_interesting_array(payload_array,    self.__interesting_handler, skip_null=self.skip_zero, kafl_state=self.kafl_state, effector_map=effector_map, set_arith_max=self.arith_max)
                mutate_seq_32_bit_interesting_array(payload_array,    self.__interesting_handler, skip_null=self.skip_zero, kafl_state=self.kafl_state, effector_map=effector_map, set_arith_max=self.arith_max)
                self.__buffered_handler(None, last_payload=True)
                self.kafl_state.progress_interesting = self.kafl_state.progress_interesting_amount

                self.kafl_state.technique = "PRE-SYNC"
                send_msg(KAFL_TAG_OUTPUT, self.kafl_state, self.comm.to_update_queue)

            else:
                effector_map = self.__get_effector_map(self.abortion_counter)

    def __perform_havoc(self, payload_array, payload):
        log_master("Havoc...")
        self.kafl_state.progress_bitflip = self.kafl_state.progress_bitflip_amount
        self.kafl_state.progress_arithmetic = self.kafl_state.progress_arithmetic_amount
        self.kafl_state.progress_interesting = self.kafl_state.progress_interesting_amount

        if payload and payload.node_type == KaflNodeType.favorite:
            self.kafl_state.progress_havoc_amount = havoc_range(self.kafl_state.get_performance() * self.HAVOC_MULTIPLIER * 2.0)
            self.kafl_state.progress_specific_amount = havoc_range(self.kafl_state.get_performance() * self.HAVOC_MULTIPLIER * 2.0)
        else:
            self.kafl_state.progress_havoc_amount = havoc_range(self.kafl_state.get_performance() * self.HAVOC_MULTIPLIER)
            self.kafl_state.progress_specific_amount = havoc_range(self.kafl_state.get_performance() * self.HAVOC_MULTIPLIER)

        self.kafl_state.technique = "HAVOC"
        mutate_seq_havoc_array(payload_array, self.__havoc_handler, self.kafl_state.progress_havoc_amount)
        self.__buffered_handler(None, last_payload=True)
        self.kafl_state.progress_havoc_amount = self.kafl_state.progress_havoc

        self.kafl_state.technique = "SPLICING"
        mutate_seq_splice_array(payload_array, self.__splicing_handler, self.kafl_state.progress_havoc_amount, self.kafl_state)
        self.__buffered_handler(None, last_payload=True)

    def __perform_post_sync(self, finished):
        self.kafl_state.technique = "POST-SYNC"
        send_msg(KAFL_TAG_OUTPUT, self.kafl_state, self.comm.to_update_queue)
        payload, finished_state = self.__recv_next(finished, self.__stop_benchmark())
        log_master("finished_state -> " + str(finished_state))
        self.payload = payload.load_payload()
        self.round_counter = 0
        self.stage_abortion = False
        self.abortion_counter = 0
        return payload, finished_state


    def wipe(self):
    	filter_bitmap_fd = os.open("/dev/shm/kafl_filter0", os.O_RDWR | os.O_SYNC | os.O_CREAT)
        os.ftruncate(filter_bitmap_fd, self.config.config_values['BITMAP_SHM_SIZE'])
        filter_bitmap = mmap.mmap(filter_bitmap_fd, self.config.config_values['BITMAP_SHM_SIZE'], mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)
        for i in range(self.config.config_values['BITMAP_SHM_SIZE']):
        	filter_bitmap[i] = '\x00'
        filter_bitmap.close()
        os.close(filter_bitmap_fd)

        filter_bitmap_fd = os.open("/dev/shm/kafl_tfilter", os.O_RDWR | os.O_SYNC | os.O_CREAT)
        os.ftruncate(filter_bitmap_fd, 0x1000000)
        filter_bitmap = mmap.mmap(filter_bitmap_fd, 0x1000000, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)
        for i in range(0x1000000):
        	filter_bitmap[i] = '\x00'
        filter_bitmap.close()
        os.close(filter_bitmap_fd)


    def loop(self):
        finished_state = False
        finished = False
        payload = None

        self.__init_fuzzing_loop()
        self.__perform_bechmark()

        while True:

            #self.wipe()

            payload_array = array('B', self.payload)
            limiter_map = self.__calc_stage_iterations()

            if not finished_state:
                self.__perform_sampling()
                self.__perform_deterministic(payload_array, limiter_map)
                finished = False

            num_of_finds = self.__get_num_of_finds()
            if num_of_finds == 0 or finished_state:
                while True:
                    self.__perform_havoc(payload_array, payload)
                    finished = True
                    num_of_finds_tmp = self.__get_num_of_finds()
                    if num_of_finds == num_of_finds_tmp or self.stage_abortion:
                        break
                    else:
                        num_of_finds = num_of_finds_tmp
                        log_master("Repeat!")
                        self.kafl_state.progress_havoc = 0
                        self.kafl_state.progress_specific = 0
                        self.kafl_state.progress_havoc_amount = havoc_range(self.kafl_state.get_performance() * self.HAVOC_MULTIPLIER)
                        self.kafl_state.progress_specific_amount = havoc_range(self.kafl_state.get_performance() * self.HAVOC_MULTIPLIER)
                        self.kafl_state.technique = "HAVOC"
                        send_msg(KAFL_TAG_OUTPUT, self.kafl_state, self.comm.to_update_queue)

            payload, finished_state = self.__perform_post_sync(finished)

    def save_data(self):
        """
        Method to store an entire master state to JSON file...
        """
        dump = {}
        for key, value in self.__dict__.iteritems():
            if key == "kafl_state":
                dump[key] = value.save_data()

        with open(self.config.argument_values['work_dir'] + "/master.json", 'w') as outfile:
            json.dump(dump, outfile, default=json_dumper)

        # Save kAFL Filter
        copyfile("/dev/shm/kafl_filter0", self.config.argument_values['work_dir'] + "/kafl_filter0")

    def load_data(self):
        """
        Method to load an entire master state from JSON file...
        """
        with open(FuzzerConfiguration().argument_values['work_dir'] + "/master.json", 'r') as infile:
            dump = json.load(infile)
            for key, value in dump.iteritems():
                if key == "kafl_state":
                    self.kafl_state.load_data(value)
                else:
                    setattr(self, key, value)

        copyfile(self.config.argument_values['work_dir'] + "/kafl_filter0", "/dev/shm/kafl_filter0")

