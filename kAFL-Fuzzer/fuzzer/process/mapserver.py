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

import os
import time

import mmh3, base64, lz4.frame
import collections

from fuzzer.communicator import send_msg, recv_msg, Communicator
from fuzzer.protocol import *
from fuzzer.state import MapserverState
from fuzzer.tree import *
from common.config import FuzzerConfiguration
from common.debug import log_mapserver
from common.qemu import qemu

__author__ = 'Sergej Schumilo'

class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)


def mapserver_loader(comm):
    log_mapserver("PID: " + str(os.getpid()))

    mapserver_process = MapserverProcess(comm)
    try:
        mapserver_process.loop()
    except KeyboardInterrupt:
        mapserver_process.comm.slave_termination.value = True
        mapserver_process.treemap.save_data()
        mapserver_process.save_data()
        log_mapserver("Date saved!")


class MapserverProcess:
    def __init__(self, comm, initial=True):

        self.comm = comm
        self.mapserver_state_obj = MapserverState()

        self.hash_list = set()
        self.crash_list = []
        self.shadow_map = set()

        self.last_hash = ""
        self.post_sync_master_tag = None

        self.effector_map = []
        self.abortion_counter = 0
        self.abortion_alredy_sent = False
        self.comm.stage_abortion_notifier.value = False
        self.new_findings = 0

        self.effector_initial_bitmap = None
        self.effector_sync = False
        self.performance = 0

        self.post_sync = False
        self.pre_sync = False
        self.round_counter = 0

        self.round_counter_effector_sync = 0
        self.round_counter_master_post = 0
        self.round_counter_master_pre = 0

        self.config = FuzzerConfiguration()
        self.enable_graphviz = self.config.argument_values['g']

        self.abortion_threshold = self.config.config_values['ABORTION_TRESHOLD']

        #self.q = qemu(1337, self.config)
        #self.q.start()

        self.ring_buffers = []
        for e in range(self.config.argument_values['p']):
            self.ring_buffers.append(collections.deque(maxlen=30))

        if self.config.load_old_state:
            self.load_data()
            self.treemap = KaflTree.load_data(enable_graphviz=self.enable_graphviz)
        else:
            msg = recv_msg(self.comm.to_mapserver_queue)
            self.mapserver_state_obj.pending = len(msg.data)
            self.treemap = KaflTree(msg.data, enable_graphviz=self.enable_graphviz)


    def __restart_vm(self):
        while True:
            self.q.__del__()
            self.q = qemu(1337, self.config)
            if self.q.start():
                break
            else:
                time.sleep(0.5)
                self.__log("Fail Reload")
        

    def __add_new_hash(self, new_hash, bitmap, payload, performance):
        """
        try:
            self.q.enable_sampling_mode()
            for i in range(5):
                self.q.set_payload(payload)
                new_bitmap = self.q.send_payload()
                if new_bitmap == self.q.send_payload():
                    self.q.submit_sampling_run()
                    break
                self.q.submit_sampling_run()
            self.q.disable_sampling_mode()
            accepted = self.treemap.append(payload, new_bitmap, performance=performance)
        except:
            self.__restart_vm()
            self.q.disable_sampling_mode()
            accepted = self.treemap.append(payload, bitmap, performance=performance)
        """
        accepted = self.treemap.append(payload, bitmap, performance=performance)
        if accepted:
            self.hash_list.add(new_hash)
        else:
            self.shadow_map.add(new_hash)
        return accepted

    def __save_ring_buffer(self, slave_id, target):
        data = []
        for payload in self.ring_buffers[slave_id]:
            data.append(base64.b64encode(payload))
        with open(target, 'w') as outfile:
            outfile.write(lz4.frame.compress(json.dumps(data)))

    def __check_hash(self, new_hash, bitmap, payload, crash, timeout, kasan, slave_id, reloaded, performance, qid, pos):
        self.ring_buffers[slave_id].append(str(payload))
        hash_was_new = False
        if new_hash != self.last_hash:
            if len(self.hash_list) == 0:
                hash_was_new = True
            if new_hash not in self.hash_list and new_hash not in self.shadow_map:
                hash_was_new = True

        if crash or kasan or timeout:
            #log_mapserver("CRASH: " + str(crash) + " KASAN: " + str(kasan) + " TIMOUT: " + str(timeout))
            #log_mapserver(str(payload))
            # fugly workaround
            #if fastCount(bitmap) >= (32 << 10):
            #    return
            if crash:
                if new_hash in self.crash_list:
                    self.mapserver_state_obj.crashes += 1
                else:
                    if self.treemap.is_unique_crash(bitmap):
                        self.abortion_counter = 0
                        log_mapserver("Unique crash submited by slave #" + str(slave_id) + " ...")
                        self.crash_list.append(new_hash)
                        if self.treemap.append(payload, bitmap, node_type=KaflNodeType.crash):
                            self.__save_ring_buffer(slave_id, self.config.argument_values['work_dir'] +  "/rbuf/crash_" + str(self.mapserver_state_obj.unique) + ".rbuf")
                            self.mapserver_state_obj.crashes += 1
                            self.mapserver_state_obj.unique += 1
                    else:
                        self.crash_list.append(new_hash)
                        self.mapserver_state_obj.crashes += 1
            elif kasan:
                if new_hash in self.crash_list:
                    self.mapserver_state_obj.kasan += 1
                else:
                    if self.treemap.is_unique_kasan(bitmap):
                        self.abortion_counter = 0
                        log_mapserver("Unique kasan report submited by slave #" + str(slave_id) + " ...")
                        self.crash_list.append(new_hash)
                        if self.treemap.append(payload, bitmap, node_type=KaflNodeType.kasan):
                            self.__save_ring_buffer(slave_id, self.config.argument_values['work_dir'] + "/rbuf/kasan_" + str(self.mapserver_state_obj.unique_kasan) + ".rbuf")
                            self.mapserver_state_obj.kasan += 1
                            self.mapserver_state_obj.unique_kasan += 1
                    else:
                        self.crash_list.append(new_hash)
                        self.mapserver_state_obj.kasan += 1
            elif timeout:
                if new_hash in self.crash_list:
                    self.mapserver_state_obj.timeout += 1
                else:
                    if self.treemap.is_unique_timeout(bitmap):
                        self.abortion_counter = 0
                        log_mapserver("Unique timeout detected by slave #" + str(slave_id) + " ...")
                        self.crash_list.append(new_hash)
                        if self.treemap.append(payload, bitmap, node_type=KaflNodeType.timeout):
                            self.__save_ring_buffer(slave_id, self.config.argument_values['work_dir'] + "/rbuf/timeout_" + str(self.mapserver_state_obj.unique_timeout) + ".rbuf")
                            self.mapserver_state_obj.timeout += 1
                            self.mapserver_state_obj.unique_timeout += 1
                    else:
                        self.crash_list.append(new_hash)
                        self.mapserver_state_obj.timeout += 1
        elif hash_was_new:
            #log_mapserver("NEW FINDING :" + str(payload))
            if self.__add_new_hash(new_hash, bitmap, payload, performance):
                #log_mapserver("NEW FINDING :" + str(payload))
                """
                os.system("cp /dev/shm/kafl_raw_" + str(qid) + "_" + str(pos) + " " + self.config.argument_values['work_dir'] + "/corpus/pt_buf_" + str(self.new_findings))
                """
                self.__update_state()
                self.new_findings += 1
                #self.mapserver_state_obj.path_pending += 1
                self.mapserver_state_obj.last_hash_time = time.time()

        if reloaded:
            self.ring_buffers[slave_id].clear()

    def __update_state(self):
        self.mapserver_state_obj.ratio_coverage, self.mapserver_state_obj.ratio_bits = self.treemap.get_bitmap_values()
        self.mapserver_state_obj.cycles = self.treemap.cycles
        self.mapserver_state_obj.hashes = self.treemap.paths
        self.mapserver_state_obj.path_pending = self.treemap.paths - self.treemap.paths_finished - self.treemap.paths_in_progress
        self.mapserver_state_obj.path_unfinished = self.treemap.paths_in_progress
        
        self.mapserver_state_obj.favorites = self.treemap.favorites
        self.mapserver_state_obj.fav_pending = self.treemap.favorites-self.treemap.favorites_finished - self.treemap.favorites_in_progress
        self.mapserver_state_obj.fav_unfinished = self.treemap.favorites_in_progress

    def __post_sync_handler(self):
        if self.round_counter_master_post == self.round_counter: #or self.abortion_alredy_sent:
            if self.post_sync_master_tag == KAFL_TAG_NXT_UNFIN:
                data = self.treemap.get_next(self.performance, finished=False)
            else:
                data = self.treemap.get_next(self.performance, finished=True)

            self.__update_state()
            self.mapserver_state_obj.level = data.level + 1
            state = data.node_state
            #data = data.load_payload()
            #data = state

            if state == KaflNodeState.in_progress or state == KaflNodeState.finished:
                send_msg(KAFL_TAG_NXT_UNFIN, data, self.comm.to_master_from_mapserver_queue)
            else:
                send_msg(KAFL_TAG_NXT_FIN, data, self.comm.to_master_from_mapserver_queue)
            #if len(self.shadow_map) > 1024:
            #    self.shadow_map = set()
            return True
        return False

    def __pre_sync_handler(self):
        log_mapserver("__pre_sync_handler: " + str(self.round_counter_master_pre ) + " / " + str(self.round_counter))
        if (self.round_counter_master_pre == self.round_counter):# or self.abortion_alredy_sent:
            send_msg(KAFL_TAG_UNTOUCHED_NODES, self.treemap.get_num_of_untouched_nodes(),
                     self.comm.to_master_from_mapserver_queue)
            return True
        return False

    def __effector_sync_handler(self):
        log_mapserver("__effector_sync_handler: " + str(self.round_counter_effector_sync ) + " / " + str(self.round_counter))
        if (self.round_counter_effector_sync == self.round_counter) or self.abortion_alredy_sent:
            send_msg(KAFL_TAG_GET_EFFECTOR, self.effector_map, self.comm.to_master_from_mapserver_queue)
            return True
        return False

    def __result_tag_handler(self, request):
        self.comm.slave_locks_B[request.source].acquire()
        results = request.data
        payloads = []
        bitmaps = []
        payload_shm = self.comm.get_mapserver_payload_shm(request.source)
        bitmap_shm = self.comm.get_bitmap_shm(request.source)

        for result in results:
            if result.new_bits:
                bitmap_shm.seek(result.pos * self.comm.get_bitmap_shm_size())
                payload_shm.seek(result.pos * self.comm.get_mapserver_payload_shm_size())
                length = payload_shm.read(4)
                data_len = (ord(length[3]) << 24) + (ord(length[2]) << 16) + (ord(length[1]) << 8) + \
                           (ord(length[0]))
                payloads.append(payload_shm.read(data_len))
                bitmaps.append(bitmap_shm.read(self.comm.get_bitmap_shm_size()))
            else:
                payloads.append(None)
                bitmaps.append(None)
                #log_mapserver("[MAPS]\t\ SKIP")
        self.comm.slave_locks_A[request.source].release()
        for i in range(len(results)):
            if results[i].reloaded:
                self.abortion_counter += 1

            if results[i].new_bits:
                if results[i].timeout:
                    self.mapserver_state_obj.timeout += 1
                new_hash = mmh3.hash64(bitmaps[i])

                self.__check_hash(new_hash, bitmaps[i], payloads[i], results[i].crash, results[i].timeout, results[i].kasan, results[i].slave_id, results[i].reloaded, results[i].performance, results[i].qid, results[i].pos)
                self.last_hash = new_hash
                self.round_counter += 1
                if self.effector_initial_bitmap:
                    if self.effector_initial_bitmap != new_hash:
                        for j in results[i].affected_bytes:
                            if not self.effector_map[j]:
                                self.effector_map[j] = True
            else:
                self.round_counter += 1

        # TODO: Replace const value by performance*(1/50)s
        if self.abortion_counter >= self.abortion_threshold:
            if not self.abortion_alredy_sent:
                log_mapserver("Stage abortion limit (" + str(self.abortion_threshold) + ") reached!")
                send_msg(KAFL_TAG_ABORT_REQ, self.mapserver_state_obj, self.comm.to_master_queue)
                self.abortion_alredy_sent = True
                self.comm.stage_abortion_notifier.value = True

    def __map_info_tag_handler(self, request):
        send_msg(KAFL_TAG_MAP_INFO, self.mapserver_state_obj, self.comm.to_master_queue)

    def __next_tag_handler(self, request):
        self.post_sync_master_tag = request.tag
        self.post_sync = True
        self.round_counter_master_post = request.data[0]
        self.performance = request.data[1]
        log_mapserver("Performance: " + str(self.performance))

    # Todo
    def __pre_abort_tag_handler(self, request):
        self.round_counter_master_pre = request.data
        self.pre_sync = True

    # Todo
    def __post_abort_tag_handler(self, request):
        self.round_counter_master_post = self.round_counter_master_pre + request.data
        self.pre_sync = False

    def __untouched_tag_handler(self, request):
        self.round_counter_master_pre = request.data
        self.pre_sync = True

    def __req_effector_tag_handler(self, request):
        #log_mapserver("New Effector Map (" + str(len(request.data)) + ")")
        self.effector_initial_bitmap = mmh3.hash64(request.data)
        for i in range(self.config.config_values['PAYLOAD_SHM_SIZE']):
            self.effector_map.append(False)

    def __get_effector_tag_handler(self, request):
        self.round_counter_effector_sync = request.data
        self.effector_sync = True

    def __sync_handler(self):
        if self.effector_sync:
            if self.__effector_sync_handler():
                self.effector_sync = False
                self.effector_initial_bitmap = None
                self.effector_map = []
                #log_mapserver("Deactivate Effector Mapping...")
                #log_mapserver("ShadowMap Size: " + str(len(self.shadow_map)))

        if self.pre_sync:
            if self.__pre_sync_handler():
                self.pre_sync = False
                self.round_counter_master_pre = 0
                log_mapserver("ShadowMap Size: " + str(len(self.shadow_map)))

        if self.post_sync:
            if self.__post_sync_handler():
                self.post_sync = False
                self.round_counter_master_post = 0
                self.round_counter = 0

    def loop(self):
        while True:
            self.__sync_handler()
            request = recv_msg(self.comm.to_mapserver_queue)

            if request.tag == KAFL_TAG_RESULT:
                self.__result_tag_handler(request)
            elif request.tag == KAFL_TAG_MAP_INFO:
                self.__map_info_tag_handler(request)
            elif request.tag == KAFL_TAG_NXT_FIN or request.tag == KAFL_TAG_NXT_UNFIN:
                self.abortion_counter = 0
                self.abortion_alredy_sent = False
                self.comm.stage_abortion_notifier.value = False
                self.__next_tag_handler(request)
            elif request.tag == KAFL_TAG_UNTOUCHED_NODES:
                self.__untouched_tag_handler(request)
            elif request.tag == KAFL_TAG_REQ_EFFECTOR:
                self.__req_effector_tag_handler(request)
            elif request.tag == KAFL_TAG_GET_EFFECTOR:
                self.__get_effector_tag_handler(request)

    def save_data(self):
        """
        Method to store an entire master state to JSON file...
        """

        dump = {}

        for key, value in self.__dict__.iteritems():
            if key == "mapserver_state_obj":
                dump[key] = self.mapserver_state_obj.save_data()
            elif key == "enable_graphviz" or key == "last_hash":
                dump[key] = self.enable_graphviz
            elif key == "hash_list" or key == "shadow_map":
                tmp = []
                for e in value:
                    tmp.append(e)
                dump[key] = tmp


        with open(self.config.argument_values['work_dir'] + "/mapserver.json", 'w') as outfile:
            json.dump(dump, outfile, default=json_dumper, cls=SetEncoder, indent=4)

    def load_data(self):
        """
        Method to load an entire master state from JSON file...
        """
        with open(FuzzerConfiguration().argument_values['work_dir'] + "/mapserver.json", 'r') as infile:
            dump = json.load(infile)
            for key, value in dump.iteritems():
                if key == "hash_list" or key == "shadow_map":
                    tmp = set()
                    for e in value:
                        tmp.add(tuple(e))
                    setattr(self, key, tmp)
                elif key == "mapserver_state_obj":
                    tmp = MapserverState()
                    tmp.load_data(value)
                    setattr(self, key, tmp)
                else:
                    setattr(self, key, value)
