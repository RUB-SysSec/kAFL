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

from fuzzer.communicator import recv_msg, Communicator
from threading import Thread
from common.config import FuzzerConfiguration
from common.debug import log_update
from common.ui import *
from common.evaluation import Evaluation

__author__ = 'Sergej Schumilo'


def update_loader(comm):
    log_update("PID: " + str(os.getpid()))
    slave_process = UpdateProcess(comm)
    try:
        slave_process.loop()
    except KeyboardInterrupt:
        log_update("Exiting...")

class UpdateProcess:
    def __init__(self, comm):
        self.comm = comm
        self.config = FuzzerConfiguration()
        self.timeout = self.config.config_values['UI_REFRESH_RATE']


    def blacklist_updater(self, ui):
        while True:
            try:
                counter = 0
                with open("/dev/shm/kafl_filter0", "rb") as f:
                    while True:
                        byte = f.read(1)
                        if not byte:
                            break
                        if byte != '\x00':
                            counter += 1
                ui.blacklist_counter = counter

                counter = 0
                with open("/dev/shm/kafl_tfilter", "rb") as f:
                    while True:
                        byte = f.read(1)
                        if not byte:
                            break
                        if byte != '\x00':
                            counter += 1
                ui.blacklist_tcounter = counter

            except:
                pass
            time.sleep(2)

    def __update_ui(self, ui, ev, update, msg):
        if msg:
            update = msg.data
            ui.update_state(update)
            ev.write_data(update, ui.blacklist_counter)
        elif update:
            update.performance_rb.append(0)
            ui.update_state(update)
            ev.write_data(update, ui.blacklist_counter)
        ui.refresh()


    def loop(self):
        ui = FuzzerUI(self.comm.num_processes, fancy=self.config.argument_values['f'], inline_log=self.config.argument_values['l'])
        ev = Evaluation(self.config)
        ui.install_sighandler()
        Thread(target=self.blacklist_updater, args=(ui,)).start()
        update = None
        while True:
            msg = recv_msg(self.comm.to_update_queue, timeout=self.timeout)
            self.__update_ui(ui, ev, update, msg)
            while not self.comm.to_update_queue.empty():
                msg = recv_msg(self.comm.to_update_queue)
                self.__update_ui(ui, ev, update, msg)
