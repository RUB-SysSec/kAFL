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
import time
import os
import signal
from fuzzer.communicator import Communicator
from process.mapserver import mapserver_loader
from process.master import MasterProcess
from process.slave import slave_loader
from process.update import update_loader
from common.debug import log_core, enable_logging
from common.qemu import qemu
from common.util import prepare_working_dir, copy_seed_files, print_fail, \
    check_if_old_state_exits, print_exit_msg, check_state_exists, print_pre_exit_msg, ask_for_purge, print_warning
from common.config import FuzzerConfiguration
from common.self_check import post_self_check


__author__ = 'Sergej Schumilo'


def start():
    config = FuzzerConfiguration()

    if not post_self_check(config):
        return -1

    if config.argument_values['v']:
        enable_logging()

    num_processes = config.argument_values['p']

    if config.argument_values['Purge'] and check_if_old_state_exits(config.argument_values['work_dir']):
        print_warning("Old workspace found!")
        if ask_for_purge("PURGE"):
            print_warning("Wiping old workspace...")
            prepare_working_dir(config.argument_values['work_dir'], purge=config.argument_values['Purge'])
            time.sleep(2)
        else:
            print_fail("Aborting...")
            return 0

    if not check_if_old_state_exits(config.argument_values['work_dir']):
        if not prepare_working_dir(config.argument_values['work_dir'], purge=config.argument_values['Purge']):
            print_fail("Working directory is weired or corrupted...")
            return 1
        if not copy_seed_files(config.argument_values['work_dir'], config.argument_values['seed_dir']):
            print_fail("Seed directory is empty...")
            return 1
        config.save_data()
    else:
        log_core("Old state exist -> loading...")
        config.load_data()

    comm = Communicator(num_processes=num_processes, tasks_per_requests=config.argument_values['t'], bitmap_size=config.config_values["BITMAP_SHM_SIZE"])
    comm.create_shm()

    master = MasterProcess(comm)

    update_process = multiprocessing.Process(name='UPDATE', target=update_loader, args=(comm, ))
    mapserver_process = multiprocessing.Process(name='MAPSERVER', target=mapserver_loader, args=(comm, ))

    slaves = []
    for i in range(num_processes):
        slaves.append(multiprocessing.Process(name='SLAVE' + str(i), target=slave_loader, args=(comm, i, )))
        slaves[i].start()

    update_process.start()
    mapserver_process.start()

    try:
        master.loop()
    except KeyboardInterrupt:
        master.save_data()
        log_core("Date saved!")

    signal.signal( signal.SIGINT, signal.SIG_IGN)
    
    counter = 0
    print_pre_exit_msg(counter, clrscr=True)
    for slave in slaves:
        while True:
            counter += 1
            print_pre_exit_msg(counter)
            slave.join(timeout=0.25)
            if not slave.is_alive():
                break
    print_exit_msg()
    return 0
