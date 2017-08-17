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
from shutil import copyfile
from common.debug import logger
import sys, tty, termios, time, os

__author__ = 'Sergej Schumilo'

class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

def atomic_write(filename, data):
    f = open("/tmp/kafl.tmp", 'wb')
    f.write(data)
    f.flush()
    os.fsync(f.fileno())
    f.close()
    os.rename("/tmp/kafl.tmp", filename)


def read_binary_file(filename):
    payload = ""
    f = open(filename, 'rb')
    while True:
        buf = f.read(1024)
        if len(buf) == 0:
            break
        payload += buf

    f.close()
    return payload


def find_diffs(data_a, data_b):
    first_diff = 0
    last_diff = 0
    for i in range(min(len(data_a), len(data_b))):
        if data_a[i] != data_b:
            if first_diff == 0:
                first_diff = i
            last_diff = i
    return first_diff, last_diff


def prepare_working_dir(directory_path, purge=False):
    folders = ["/findings/", "/corpus", "/findings/panic", "/findings/kasan", "/findings/timeout", "/rbuf", "/evaluation"]

    if purge:
        if os.path.isdir(directory_path):
            for root, dirs, files in os.walk(directory_path, topdown=False):
                for name in files:
                    os.remove(os.path.join(root, name))
                for name in dirs:
                    os.rmdir(os.path.join(root, name))
        if os.path.exists("/dev/shm/kafl_filter0"):
            os.remove("/dev/shm/kafl_filter0")
        if os.path.exists("/dev/shm/kafl_tfilter"):
            os.remove("/dev/shm/kafl_tfilter")

    if len(os.listdir(directory_path)) == 0:
        for folder in folders:
            os.makedirs(directory_path + folder)
    else:
        for folder in folders:
            if not os.path.isdir(directory_path + folder):
                return False
    return True


def check_if_old_state_exits(working_directory):

    if not os.path.exists(working_directory):
        logger("[MISC]\t\tError 1 (workdir does not exist)...")
        return False

    if len(os.listdir(working_directory)) == 0:
        logger("[MISC]\t\tError 2 (workdir is empty)...")
        return False

    if not os.path.exists(working_directory + "/config.json"):
        logger("[MISC]\t\tError 3 (config.json does not exist)...")
        return False

    if not os.path.exists(working_directory + "/tree.json"):
        logger("[MISC]\t\tError 4 (tree.json does not exist)...")
        return False

    if not os.path.exists(working_directory + "/master.json"):
        logger("[MISC]\t\tError 5 (master.json does not exist)...")
        return False

    if not os.path.exists(working_directory + "/mapserver.json"):
        logger("[MISC]\t\tError 6 (mapserver.json does not exist)...")
        return False

    return True


def copy_seed_files(working_directory, seed_directory):
    if len(os.listdir(seed_directory)) == 0:
        return False

    if len(os.listdir(working_directory)) == 0:
        return True

    i = 0
    for (directory, _, files) in os.walk(seed_directory):
        for f in files:
            path = os.path.join(directory, f)
            if os.path.exists(path):
                copyfile(path, working_directory + "/corpus/" + "payload_" + str(i))
                i += 1

    return True


def get_seed_files(working_directory):
    data = []
    for (directory, _, files) in os.walk(working_directory):
        for f in files:
            path = os.path.join(directory, f)
            if os.path.exists(path):
                data.append(read_binary_file(path))
    return data


def check_state_exists(working_directory):
    return os.path.exists(working_directory + "/state.json")

def print_warning(msg):
    sys.stdout.write("\033[0;33m\033[1m[WARNING] " + msg + "\033[0m\n")
    sys.stdout.flush()

def print_fail(msg):
    sys.stdout.write("\033[91m\033[1m[FAIL] " + msg + "\033[0m\n")
    sys.stdout.flush()

def print_pre_exit_msg(num_dots, clrscr=False):
    dots = ""
    for i in range((num_dots%3)+1):
        dots += "."
    for i in range(3-len(dots)):
        dots += " "

    if clrscr:
        print('\x1b[2J')
    print('\x1b[1;1H' + '\x1b[1;1H' + '\033[0;33m' + "[*] Terminating Slaves" + dots + '\033[0m' + "\n")

def print_exit_msg():
    print('\x1b[2J' + '\x1b[1;1H' + '\033[92m' + "[!] Data saved! Bye!" + '\033[0m' + "\n")

def is_float(value):
    try:
        float(value)
        return True
    except ValueError:
        return False


def is_int(value):
    try:
        int(value)
        return True
    except ValueError:
        return False

def getch():
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch

def ask_for_purge(data):
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    print("Enter " + data + " to wipe old workspace:")
    i = 0
    print(len(data)*'_'),
    while True:
        input_char = getch()

        # Check for CTRL+C
        if input_char == chr(0x3):
            print("")
            return False

        # Check for matching character
        if(data[i] == input_char):
            i += 1
            print("\r" + FAIL + data[:i] + ENDC + (len(data)-i)*'_', end="")

        # Check if we are done here ...
        if i == len(data):
            break
    print("")
    return True


def json_dumper(obj):
    return obj.__dict__
