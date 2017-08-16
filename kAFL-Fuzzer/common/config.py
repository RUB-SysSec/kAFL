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

import ConfigParser
import json
import os
import re
import sys

import argparse

from common.util import is_float, is_int, json_dumper, Singleton

class ArgsParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_help()
        print('\033[91m[Error] %s\n\n\033[0m\n' % message)
        sys.exit(1)

def create_dir(dirname):
    if not os.path.isdir(dirname):
        try:
            os.makedirs(dirname)
        except:
            msg = "Cannot create directory: {0}".format(dirname)
            raise argparse.ArgumentTypeError(msg)
    return dirname

def parse_is_dir(dirname):
    if not os.path.isdir(dirname):
        msg = "{0} is not a directory".format(dirname)
        raise argparse.ArgumentTypeError(msg)
    else:
        return dirname

def parse_is_file(dirname):
    if not os.path.isfile(dirname):
        msg = "{0} is not a file".format(dirname)
        raise argparse.ArgumentTypeError(msg)
    else:
        return dirname

def parse_ignore_range(string):
    m = re.match(r"(\d+)(?:-(\d+))?$", string)
    if not m:
        raise argparse.ArgumentTypeError("'" + string + "' is not a range of number.")
    start = min(int(m.group(1)), int(m.group(2)))
    end = max(int(m.group(1)), int(m.group(2))) or start
    if end > (128 << 10):
        raise argparse.ArgumentTypeError("Value out of range (max 128KB).")

    if start == 0 and end == (128 << 10):
        raise argparse.ArgumentTypeError("Invalid range specified.")
    return list([start, end])


def parse_range_ip_filter(string):
    m = re.match(r"([(0-9abcdef]{1,16})(?:-([0-9abcdef]{1,16}))?$", string.replace("0x", "").lower())
    if not m:
        raise argparse.ArgumentTypeError("'" + string + "' is not a range of number.")

    #print(m.group(1))
    #print(m.group(2))
    start = min(int(m.group(1).replace("0x", ""), 16), int(m.group(2).replace("0x", ""), 16))
    end = max(int(m.group(1).replace("0x", ""), 16), int(m.group(2).replace("0x", ""), 16)) or start

    if start > end:
        raise argparse.ArgumentTypeError("Invalid range specified.")
    return list([start, end])


class FullPaths(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, os.path.abspath(os.path.expanduser(values)))


class ConfigReader(object):

    def __init__(self, config_file, section, default_values):
        self.section = section
        self.default_values = default_values
        self.config = ConfigParser.ConfigParser()
        self.config.read(config_file)
        self.config_value = {}
        self.__set_config_values()

    def __set_config_values(self):
        for default_value in self.default_values.keys():
            if self.config.has_option(self.section, default_value):
                try:
                    self.config_value[default_value] = int(self.config.get(self.section, default_value))
                except ValueError:
                    if self.config.get(self.section, default_value) == "True":
                        self.config_value[default_value] = True
                    elif self.config.get(self.section, default_value) == "False":
                        self.config_value[default_value] = False
                    elif self.config.get(self.section, default_value).startswith("[") and \
                            self.config.get(self.section, default_value).endswith("]"):
                        self.config_value[default_value] = \
                            self.config.get(self.section, default_value)[1:-1].replace(' ', '').split(',')
                    elif self.config.get(self.section, default_value).startswith("{") and \
                            self.config.get(self.section, default_value).endswith("}"):
                        self.config_value[default_value] = json.loads(self.config.get(self.section, default_value))
                    else:
                        if is_float(self.config.get(self.section, default_value)):
                            self.config_value[default_value] = float(self.config.get(self.section, default_value))
                        elif is_int(self.config.get(self.section, default_value)):
                            self.config_value[default_value] = int(self.config.get(self.section, default_value))
                        else:
                            self.config_value[default_value] = self.config.get(self.section, default_value)
            else:
                self.config_value[default_value] = self.default_values[default_value]

    def get_values(self):
        return self.config_value

class InfoConfiguration:
    __metaclass__ = Singleton

    __config_section = "Fuzzer"
    __config_default = {"UI_REFRESH_RATE": 0.25,
                      "MASTER_SHM_PREFIX": "kafl_master_",
                      "MAPSERV_SHM_PREFIX": "kafl_mapserver_",
                      "BITMAP_SHM_PREFIX": "kafl_bitmap_",
                      "PAYLOAD_SHM_SIZE": (65 << 10),
                      "BITMAP_SHM_SIZE": (64 << 10),
                      "QEMU_KAFL_LOCATION": None,
                      "ABORTION_TRESHOLD": 50,
                      "TIMEOUT_TICK_FACTOR": 10.0,
                      "APPLE-SMC-OSK": "",
                        }

    def __init__(self, initial=True):
        if initial:
            self.argument_values = None
            self.config_values = None
            self.__load_arguments()
            self.__load_config()
            self.load_old_state = False


    def __load_config(self):
        self.config_values = ConfigReader("kafl.ini", self.__config_section, self.__config_default).get_values()

    def __load_arguments(self):
        parser = ArgsParser(formatter_class=argparse.RawTextHelpFormatter)

        parser.add_argument('ram_file', metavar='<RAM File>', action=FullPaths, type=parse_is_file,
                            help='path to the RAM file.')
        parser.add_argument('overlay_dir', metavar='<Overlay Directory>', action=FullPaths, type=parse_is_dir,
                            help='path to the overlay directory.')
        parser.add_argument('executable', metavar='<Info Executable>', action=FullPaths, type=parse_is_file,
                            help='path to the info executable (kernel address dumper).')
        parser.add_argument('mem', metavar='<RAM Size>', help='size of virtual RAM (default: 300).', default=300, type=int)

        parser.add_argument('-v', required=False, help='enable verbose mode (./debug.log).', action='store_true',
                            default=False)
        parser.add_argument('-S', required=False, metavar='Snapshot', help='specifiy snapshot title (default: kafl).', default="kafl", type=str)
        parser.add_argument('-macOS', required=False, help='enable macOS Support (requires Apple OSK)', action='store_true', default=False)

        self.argument_values = vars(parser.parse_args())

class FuzzerConfiguration:
    __metaclass__ = Singleton

    __config_section = "Fuzzer"
    __config_default = {"UI_REFRESH_RATE": 0.25,
                      "MASTER_SHM_PREFIX": "kafl_master_",
                      "MAPSERV_SHM_PREFIX": "kafl_mapserver_",
                      "BITMAP_SHM_PREFIX": "kafl_bitmap_",
                      "PAYLOAD_SHM_SIZE": (65 << 10),
                      "BITMAP_SHM_SIZE": (64 << 10),
                      "QEMU_KAFL_LOCATION": None,
                      "ABORTION_TRESHOLD": 50,
                      "TIMEOUT_TICK_FACTOR": 10.0,
                      "ARITHMETIC_MAX": 35,
                      "APPLE-SMC-OSK": "",
                        }

    def __init__(self, emulated_arguments=None):
        if not emulated_arguments:
            self.argument_values = None
            self.config_values = None
            self.__load_arguments()
            self.__load_config()
            self.load_old_state = False
        else:
            self.argument_values = emulated_arguments
            self.__load_config()
            self.load_old_state = False

        #print(self.argument_values)

    def __load_config(self):
        self.config_values = ConfigReader("kafl.ini", self.__config_section, self.__config_default).get_values()

    def __load_arguments(self):
        parser = ArgsParser(formatter_class=argparse.RawTextHelpFormatter)
        parser.add_argument('ram_file', metavar='<RAM File>', action=FullPaths, type=parse_is_file,
                            help='Path to the RAM file.')
        parser.add_argument('overlay_dir', metavar='<Overlay Directory>', action=FullPaths, type=parse_is_dir,
                            help='Path to the overlay directory.')
        parser.add_argument('executable', metavar='<Fuzzer Executable>', action=FullPaths, type=parse_is_file,
                            help='Path to the fuzzer executable.')
        parser.add_argument('mem', metavar='<RAM Size>', help='Size of virtual RAM (default: 300).', default=300, type=int)
        parser.add_argument('seed_dir', metavar='<Seed Directory>', action=FullPaths, type=parse_is_dir,
                            help='Path to the seed directory.')
        parser.add_argument('work_dir', metavar='<Working Directory>', action=FullPaths, type=create_dir,
                            help='Path to the working directory.')
        #parser.add_argument('ip_filter', metavar='<IP-Filter>', type=parse_range_ip_filter,
        #                    help='Instruction pointer filter range.')

        parser.add_argument('-ip0', required=True, metavar='<IP-Filter 0>', type=parse_range_ip_filter, help='instruction pointer filter range 0')
        parser.add_argument('-ip1', required=False, metavar='<IP-Filter 1>', type=parse_range_ip_filter, help='instruction pointer filter range 1 (not supported in this version)')
        parser.add_argument('-ip2', required=False, metavar='<IP-Filter 2>', type=parse_range_ip_filter, help='instruction pointer filter range 2 (not supported in this version)')
        parser.add_argument('-ip3', required=False, metavar='<IP-Filter 3>', type=parse_range_ip_filter, help='instruction pointer filter range 3 (not supported in this version)')


        parser.add_argument('-p', required=False, metavar='<Process Number>', help='number of worker processes to start.', default=1, type=int)
        parser.add_argument('-t', required=False, metavar='<Task Number>', help='tasks per worker request to provide.', default=1, type=int)
        parser.add_argument('-v', required=False, help='enable verbose mode (./debug.log).', action='store_true',
                            default=False)
        parser.add_argument('-g', required=False, help='disable GraphViz drawing.', action='store_false', default=True)
        parser.add_argument('-s', required=False, help='skip zero bytes during deterministic fuzzing stages.',
                            action='store_true', default=False)
        parser.add_argument('-b', required=False, help='enable usage of ringbuffer for findings.',
                            action='store_true', default=False)
        parser.add_argument('-d', required=False, help='disable usage of AFL-like effector maps.',
                            action='store_false', default=True)
        parser.add_argument('--Purge', required=False, help='purge the working directory.', action='store_true',
                            default=False)
        parser.add_argument('-i', required=False, type=parse_ignore_range, metavar="[0-131072]",
                            help='range of bytes to skip during deterministic fuzzing stages (0-128KB).',
                            action='append')
        parser.add_argument('-e', required=False, help='disable evaluation mode.', action='store_false', default=True)
        parser.add_argument('-S', required=False, metavar='Snapshot', help='specifiy snapshot title (default: kafl).', default="kafl", type=str)
        parser.add_argument('-D', required=False, help='skip deterministic stages (dumb mode).',action='store_false', default=True)
        parser.add_argument('-I', required=False, metavar='<Dict-File>', help='import dictionary to fuzz.', default=None, type=parse_is_file)
        parser.add_argument('-macOS', required=False, help='enable macOS Support (requires Apple OSK)', action='store_true', default=False)
        parser.add_argument('-f', required=False, help='disable fancy UI', action='store_false', default=True)
        parser.add_argument('-n', required=False, help='disable filter sampling', action='store_false', default=True)
        parser.add_argument('-l', required=False, help='enable UI log output', action='store_true', default=False)

        self.argument_values = vars(parser.parse_args())

    def save_data(self):
        """
        Method to store an entire config state to JSON file...
        """
        with open(self.argument_values['work_dir'] + "/config.json", 'w') as outfile:
            json.dump(self.__dict__, outfile, default=json_dumper)

    def load_data(self):
        """
        Method to load an entire config state from JSON file...
        """
        with open(self.argument_values['work_dir'] + "/config.json", 'r') as infile:
            dump = json.load(infile)
            for key, value in dump.iteritems():
                setattr(self, key, value)
        self.load_old_state = True
