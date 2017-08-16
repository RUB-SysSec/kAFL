#!/usr/bin/env python

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
from common.self_check import self_check

__author__ = 'sergej'


def main():
    f = open("help.txt")
    for line in f:
        print(line.replace("\n", ""))
    f.close()

    print("<< " + '\033[1m' + '\033[92m' + sys.argv[0] + ": Kernel Fuzzer " + '\033[0m' + ">>\n")

    if not self_check():
        return 1

    from fuzzer.core import start
    return start()


if __name__ == "__main__":
    main()
