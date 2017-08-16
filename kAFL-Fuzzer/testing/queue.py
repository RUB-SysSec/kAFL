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

import unittest, os
from common.config import FuzzerConfiguration
from fuzzer.tree import KaflTree
from common.util import prepare_working_dir
import time

from subprocess import Popen


class QueueTest(unittest.TestCase):

	def test_simple(self):
		args = dict()
		args['ram_file'] = "/tmp/kafl_unittest_ram_file"
		args['overlay_dir'] = "/tmp/kafl_unittest_overlay_dir/"
		args['executable'] = "/tmp/kafl_unittest_exec_file"
		args['work_dir'] = "/tmp/kafl_unittest_work_dir/"
		args['mem'] = 300
		args['ip_filter'] = (0x0000,0xffff)
		FuzzerConfiguration(emulated_arguments=args)

		if not os.path.isdir(args['work_dir']):
			os.makedirs(args['work_dir'])
		prepare_working_dir(args['work_dir'], purge=True)

		seed = \
			[ \
			["ABC", [chr(0), chr(1), chr(1)]], \
			["DEF", [chr(0), chr(1), chr(0)]] \
			]
		
		kt = KaflTree(seed, enable_graphviz=True)
		kt.draw()
		p = Popen("xdot /tmp/kafl_unittest_work_dir/graph.dot".split(" "))
		time.sleep(2)
		for i in range(10):
			print(kt.get_next(100))
			kt.draw()
			time.sleep(1)
		p.terminate()
		self.assertTrue(True)

