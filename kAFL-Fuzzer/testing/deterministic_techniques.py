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

import unittest

from array import array
from fuzzer.technique.bitflip import *
from fuzzer.technique.arithmetic import *
from fuzzer.technique.interesting_values import *
import random, string

#from fuzzer.technique.helper import interesting_8_Bit, interesting_16_Bit, interesting_32_Bit

class DeterministicTechniquesTest(unittest.TestCase):
	counter = 0
	storage = []

	MAX_ITERATIONS = 5

	def generate_input(self, size):
		return ''.join(random.choice(string.printable + '\x00') for i in range(size))

	def generate_effector_map(self, length):
		eff_map = []
		for i in range(length):
			eff_map.append(random.choice([True, False]))
		return eff_map

	def func(self, payload, no_data=False, affected_bytes=None):
		#if not no_data:
		self.counter += 1

	def func_duplicate(self, payload, no_data=False, affected_bytes=None):
		#print(array('B', payload))
		if not no_data:
			self.assertNotIn(payload, self.storage)
			self.storage.append(payload)

	def bitflip_range(self, use_effector_map=False, skip_zero=False):
		for i in range(0, self.MAX_ITERATIONS):
			if use_effector_map:
				eff_map = effector_map=self.generate_effector_map(self.MAX_ITERATIONS)
			else:
				eff_map = None
			data = self.generate_input(i)
			value1 = bitflip_range(data, effector_map=eff_map, skip_null=skip_zero)

			self.counter = 0
			mutate_seq_walking_bits_array(array('B', data), self.func, effector_map=eff_map, skip_null=skip_zero)
			mutate_seq_two_walking_bits_array(array('B', data), self.func, effector_map=eff_map, skip_null=skip_zero)
			mutate_seq_four_walking_bits_array(array('B', data), self.func, effector_map=eff_map, skip_null=skip_zero)
			mutate_seq_walking_byte_array(array('B', data), self.func, effector_map=eff_map, skip_null=skip_zero)
			mutate_seq_two_walking_bytes_array(array('B', data), self.func, effector_map=eff_map)
			mutate_seq_four_walking_bytes_array(array('B', data), self.func, effector_map=eff_map)
			self.assertEqual(value1, self.counter)

	def bitflip_range_8bit(self, use_effector_map=False, skip_zero=False):
		for i in range(0, self.MAX_ITERATIONS):
			if use_effector_map:
				eff_map = effector_map=self.generate_effector_map(self.MAX_ITERATIONS)
			else:
				eff_map = None
			data = self.generate_input(i)
			value1 = bitflip8_range(data, effector_map=eff_map, skip_null=skip_zero)

			self.counter = 0
			mutate_seq_walking_bits_array(array('B', data), self.func, effector_map=eff_map, skip_null=skip_zero)
			self.assertEqual(value1, self.counter)

	def bitflip_duplicate(self, use_effector_map=False, skip_zero=False):
		for i in range(0, self.MAX_ITERATIONS):
			self.storage = []
			if use_effector_map:
				eff_map = effector_map=self.generate_effector_map(self.MAX_ITERATIONS)
			else:
				eff_map = None
			data = self.generate_input(i)
			mutate_seq_walking_bits_array(array('B', data), self.func_duplicate, effector_map=eff_map, skip_null=skip_zero)
        	mutate_seq_two_walking_bits_array(array('B', data), self.func_duplicate, effector_map=eff_map, skip_null=skip_zero)
        	mutate_seq_four_walking_bits_array(array('B', data), self.func_duplicate, effector_map=eff_map, skip_null=skip_zero)
        	mutate_seq_walking_byte_array(array('B', data), self.func_duplicate, effector_map=eff_map, skip_null=skip_zero)
        	mutate_seq_two_walking_bytes_array(array('B', data), self.func_duplicate, effector_map=eff_map)
        	mutate_seq_four_walking_bytes_array(array('B', data), self.func_duplicate, effector_map=eff_map)
	
	def artihmetic_range(self, use_effector_map=False, skip_zero=False):
		for i in range(0, self.MAX_ITERATIONS):
			if use_effector_map:
				eff_map = effector_map=self.generate_effector_map(self.MAX_ITERATIONS)
			else:
				eff_map = None
			data = self.generate_input(i)
			value1 = arithmetic_range(data, effector_map=eff_map, skip_null=skip_zero)

			#print(array('B', data))
			self.counter = 0
			mutate_seq_8_bit_arithmetic_array(array('B', data), self.func, effector_map=eff_map, skip_null=skip_zero)
			mutate_seq_16_bit_arithmetic_array(array('B', data), self.func, effector_map=eff_map, skip_null=skip_zero)
			mutate_seq_32_bit_arithmetic_array(array('B', data), self.func, effector_map=eff_map, skip_null=skip_zero)
			self.assertEqual(value1, self.counter)

	def arithmetic_duplicate(self, use_effector_map=False, skip_zero=False):
		for i in range(0, self.MAX_ITERATIONS):
			if use_effector_map:
				eff_map = effector_map=self.generate_effector_map(self.MAX_ITERATIONS)
			else:
				eff_map = None
			data = self.generate_input(i)

			self.storage = []
			mutate_seq_8_bit_arithmetic_array(array('B', data), self.func_duplicate, effector_map=eff_map, skip_null=skip_zero)
			self.storage = []
			mutate_seq_16_bit_arithmetic_array(array('B', data), self.func_duplicate, effector_map=eff_map, skip_null=skip_zero)
			self.storage = []
			mutate_seq_32_bit_arithmetic_array(array('B', data), self.func_duplicate, effector_map=eff_map, skip_null=skip_zero)


	def interesting_range(self, use_effector_map=False, skip_zero=False):
		for i in range(0, self.MAX_ITERATIONS):
			if use_effector_map:
				eff_map = effector_map=self.generate_effector_map(self.MAX_ITERATIONS)
			else:
				eff_map = None
			data = self.generate_input(i)
			value1 = interesting_range(data, effector_map=eff_map, skip_null=skip_zero)

			self.counter = 0
			mutate_seq_8_bit_interesting_array(array('B', data), self.func, effector_map=eff_map, skip_null=skip_zero)
			mutate_seq_16_bit_interesting_array(array('B', data), self.func, effector_map=eff_map, skip_null=skip_zero)
			mutate_seq_32_bit_interesting_array(array('B', data), self.func, effector_map=eff_map, skip_null=skip_zero)
			self.assertEqual(value1, self.counter)

	def interesting_duplicate(self, use_effector_map=False, skip_zero=False):
		for i in range(0, self.MAX_ITERATIONS):
			self.storage = []
			if use_effector_map:
				eff_map = effector_map=self.generate_effector_map(self.MAX_ITERATIONS)
			else:
				eff_map = None
			data = self.generate_input(i)
			mutate_seq_8_bit_interesting_array(array('B', data), self.func_duplicate, effector_map=eff_map, skip_null=skip_zero)
			mutate_seq_16_bit_interesting_array(array('B', data), self.func_duplicate, effector_map=eff_map, skip_null=skip_zero)
			mutate_seq_32_bit_interesting_array(array('B', data), self.func_duplicate, effector_map=eff_map, skip_null=skip_zero)

	def test_bitflip_range(self):
		self.bitflip_range()

	def test_bitflip_range_eff(self):
		self.bitflip_range(use_effector_map=True)

	def test_bitflip_range_skip_zero(self):
		self.bitflip_range(skip_zero=True)

	def test_bitflip_range_eff_and_skip_zero(self):
		self.bitflip_range(use_effector_map=True, skip_zero=True)

	def test_bitflip_range_8bit(self):
		self.bitflip_range_8bit()
	
	def test_bitflip_range_8bit_eff(self):
		self.bitflip_range_8bit(use_effector_map=True)	
	
	def test_bitflip_range_8bit_skip_zero(self):
		self.bitflip_range_8bit(skip_zero=True)

	def test_bitflip_range_8bit_eff_and_skip_zero(self):
		self.bitflip_range_8bit(use_effector_map=True, skip_zero=True)
	
	def test_bitflip_duplicate(self):
		self.bitflip_duplicate()

	def test_bitflip_duplicate_eff(self):
		self.bitflip_duplicate(use_effector_map=True)	
	
	def test_bitflip_duplicate_skip_zero(self):
		self.bitflip_duplicate(skip_zero=True)

	def test_bitflip_duplicate_eff_and_skip_zero(self):
		self.bitflip_duplicate(use_effector_map=True, skip_zero=True)

	def test_artihmetic_range(self):
		self.artihmetic_range()

	def test_artihmetic_range_eff(self):
		self.artihmetic_range(use_effector_map=True)

	def test_artihmetic_range_skip_zero(self):
		self.artihmetic_range(skip_zero=True)

	def test_artihmetic_range_eff_and_skip_zero(self):
		self.artihmetic_range(use_effector_map=True, skip_zero=True)
	
	def test_arithmetic_duplicate(self):
		self.arithmetic_duplicate()

	def test_arithmetic_duplicate_eff(self):
		self.arithmetic_duplicate(use_effector_map=True)

	def test_arithmetic_duplicate_skip_zero(self):
		self.arithmetic_duplicate(skip_zero=True)

	def test_arithmetic_duplicate_eff_and_skip_zero(self):
		self.arithmetic_duplicate(use_effector_map=True, skip_zero=True)

	def test_interesting_range(self):
		self.artihmetic_range()

	def test_interesting_range_eff(self):
		self.artihmetic_range(use_effector_map=True)

	def test_interesting_range_skip_zero(self):
		self.artihmetic_range(skip_zero=True)
	
	def test_interesting_range_eff_and_skip_zero(self):
		self.artihmetic_range(use_effector_map=True, skip_zero=True)

	def test_interesting_duplicate(self):
		self.interesting_duplicate()

	def test_interesting_duplicate_eff(self):
		self.interesting_duplicate(use_effector_map=True)

	def test_interesting_duplicate_skip_zero(self):
		self.interesting_duplicate(skip_zero=True)

	def test_interesting_duplicate_eff_and_skip_zero(self):
		self.interesting_duplicate(use_effector_map=True, skip_zero=True)
