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

from fuzzer.technique.helper import interesting_8_Bit, interesting_16_Bit, interesting_32_Bit

class DeterministicInputTest(unittest.TestCase):

	MAX_ITERATIONS = 20

	def generate_test_mutations_arithmetic(self):
		self.TEST_MUTATIONS = []
		for i in range(len(self.TEST_INPUT)):
			value = ""
			while True:
				value = self.TEST_INPUT[:i] + random.choice(string.printable) + self.TEST_INPUT[i+1:]
				if value != self.TEST_INPUT:
					break
			self.TEST_MUTATIONS.append(value)
			self.TEST_MUTATION_CHECK.append(False)

	def generate_test_mutations_seq_arithmetic(self, offset):
		self.TEST_MUTATIONS = []
		for i in range(len(self.TEST_INPUT)):
			self.TEST_MUTATIONS.append(self.TEST_INPUT[:i] + chr(in_range_8(ord(self.TEST_INPUT[i])+offset)) + self.TEST_INPUT[i+1:])
			self.TEST_MUTATION_CHECK.append(False)

	def generate_test_mutations_seq_arithmetic_16(self, offset):
		self.TEST_MUTATIONS = []
		for i in range(len(self.TEST_INPUT)-1):
			if random.choice([True, False]):
				self.TEST_MUTATIONS.append(self.TEST_INPUT[:i] + to_string_16(in_range_16(((ord(self.TEST_INPUT[i])<< 8)+ord(self.TEST_INPUT[i+1])+offset))) + self.TEST_INPUT[i+2:])
			else:
				self.TEST_MUTATIONS.append(self.TEST_INPUT[:i] + to_string_16(in_range_16(((ord(self.TEST_INPUT[i+1])<< 8)+ord(self.TEST_INPUT[i])+offset))) + self.TEST_INPUT[i+2:])
			self.TEST_MUTATION_CHECK.append(False)

	def generate_test_mutations_seq_arithmetic_32(self, offset):
		self.TEST_MUTATIONS = []
		for i in range(len(self.TEST_INPUT)-3):
			if random.choice([True, False]):
				self.TEST_MUTATIONS.append(self.TEST_INPUT[:i] + \
					to_string_32(in_range_32(\
						((ord(self.TEST_INPUT[i]) << 24) + \
						(ord(self.TEST_INPUT[i+1]) << 16) + \
						(ord(self.TEST_INPUT[i+2]) << 8) +  \
						ord(self.TEST_INPUT[i+3])+offset))) + \
					self.TEST_INPUT[i+4:])
			else:
				self.TEST_MUTATIONS.append(self.TEST_INPUT[:i] + \
					to_string_32(in_range_32(\
						((ord(self.TEST_INPUT[i+3]) << 24) + \
						(ord(self.TEST_INPUT[i+2]) << 16) + \
						(ord(self.TEST_INPUT[i+1]) << 8) +  \
						ord(self.TEST_INPUT[i])+offset))) + \
					self.TEST_INPUT[i+4:])
			self.TEST_MUTATION_CHECK.append(False)

	def generate_test_mutations_seq_interesting8(self):
		self.TEST_MUTATIONS = []
		for i in range(len(self.TEST_INPUT)):
			value = chr(random.choice(interesting_8_Bit))
			self.TEST_MUTATIONS.append(self.TEST_INPUT[:i] + value + self.TEST_INPUT[i+1:])
			self.TEST_MUTATION_CHECK.append(False)

	def generate_test_mutations_seq_interesting16(self):
		self.TEST_MUTATIONS = []
		for i in range(len(self.TEST_INPUT)-1):
			value = random.choice(interesting_16_Bit)
			if random.choice([True, False]):
				value = swap_16(value)
			self.TEST_MUTATIONS.append(self.TEST_INPUT[:i] + bytes_to_str_16(value) + self.TEST_INPUT[i+2:])
			self.TEST_MUTATION_CHECK.append(False)

	def generate_test_mutations_seq_interesting32(self):
		self.TEST_MUTATIONS = []
		for i in range(len(self.TEST_INPUT)-3):
			value = bytes_to_str_32(random.choice(interesting_32_Bit))
			self.TEST_MUTATIONS.append(self.TEST_INPUT[:i] + value + self.TEST_INPUT[i+4:])
			self.TEST_MUTATION_CHECK.append(False)

	def func_check(self, payload, no_data=False, affected_bytes=None):
		if not no_data:
			if payload in self.TEST_MUTATIONS:
				self.TEST_MUTATION_CHECK[self.TEST_MUTATIONS.index(payload)] = True

	def test_simple_arithmetic_input_generation(self):
		for i in range(self.MAX_ITERATIONS):
			self.TEST_INPUT = ''.join(random.choice(string.printable + '\x00') for i in range(i))
			self.TEST_MUTATIONS = []
			self.TEST_MUTATION_CHECK = []
			self.generate_test_mutations_arithmetic()

			self.func_check(self.TEST_INPUT)
			mutate_seq_walking_bits_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			mutate_seq_two_walking_bits_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			mutate_seq_four_walking_bits_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			mutate_seq_walking_byte_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			mutate_seq_two_walking_bytes_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None)
			mutate_seq_four_walking_bytes_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None)

			mutate_seq_8_bit_arithmetic_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None, set_arith_max=127)
			mutate_seq_16_bit_arithmetic_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None, set_arith_max=127)
			mutate_seq_32_bit_arithmetic_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None, set_arith_max=127)

			for i in range(len(self.TEST_MUTATION_CHECK)):
				self.assertTrue(self.TEST_MUTATION_CHECK[i])

	def test_seq_arithmetic_input_generation(self):
		for i in range(1, self.MAX_ITERATIONS+1):
			self.TEST_INPUT = ''.join(random.choice(string.printable + '\x00') for i in range(i))
			self.TEST_MUTATIONS = []
			self.TEST_MUTATION_CHECK = []
			self.generate_test_mutations_seq_arithmetic(i%127)

			self.func_check(self.TEST_INPUT)
			mutate_seq_walking_bits_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			mutate_seq_two_walking_bits_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			mutate_seq_four_walking_bits_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			mutate_seq_walking_byte_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			mutate_seq_two_walking_bytes_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None)
			mutate_seq_four_walking_bytes_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None)

			mutate_seq_8_bit_arithmetic_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None, set_arith_max=(i+1)%127)
			mutate_seq_16_bit_arithmetic_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None, set_arith_max=(i+1)%127)
			mutate_seq_32_bit_arithmetic_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None, set_arith_max=(i+1)%127)

			for i in range(len(self.TEST_MUTATION_CHECK)):
				if(not self.TEST_MUTATION_CHECK[i]):
					print(str(array('B', self.TEST_INPUT)) + " - " + str(array('B', self.TEST_MUTATIONS[i])))
				self.assertTrue(self.TEST_MUTATION_CHECK[i])

	def test_simple_interesting8_input_generation(self):
		for i in range(self.MAX_ITERATIONS):
			self.TEST_INPUT = ''.join(random.choice(string.printable + '\x00') for i in range(i))
			self.TEST_MUTATIONS = []
			self.TEST_MUTATION_CHECK = []
			self.generate_test_mutations_seq_interesting8()

			self.func_check(self.TEST_INPUT)

			mutate_seq_walking_bits_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			mutate_seq_two_walking_bits_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			mutate_seq_four_walking_bits_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			mutate_seq_walking_byte_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			mutate_seq_two_walking_bytes_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None)
			mutate_seq_four_walking_bytes_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None)

			mutate_seq_8_bit_arithmetic_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			mutate_seq_16_bit_arithmetic_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			mutate_seq_32_bit_arithmetic_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)

			mutate_seq_8_bit_interesting_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			#mutate_seq_16_bit_interesting_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			#mutate_seq_32_bit_interesting_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)

			for i in range(len(self.TEST_MUTATION_CHECK)):
				if(not self.TEST_MUTATION_CHECK[i]):
					print(str(array('B', self.TEST_INPUT)) + " - " + str(array('B', self.TEST_MUTATIONS[i])))
				self.assertTrue(self.TEST_MUTATION_CHECK[i])

	def test_simple_interesting16_input_generation(self):
		for i in range(self.MAX_ITERATIONS):
			self.TEST_INPUT = ''.join(random.choice(string.printable + '\x00') for i in range(i))
			self.TEST_MUTATIONS = []
			self.TEST_MUTATION_CHECK = []
			self.generate_test_mutations_seq_interesting16()

			self.func_check(self.TEST_INPUT)
			mutate_seq_walking_bits_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			mutate_seq_two_walking_bits_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			mutate_seq_four_walking_bits_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			mutate_seq_walking_byte_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			mutate_seq_two_walking_bytes_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None)
			mutate_seq_four_walking_bytes_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None)

			mutate_seq_8_bit_arithmetic_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			mutate_seq_16_bit_arithmetic_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			mutate_seq_32_bit_arithmetic_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)

			mutate_seq_8_bit_interesting_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)			
			mutate_seq_16_bit_interesting_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			#mutate_seq_32_bit_interesting_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)

			for i in range(len(self.TEST_MUTATION_CHECK)):
				if(not self.TEST_MUTATION_CHECK[i]):
					print(str(array('B', self.TEST_INPUT)) + " - " + str(array('B', self.TEST_MUTATIONS[i])))
				#print(str(self.TEST_MUTATION_CHECK[i]) + " : " + str(array('B', self.TEST_INPUT)) + " : " + str(array('B', self.TEST_MUTATIONS[i])))
				self.assertTrue(self.TEST_MUTATION_CHECK[i])

	def test_simple_interesting32_input_generation(self):
		for i in range(self.MAX_ITERATIONS):
			self.TEST_INPUT = ''.join(random.choice(string.printable + '\x00') for i in range(i))
			self.TEST_MUTATIONS = []
			self.TEST_MUTATION_CHECK = []
			self.generate_test_mutations_seq_interesting32()

			self.func_check(self.TEST_INPUT)
			mutate_seq_walking_bits_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			mutate_seq_two_walking_bits_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			mutate_seq_four_walking_bits_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			mutate_seq_walking_byte_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			mutate_seq_two_walking_bytes_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None)
			mutate_seq_four_walking_bytes_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None)

			mutate_seq_8_bit_arithmetic_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			mutate_seq_16_bit_arithmetic_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			mutate_seq_32_bit_arithmetic_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)

			mutate_seq_8_bit_interesting_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)			
			mutate_seq_16_bit_interesting_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)
			mutate_seq_32_bit_interesting_array(array('B', self.TEST_INPUT), self.func_check, effector_map=None, skip_null=None)

			for i in range(len(self.TEST_MUTATION_CHECK)):
				self.assertTrue(self.TEST_MUTATION_CHECK[i])

	def test_is_not_arithmetic_8(self):
		for i in range(self.MAX_ITERATIONS):
			self.TEST_INPUT = ''.join(random.choice(string.printable + '\x00') for i in range(i)) 
			self.TEST_MUTATIONS = []
			self.TEST_MUTATION_CHECK = []
			self.generate_test_mutations_seq_arithmetic(i%127)
			for j in range(len(self.TEST_INPUT)):
				self.assertFalse(is_not_arithmetic(ord(self.TEST_INPUT[j]), ord(self.TEST_MUTATIONS[j][j]), 1, set_arith_max=(i+1)%127))

	def test_is_not_arithmetic_16(self):
		for i in range(self.MAX_ITERATIONS):
			self.TEST_INPUT = ''.join(random.choice(string.printable + '\x00') for i in range(i)) 
			self.TEST_MUTATIONS = []
			self.TEST_MUTATION_CHECK = []
			self.generate_test_mutations_seq_arithmetic_16(i%127)
			for j in range(len(self.TEST_INPUT)-1):
				value1 = (ord(self.TEST_INPUT[j]) << 8) + ord(self.TEST_INPUT[j+1])
				value2 = (ord(self.TEST_MUTATIONS[j][j]) << 8) + ord(self.TEST_MUTATIONS[j][j+1])
				swapped_value = swap_16(value2)

				v1 = is_not_arithmetic(value1, value2, 2, set_arith_max=(i+1)%127)
				v2 = is_not_arithmetic(value1, swapped_value, 2, set_arith_max=(i+1)%127)
				self.assertFalse(v1 and v2)

	def test_is_not_arithmetic_32(self):
		for i in range(self.MAX_ITERATIONS):
			self.TEST_INPUT = ''.join(random.choice(string.printable + '\x00') for i in range(i)) 
			self.TEST_MUTATIONS = []
			self.TEST_MUTATION_CHECK = []
			self.generate_test_mutations_seq_arithmetic_32(i%127)
			for j in range(0, len(self.TEST_INPUT)-3):
				value1 = (ord(self.TEST_INPUT[j]) << 24) + \
				(ord(self.TEST_INPUT[j+1]) << 16) + \
				(ord(self.TEST_INPUT[j+2]) << 8) + \
				ord(self.TEST_INPUT[j+3])

				value2 = (ord(self.TEST_MUTATIONS[j][j]) << 24) + \
				(ord(self.TEST_MUTATIONS[j][j+1]) << 16) + \
				(ord(self.TEST_MUTATIONS[j][j+2]) << 8) + \
				 ord(self.TEST_MUTATIONS[j][j+3])
				swapped_value = swap_32(value2)

				v1 = is_not_arithmetic(value1, value2, 4)
				v2 = is_not_arithmetic(value1, swapped_value, 4)
				self.assertFalse(v1 and v2)
	
	def test_is_not_interesting_8(self):
		for i in range(self.MAX_ITERATIONS):
			self.TEST_INPUT = ''.join(random.choice(string.printable + '\x00') for i in range(i)) 
			self.TEST_MUTATIONS = []
			self.TEST_MUTATION_CHECK = []
			self.generate_test_mutations_seq_interesting8()
			for j in range(len(self.TEST_INPUT)):
				v1 = is_not_interesting(ord(self.TEST_INPUT[j]), ord(self.TEST_MUTATIONS[j][j]), 1, False)
				self.assertFalse(v1 and v2)

	def test_is_not_interesting_16(self):
		for i in range(self.MAX_ITERATIONS):
			self.TEST_INPUT = ''.join(random.choice(string.printable + '\x00') for i in range(i)) 
			self.TEST_MUTATIONS = []
			self.TEST_MUTATION_CHECK = []
			self.generate_test_mutations_seq_interesting16()
			for j in range(len(self.TEST_INPUT)-1):
				value1 = (ord(self.TEST_INPUT[j]) << 8) + ord(self.TEST_INPUT[j+1])
				value2 = (ord(self.TEST_MUTATIONS[j][j]) << 8) + ord(self.TEST_MUTATIONS[j][j+1])
				swapped_value = swap_16(value2)

				v1 = is_not_interesting(value1, value2, 2, True)
				v2 = is_not_interesting(value1, swapped_value, 2, False)
				self.assertFalse(v1 and v2)

	def test_is_not_interesting_32(self):
		for i in range(self.MAX_ITERATIONS):
			self.TEST_INPUT = ''.join(random.choice(string.printable + '\x00') for i in range(i)) 
			self.TEST_MUTATIONS = []
			self.TEST_MUTATION_CHECK = []
			self.generate_test_mutations_seq_interesting32()
			for j in range(len(self.TEST_INPUT)-3):
				value1 = (ord(self.TEST_INPUT[j]) << 24) + \
				(ord(self.TEST_INPUT[j+1]) << 16) + \
				(ord(self.TEST_INPUT[j+2]) << 8) + \
				ord(self.TEST_INPUT[j+3])

				value2 = (ord(self.TEST_MUTATIONS[j][j]) << 24) + \
				(ord(self.TEST_MUTATIONS[j][j+1]) << 16) + \
				(ord(self.TEST_MUTATIONS[j][j+2]) << 8) + \
				 ord(self.TEST_MUTATIONS[j][j+3])
				self.assertFalse(is_not_interesting(value1, value2, 4, True))
	
