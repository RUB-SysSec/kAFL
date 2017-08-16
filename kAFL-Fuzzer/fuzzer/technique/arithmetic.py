from array import array
from fuzzer.technique.helper import *

__author__ = 'sergej'


def arithmetic_range(data, skip_null=False, effector_map=None, set_arith_max=None):
    if len(data) == 0:
        return 0

    if not set_arith_max:
        set_arith_max = AFL_ARITH_MAX

    data_len = len(data)
    num = 0

    if effector_map:
        byte_count = 0
        for i in range(len(data)):
            if effector_map[i]:
                byte_count += 1
                num += (set_arith_max*2)
                if byte_count >= 2:
                    num += ((set_arith_max-2)*4)
                if byte_count >= 4:
                    num += ((set_arith_max-2)*4)

            else:
                byte_count = 0
    else:
        num += (data_len*(set_arith_max*2))

        if data_len > 1:
                num += ((data_len-1)*((set_arith_max-2)*4))
        if data_len > 2:
                num += ((data_len-3)*((set_arith_max-2)*4))

    return num


def mutate_seq_8_bit_arithmetic_array(data, func, skip_null=False, kafl_state=None, effector_map=None, set_arith_max=None):
    if kafl_state:
        kafl_state.technique = "ARITH 8"

    if not set_arith_max:
        set_arith_max = AFL_ARITH_MAX

    for i in range(0, len(data) * set_arith_max):
        if effector_map:
            if not effector_map[i/set_arith_max]:
                continue
        if skip_null and data[i/set_arith_max] == 0x00:
            func(None, no_data=True)
            func(None, no_data=True)
            continue

        if is_not_bitflip(data[i/set_arith_max] ^ (data[i/set_arith_max] + ((i) % set_arith_max))):
            was = data[i/set_arith_max]
            data[i/set_arith_max] = ((data[i/set_arith_max] + (i % set_arith_max)) & 0xff)
            if (i%set_arith_max) != 0:
                func(data.tostring())
            else:
                func(None, no_data=True)
                func(None, no_data=True)
                continue
            data[i/set_arith_max] = ((data[i/set_arith_max] - (i % set_arith_max)) & 0xff)
        else:
            func(None, no_data=True)

        if is_not_bitflip(data[i/set_arith_max] ^ (data[i/set_arith_max] - ((i) % set_arith_max))):
            data[i/set_arith_max] = ((data[i/set_arith_max] - (i % set_arith_max)) & 0xff)
            func(data.tostring())
            data[i/set_arith_max] = ((data[i/set_arith_max] + (i % set_arith_max)) & 0xff)
        else:
            func(None, no_data=True)


def mutate_seq_16_bit_arithmetic_array(data, func, skip_null=False, kafl_state=None, effector_map=None, set_arith_max=None):
    if kafl_state:
        kafl_state.technique = "ARITH 16"

    if not set_arith_max:
        set_arith_max = AFL_ARITH_MAX

    for i in range(0, len(data)-1):
        value = array('H', (data[i:i+2]).tostring())
        value = value[0]
        for j in range(1, set_arith_max-1):
            if effector_map:
                if not effector_map[i] or not effector_map[i+1]:
                    continue
            if skip_null and value == 0x00:
                func(None, no_data=True)
                func(None, no_data=True)
                func(None, no_data=True)
                func(None, no_data=True)
                continue

            r1 = (value ^ in_range_16(value + j))
            r2 = (value ^ in_range_16(value - j))
            r3 = swap_16(value ^ in_range_16(value + j))
            r4 = swap_16(value ^ in_range_16(value - j))

            # little endian increment
            if is_not_bitflip(r1) and ((value & 0xff) + j) > 0xff:
                func(data[:i].tostring() + to_string_16(in_range_16(value + j)) + data[i+2:].tostring())
            else:
                func(None, no_data=True)

            # little endian decrement
            if is_not_bitflip(r2) and (value & 0xff) < j:
                func(data[:i].tostring() + to_string_16(in_range_16(value - j)) + data[i+2:].tostring())
            else:
                func(None, no_data=True)

            if swap_16(in_range_16(value + j)) == in_range_16(value + j) or swap_16(in_range_16(value - j)) == in_range_16(value - j):
                func(None, no_data=True)
                func(None, no_data=True)
                continue

            # big endian increment
            if is_not_bitflip(r3) and ((value >> 8) + j) > 0xff:
                func(data[:i].tostring() + to_string_16(swap_16(in_range_16(value + j))) + data[i+2:].tostring())
            else:
                func(None, no_data=True)

            # big endian decrement
            if is_not_bitflip(r4) and (value >> 8) < j:
                func(data[:i].tostring() + to_string_16(swap_16(in_range_16(value - j))) + data[i+2:].tostring())
            else:
                func(None, no_data=True)


def mutate_seq_32_bit_arithmetic_array(data, func, skip_null=False, kafl_state=None, effector_map=None, set_arith_max=None):
    if kafl_state:
        kafl_state.technique = "ARITH 32"

    if not set_arith_max:
        set_arith_max = AFL_ARITH_MAX

    for i in range(0, len(data)-3):
        value = array('I', (data[i:i+4]).tostring())
        value = value[0]
        for j in range(1, set_arith_max-1):
            

            if effector_map:
                if not effector_map[i] or not effector_map[i + 1] or not effector_map[i + 2] or not effector_map[i + 3]:
                    continue
            if skip_null and value == 0x00:
                func(None, no_data=True)
                func(None, no_data=True)
                func(None, no_data=True)
                func(None, no_data=True)
                continue

            r1 = (value ^ in_range_32(value + j))
            r2 = (value ^ in_range_32(value - j))
            r3 = swap_32(value ^ in_range_32(value + j))
            r4 = swap_32(value ^ in_range_32(value - j))

            # little endian increment
            if is_not_bitflip(r1) and in_range_32((value & 0xffff) + j) > 0xffff:
                func(data[:i].tostring() + to_string_32(in_range_32(value + j)) + data[i+4:].tostring())
            else:
                func(None, no_data=True)

            # little endian decrement
            if is_not_bitflip(r2) and in_range_32(value & 0xffff) < j:
                func(data[:i].tostring() + to_string_32(in_range_32(value - j)) + data[i+4:].tostring())
            else:
                func(None, no_data=True)

            if swap_32(in_range_32(value + j)) == in_range_32(value + j) or swap_32(in_range_32(value - j)) == in_range_32(value - j):
                func(None, no_data=True)
                func(None, no_data=True)
                continue

            # big endian increment
            if is_not_bitflip(r3) and in_range_32((value >> 16) + j) > 0xffff:
                func(data[:i].tostring() + to_string_32(swap_32(in_range_32(value + j))) + data[i+4:].tostring())
            else:
                func(None, no_data=True)

            # big endian decrement
            if is_not_bitflip(r4) and in_range_32(value >> 16) < j:
                func(data[:i].tostring() + to_string_32(swap_32(in_range_32(value - j))) + data[i+4:].tostring())
            else:
                func(None, no_data=True)
