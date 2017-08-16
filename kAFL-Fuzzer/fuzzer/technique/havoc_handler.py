__author__ = 'sergej'

from array import array

from fuzzer.technique.helper import *
from common.util import read_binary_file, find_diffs
from common.debug import logger


def havoc_perform_bit_flip(data, func):
    if len(data) >= 1:
        bit = RAND(len(data) << 3)
        data[bit/8] ^= 1 << (bit % 8)
        func(data.tostring())
    return data


def havoc_perform_insert_interesting_value_8(data, func):
    if len(data) >= 1:
        data[RAND(len(data))] = interesting_8_Bit[RAND(len(interesting_8_Bit))]
        func(data.tostring())
    return data


def havoc_perform_insert_interesting_value_16(data, func):
    if len(data) >= 2:
        pos = RAND(len(data)-1)
        interesting_value = interesting_16_Bit[RAND(len(interesting_16_Bit))]
        if RAND(2) == 1:
            interesting_value = swap_16(interesting_value)
        store_16(data, pos, interesting_value)
        func(data.tostring())
    return data


def havoc_perform_insert_interesting_value_32(data, func):
    if len(data) >= 4:
        pos = RAND(len(data)-3)
        interesting_value = interesting_32_Bit[RAND(len(interesting_32_Bit))]
        if RAND(2) == 1:
            interesting_value = swap_32(interesting_value)
        store_32(data, pos, interesting_value)
        func(data.tostring())
    return data


def havoc_perform_byte_subtraction_8(data, func):
    if len(data) >= 1:
        pos = RAND(len(data))
        value = load_8(data, pos)
        value -= 1 + RAND(AFL_ARITH_MAX)
        store_8(data, pos, value)
        func(data.tostring())
    return data


def havoc_perform_byte_addition_8(data, func):
    if len(data) >= 1:
        pos = RAND(len(data))
        value = load_8(data, pos)
        value += 1 + RAND(AFL_ARITH_MAX)
        store_8(data, pos, value)
        func(data.tostring())
    return data


def havoc_perform_byte_subtraction_16(data, func):
    if len(data) >= 2:
        pos = RAND(len(data)-1)
        value = load_16(data, pos)
        if RAND(2) == 1:
            value = swap_16(swap_16(value) - (1 + RAND(AFL_ARITH_MAX)))
        else:
            value -= 1 + RAND(AFL_ARITH_MAX)
        store_16(data, pos, value)
        func(data.tostring())
    return data


def havoc_perform_byte_addition_16(data, func):
    if len(data) >= 2:
        pos = RAND(len(data)-1)
        value = load_16(data, pos)
        if RAND(2) == 1:
            value = swap_16(swap_16(value) + (1 + RAND(AFL_ARITH_MAX)))
        else:
            value += 1 + RAND(AFL_ARITH_MAX)
        store_16(data, pos, value)
        func(data.tostring())
    return data


def havoc_perform_byte_subtraction_32(data, func):
    if len(data) >= 4:
        pos = RAND(len(data)-3)
        value = load_32(data, pos)
        if RAND(2) == 1:
            value = swap_32(swap_32(value) - (1 + RAND(AFL_ARITH_MAX)))
        else:
            value -= 1 + RAND(AFL_ARITH_MAX)
        store_32(data, pos, value)
        func(data.tostring())
    return data


def havoc_perform_byte_addition_32(data, func):
    if len(data) >= 4:
        pos = RAND(len(data)-3)
        value = load_32(data, pos)
        if RAND(2) == 1:
            value = swap_32(swap_32(value) + (1 + RAND(AFL_ARITH_MAX)))
        else:
            value += 1 + RAND(AFL_ARITH_MAX)
        store_32(data, pos, value)
        func(data.tostring())
    return data


def havoc_perform_set_random_byte_value(data, func):
    if len(data) >= 1:
        data[RAND(len(data))] = 1 + RAND(0xff)
        func(data.tostring())
    return data

# Todo: somehow broken :-(
def havoc_perform_delete_random_byte(data, func):
    if len(data) >= 2:
        del_length = AFL_choose_block_len(len(data) - 1)
        del_from = RAND(len(data) - del_length + 1)
        data = data[del_from:del_from + del_length]
        func(data.tostring())
    return data


def havoc_perform_clone_random_byte(data, func):
    if (len(data) + AFL_HAVOC_BLK_LARGE) < KAFL_MAX_FILE:
        clone_length = AFL_choose_block_len(len(data))
        clone_from = RAND(len(data) - clone_length + 1)
        clone_to = RAND(len(data))
        head = data[0:clone_to].tostring()

        if RAND(4) != 0:
            body = data[clone_from: clone_from+clone_length].tostring()
        else:
            body = ''.join(chr(random.randint(0, 0xff)) for _ in range(clone_length))

        tail = data[clone_to:(len(data)  - clone_to)].tostring()
        data = array('B', head + body + tail)
        func(data.tostring())
    return data


def havoc_perform_byte_seq_override(data, func):
    if len(data) >= 2:
        copy_length = AFL_choose_block_len(len(data) - 1)
        copy_from = RAND(len(data) - copy_length + 1)
        copy_to = RAND(len(data) - copy_length + 1)
        if RAND(4) != 0:
            if copy_from != copy_to:
                chunk = data[copy_from: copy_from + copy_length]
                for i in range(len(chunk)):
                    data[i+copy_to] = chunk[i]
        else:
            value = RAND(0xff)
            for i in range(copy_length):
                data[i+copy_to] = value
        func(data.tostring())
    return data


def havoc_perform_byte_seq_extra1(data):
    pass


def havoc_perform_byte_seq_extra2(data):
    pass

def havoc_splicing(data, files=None):

    if len(data) >= 2:
        for file in files:
            file_data = read_binary_file(file)
            if len(file_data) < 2:
                continue

            first_diff, last_diff = find_diffs(data, file_data)
            if last_diff < 2 or first_diff == last_diff:
                continue

            split_location = first_diff + RAND(last_diff - first_diff)

            data = array('B', data.tostring()[:split_location] + file_data[split_location:len(data)])
            #func(data.tostring())
            break

    return data

dict_import = []
def set_dict(new_dict):
    global dict_import
    dict_import = new_dict

def append_handler(handler):
    global havoc_handler
    havoc_handler.append(handler)

def havoc_dict(data, func):
    global dict_import
    if len(dict_import) > 0:
        dict_entry = dict_import[RAND(len(dict_import))]
        dict_entry = dict_entry[:len(data)]
        entry_pos = RAND(len(data)-len(dict_entry))
        data = array('B',data.tostring()[:entry_pos] + dict_entry + data.tostring()[entry_pos+len(dict_entry):])
        func(data.tostring())
    return data

havoc_handler = [havoc_perform_bit_flip,
                 havoc_perform_insert_interesting_value_8,
                 havoc_perform_insert_interesting_value_16,
                 havoc_perform_insert_interesting_value_32,
                 havoc_perform_byte_addition_8,
                 havoc_perform_byte_addition_16,
                 havoc_perform_byte_addition_32,
                 havoc_perform_byte_subtraction_8,
                 havoc_perform_byte_subtraction_16,
                 havoc_perform_byte_subtraction_32,
                 havoc_perform_set_random_byte_value,
                 #havoc_perform_delete_random_byte,
                 #havoc_perform_delete_random_byte,
                 #havoc_perform_clone_random_byte,
                 havoc_perform_byte_seq_override,
                 #havoc_perform_clone_random_byte,
                 havoc_perform_byte_seq_override,
                 #havoc_perform_byte_seq_extra1,
                 #havoc_perform_byte_seq_extra2,
                 ]
