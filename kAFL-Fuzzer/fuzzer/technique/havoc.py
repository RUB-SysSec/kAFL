__author__ = 'sergej'

from array import array
from fuzzer.technique.helper import *
from fuzzer.technique.havoc_handler import *
from common.config import FuzzerConfiguration
from common.debug import logger

def load_dict(file_name):
    f = open(file_name)
    dict_entries = []
    for line in f:
        if not line.startswith("#"):
            try:
                dict_entries.append((line.split("=\"")[1].split("\"\n")[0]).decode("string_escape"))
            except:
                pass
    f.close()
    return dict_entries

if FuzzerConfiguration().argument_values["I"]:
    set_dict(load_dict(FuzzerConfiguration().argument_values["I"]))
    append_handler(havoc_dict)
    append_handler(havoc_dict)

location_findings = FuzzerConfiguration().argument_values['work_dir'] + "/findings/"
location_corpus = FuzzerConfiguration().argument_values['work_dir'] + "/corpus/"

def havoc_range(perf_score):

    max_iterations = int(perf_score * 2.5)

    if max_iterations < AFL_HAVOC_MIN:
        max_iterations = AFL_HAVOC_MIN

    return max_iterations


def mutate_seq_havoc_array(data, func, max_iterations, stacked=True, resize=False, files_to_splice=None):

    reseed()
    if resize:
        copy = array('B', data.tostring() + data.tostring())
    else:
        copy = array('B', data.tostring())

    cnt = 0
    for i in range(max_iterations):
        if resize:
            copy = array('B', data.tostring() + data.tostring())
        else:
            copy = array('B', data.tostring())

        value = RAND(AFL_HAVOC_STACK_POW2)
        if files_to_splice:
            copy = havoc_splicing(data, files_to_splice)
            value = RAND(AFL_HAVOC_STACK_POW2)*3

        for j in range(1 << (1 + value)):
            handler = random.choice(havoc_handler)
            if not stacked:
                if resize:
                    copy = array('B', data.tostring() + data.tostring())
                else:
                    copy = array('B', data.tostring())
            copy = handler(copy[:(64<<10)], func)
            cnt += 1
            if cnt >= max_iterations:
                return

    pass


def mutate_seq_splice_array(data, func, max_iterations, kafl_state, stacked=True, resize=False):
    files = []
    for i in range(kafl_state.panics_unique):
        files.append(location_findings + "/panic/panic_" + str(i+1))
    for i in range(kafl_state.kasan_unique):
        files.append(location_findings + "/kasan/kasan_" + str(i+1))
    for i in range(kafl_state.reloads_unique):
        files.append(location_findings + "/timeout/timeout_" + str(i+1))

    for i in range(kafl_state.hashes):
        files.append(location_corpus + "payload_" + str(i))

    random.shuffle(files)
    mutate_seq_havoc_array(data, func, max_iterations, stacked=stacked, resize=resize, files_to_splice=files)
