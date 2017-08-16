__author__ = 'sergej'

def mutate_seq_debug_array(data, func, skip_null=False, kafl_state=None):
    kafl_state.technique = "DEBUG"
    for i in range(len(data)*0xff):
        #tmp = data[i/0xff]
        #data[i/0xff] = (i % 0xff)
        func(data.tostring())
        #data[i/0xff] = tmp

