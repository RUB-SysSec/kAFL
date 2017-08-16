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

import signal
import psutil
from fuzzer.state import *
import subprocess
from common.debug import get_rbuf_content

class FuzzerUI():
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[0;33m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    CLRSCR = '\x1b[1;1H'
    REALCLRSCR = '\x1b[2J'
    BOLD = '\033[1m'

    HLINE = unichr(0x2500)
    VLINE = unichr(0x2502)
    VLLINE = unichr(0x2524)
    VRLINE = unichr(0x251c)
    LBEDGE = unichr(0x2514)
    RBEDGE = unichr(0x2518)
    HULINE = unichr(0x2534)
    HDLINE = unichr(0x252c)
    LTEDGE = unichr(0x250c)
    RTEDGE = unichr(0x2510)

    approx_equal = lambda self, a, b, t: abs(a - b) < t

    TARGET_FIELD_LEN = 14
    INTERFACE_FIELD_LEN = 10
    TECHNIQUE_FIELD_LEN = 14
    BEST_PERFORMANCE = 1000
    BEST_PERFORMANCE_BAR_LEN = 14
    TECHNIQUE_BAR_LEN = 15

    MIN_WIDTH = 72
    MIN_HEIGHT = 25

    current_max_performance = 100

    def __init__(self, process_num, fancy=True, inline_log=True):
        if not fancy:
            self.HLINE = '-'
            self.VLINE = '|'
            self.VLLINE = '+'
            self.VRLINE = '+'
            self.LBEDGE = '+'
            self.RBEDGE = '+'
            self.HULINE = '+'
            self.HDLINE = '+'   
            self.LTEDGE = '+'
            self.RTEDGE = '+'

        print(self.REALCLRSCR).encode('utf-8')
        self.process_num = process_num
        self.state = None
        self.__loading_screen()
        self.state = State()
        self.size_ok = True
        self.sighandler_lock = False
        self.old_signal_handler = signal.getsignal(signal.SIGWINCH)

        self.blacklist_timer = None
        self.blacklist_counter = 0
        self.blacklist_tcounter = 0
        self.inline_log = inline_log
        if self.inline_log:
            self.MIN_HEIGHT += 14

    def __del__(self):
        print(self.REALCLRSCR + self.CLRSCR + self.FAIL + \
                  "[!] Data saved! Bye!" + self.ENDC + "\n").encode('utf-8')

    def update_state(self, state):
        self.state = state

    def refresh(self):
        self.__redraw_ui()

    def install_sighandler(self):
        signal.signal(signal.SIGWINCH, self.__sigwinch_handler)

    def uninstall_signhandler(self):
        signal.signal(signal.SIGWINCH, self.old_signal_handler)

    def __hexdump(self, src, length=16, max_length=64):
        if len(src) < max_length:
            src += '\x00' * (max_length-len(src))
        FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
        lines = []
        for c in xrange(0, len(src), length):
            chars = src[c:c+length]
            hex = ' '.join(["%02x" % ord(x) for x in chars])
            printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
            lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
        return ''.join(lines)

    def __sigwinch_handler(self, signum, frame):
        self.size_ok = self.__win_size()
        try:
            print(self.REALCLRSCR).encode('utf-8')
            self.__redraw_ui()
        except:
            pass

    def __win_size(self):
        try:
            rows, columns = subprocess.check_output(['stty', 'size']).split(" ")
            if int(columns) > self.MIN_WIDTH and int(rows) > self.MIN_HEIGHT:
                return True
            else:
                return False
        except ValueError:
            return True

    def __get_logs(self):
        tmp = get_rbuf_content()
        #print(tmp)
        content = ("\n " + self.VLINE + " " + " " * 65 + "|" ) * 10
        content +=  ("\n" + 70 * " ") * 4
        try:
            content += "\033[15A" + "\n"
            for e in tmp:
                content += "\n " + self.VLINE + " " + e[:65] + (65-len(e[:65])) * ' ' + self.VLINE + "\r" + "\033[68C\033[K" + self.VLINE
            return content + "\n"
        except:
            return content + "\n"

    def __redraw_ui(self):
        if self.size_ok and not self.state.loading:
            #ui = self.REALCLRSCR
            ui = ""
            ui += self.CLRSCR
            ui += self.__get_logo()
            ui += self.__get_ui_line1()
            ui += self.__get_ui_line2()
            ui += self.__get_ui_line3()
            ui += self.__get_ui_line4()
            ui += self.__get_ui_line5()
            ui += self.__get_ui_line6()
            ui += self.__get_ui_line7()
            ui += self.__get_ui_line8()
            ui += self.__get_ui_line9()
            ui += self.__get_ui_line10()
            ui += self.__get_ui_line11()
            ui += self.__get_ui_line12()
            if self.state.reload:
                ui += self.__reload_lines()
            ui += self.__get_ui_line13()

            if self.inline_log:
                ui += "\n  kAFL Logs:\n " + self.LTEDGE + (66 * self.HLINE) + self.RTEDGE
                ui += self.__get_logs()
                ui += " " + self.LBEDGE + (66 * self.HLINE) + self.RBEDGE + "\n"


            print(ui).encode('utf-8')
        elif self.size_ok and self.state.loading:
            self.__loading_screen()
        else:
            print(self.REALCLRSCR + self.CLRSCR + self.FAIL + \
                  "[!] Please resize your terminal window!" + self.ENDC + "\n").encode('utf-8')

    def __loading_screen(self):
        print(self.CLRSCR + self.__get_logo(loading_screen=True) +
              " " + self.VLINE + " Loading QEMU processes into memory...                            " + self.VLINE).encode('utf-8')
        print(" " + self.VRLINE + (66 * self.HLINE) + self.VLLINE).encode('utf-8')
        if self.state:
            print(" " + self.VLINE + " Progress:" + self.__get_progress_bar(39, (self.state.slaves_ready/(self.process_num*1.0)))
                      + " (" + self.__get_printable_integer(self.state.slaves_ready) + " / " +
                      self.__get_printable_integer(self.process_num) + ") " + self.VLINE + self.ENDC).encode('utf-8')
        else:
            print(" " + self.VLINE + " Progress:" + self.__get_progress_bar(39, 0.0) +
                  " (" + self.__get_printable_integer(0) + " / " +
                  self.__get_printable_integer(self.process_num) + ") " + self.VLINE + self.ENDC).encode('utf-8')
            print(" " + self.LBEDGE + 66 * self.HLINE + self.RBEDGE).encode('utf-8')

    def __reload_lines(self):
        template = ""
        template += " +" +  66 * self.HLINE + "+" + "\n"
        if self.state:
            template += " " + self.VLINE + " KSM-Reload:" + self.__get_progress_bar(37, (self.state.slaves_ready/(self.process_num*1.0))) + \
                    " (" + self.__get_printable_integer(self.state.slaves_ready) + " / " + \
                    self.__get_printable_integer(self.process_num) + ") " + self.VLINE + self.ENDC + "\n"
        else:
            template += " " + self.VLINE + " KSM-Reload:" + self.__get_progress_bar(37, 0.0) + \
                    " (" + self.__get_printable_integer(0) + " / " + \
                    self.__get_printable_integer(self.process_num) + ") " + self.VLINE + self.ENDC + "\n"
        return template

    def __get_logo(self, loading_screen=False):
        # Slant ascii font :)
        if not loading_screen:
            HDLINE = self.HDLINE
        else:
            HDLINE = self.HLINE
        return "               __                        __   ___    ________            \n" + \
               "              / /_____  _________  ___  / /  /   |  / ____/ /            \n" + \
               "             / //_/ _ \/ ___/ __ \/ _ \/ /  / /| | / /_  / /             \n" + \
               "            / ,< /  __/ /  / / / /  __/ /  / ___ |/ __/ / /___           \n" + \
               "           /_/|_|\___/_/  /_/ /_/\___/_/  /_/  |_/_/   /_____/           \n" + \
               " " + self.LTEDGE  + (66 * self.HLINE) + self.RTEDGE + "    \n" + \
               " " + self.VLINE + "                 " + self.FAIL + "      * x86-64 kernel AFL *     " + self.ENDC + \
               " (" + self.__get_printable_integer(self.process_num)[1:] +  " Processes) " + self.VLINE + " \n" + \
               " " + self.VRLINE + (25 * self.HLINE) + HDLINE + (40 * self.HLINE) + self.VLLINE + "\n"

    def __get_ui_line1(self):
        template =  template = " " + self.VLINE + " Runtime:   " + self.__get_diff_time(self.state.runtime) + \
                   " " + self.VLINE  + " Performance: <PERFORMANCE_BAR> <PERFORMANCE_VALUE> t/s " + self.VLINE + "\n"
        if len(self.state.interface_str) > self.INTERFACE_FIELD_LEN:
            interface = self.state.interface_str[:(self.INTERFACE_FIELD_LEN - 1)] + "."
        else:
            interface = self.state.interface_str
        interface = ((self.INTERFACE_FIELD_LEN - len(interface)) * ' ') + interface

        self.state.performance = self.state.get_performance()
        if self.state.performance > self.state.get_max_performance():
            #self.current_max_performance = self.state.performance
            performance_float = 1.0
            #if self.state.performance >= self.BEST_PERFORMANCE:
            #    performance_float = 1.0
        elif self.state.get_max_performance() == 0:
            performance_float = 0.0
        else:
            performance_float = self.state.performance / (self.state.get_max_performance() * 1.0)
            #performance_float = self.state.performance / (self.BEST_PERFORMANCE * 1.0)

        if self.state.technique == "PRE-SAMPLING" or self.state.technique == "POST-SAMPLING" or self.state.technique == "BENCHMARKING":
            performance_bar = self.__get_progress_bar(self.BEST_PERFORMANCE_BAR_LEN, performance_float)
            return template.replace("<INTERFACE>", interface) \
                .replace("<PERFORMANCE_BAR>", performance_bar) \
                .replace("<PERFORMANCE_VALUE>", "  - ")
        else:
            performance_bar = self.__get_progress_bar(self.BEST_PERFORMANCE_BAR_LEN, performance_float)
            performance_value = self.__get_printable_integer(self.state.performance)
            return template.replace("<INTERFACE>", interface) \
                .replace("<PERFORMANCE_BAR>", performance_bar) \
                .replace("<PERFORMANCE_VALUE>", performance_value)

    def __get_ui_line2(self):
        template = " " + self.VLINE + " Last Path: " + self.__get_diff_time(self.state.last_hash_time) + \
                   " " + self.VRLINE   + 40 * self.HLINE + "" + self.VLLINE + "\n"
        if len(self.state.target_str) > self.TARGET_FIELD_LEN:
            target = self.state.target_str[:self.TARGET_FIELD_LEN - 1] + "."
        else:
            target = self.state.target_str
        target = ((self.TARGET_FIELD_LEN - len(target)) * ' ') + target
        return template.replace("<TARGET>", target)

    def __get_ui_line3(self):
        template = " " + self.VLINE + " Bitmap:    " + str(self.__get_printable_float(self.state.ratio_bits)).replace("%", "b") + "/ " + \
                   self.__get_printable_float(self.state.ratio_coverage) + \
                   " " + self.VLINE + "       Fuzzing Technique Progress       " + self.VLINE + "\n"
        return template

    def __get_ui_line4(self):
        if self.state.progress_bitflip_amount == 0:
            bitflip_rate = 0.0
        else:
            bitflip_rate = float(self.state.progress_bitflip) / float(self.state.progress_bitflip_amount)
        if self.approx_equal(1.0, bitflip_rate, 0.001):
            use_color = False
        else:
            use_color = True
        template = " " + self.VLINE + " Blacklisted:  " + self.__get_printable_integer(self.blacklist_tcounter) + "/" + self.__get_printable_integer(self.blacklist_counter) + \
                   " " + self.VLINE + " Bitflipping: " + \
                   self.__get_progress_bar(self.TECHNIQUE_BAR_LEN, bitflip_rate, color=use_color,
                                           specific_char='*', technique_color=True) + \
                   "   " + self.__get_printable_integer(self.state.progress_bitflip_amount) + "  " + self.VLINE + " \n"
        return template

    def __get_ui_line5(self):
        if self.state.progress_arithmetic_amount == 0:
            arithmetic_rate = 0.0
        else:
            arithmetic_rate = float(self.state.progress_arithmetic) / float(self.state.progress_arithmetic_amount)
        if self.approx_equal(1.0, arithmetic_rate, 0.001):
            use_color = False
        else:
            use_color = True
        template = " " + self.VRLINE + (25 * self.HLINE) + self.VLLINE + " Arithmetic:  " + \
                   self.__get_progress_bar(self.TECHNIQUE_BAR_LEN, arithmetic_rate, color=use_color,
                                           specific_char='*', technique_color=True) \
                   + "   " + self.__get_printable_integer(self.state.progress_arithmetic_amount) +"  " + self.VLINE + "\n"
        return template

    def __get_ui_line6(self):
        if self.state.progress_interesting_amount == 0:
            interesting_rate = 0.0
        else:
            interesting_rate = float(self.state.progress_interesting) / float(self.state.progress_interesting_amount)
        if self.approx_equal(1.0, interesting_rate, 0.001):
            use_color = False
        else:
            use_color = True

        if self.state.cycles != 0:
            cycles = self.WARNING + self.BOLD + self.__get_printable_integer(self.state.cycles) + self.ENDC
        else:
            cycles = self.__get_printable_integer(self.state.cycles)

        template = " " + self.VLINE + " Cycles:            " + cycles + \
                   " " + self.VLINE + " Interesting: " + \
                   self.__get_progress_bar(self.TECHNIQUE_BAR_LEN, interesting_rate, color=use_color,
                                           specific_char='*', technique_color=True) + \
                   "   " + self.__get_printable_integer(self.state.progress_interesting_amount) + "  " + self.VLINE + "\n"
        return template

    def __get_ui_line7(self):
        if self.state.progress_havoc_amount == 0:
            havoc_rate = 0.0
        else:
            havoc_rate = float(self.state.progress_havoc) / float(self.state.progress_havoc_amount)
        if self.approx_equal(1.0, havoc_rate, 0.001):
            use_color = False
        else:
            use_color = True
        template = " " + self.VLINE + " Level:        " + self.__get_printable_integer(self.state.level) + "/" + self.__get_printable_integer(self.state.max_level) \
                   + " " + self.VLINE + " Havoc:       " + \
                   self.__get_progress_bar(self.TECHNIQUE_BAR_LEN, havoc_rate, color=use_color,
                                           specific_char='*', technique_color=True) \
                   + "   " + self.__get_printable_integer(self.state.progress_havoc_amount) + "  " + self.VLINE + "\n"
        return template

    def __get_ui_line8(self):
        if self.state.progress_specific_amount == 0:
            specific_rate = 0.0
        else:
            specific_rate = float(self.state.progress_specific) / float(self.state.progress_specific_amount)
        if self.approx_equal(1.0, specific_rate, 0.001):
            use_color = False
        else:
            use_color = True

        tmp_fav_ratio = 0.0
        if self.state.hashes != 0:
            tmp_fav_ratio = 100.0 * (float(self.state.favorites) / float(self.state.hashes))

        template = " " + self.VLINE + " Favs: " + self.__get_printable_integer(self.state.favorites) + "/" + \
                   self.__get_printable_integer(self.state.hashes) + " " + self.__get_printable_float(tmp_fav_ratio, brackets=True) +\
                   " " + self.VLINE + " Splicing:    " + self.__get_progress_bar(self.TECHNIQUE_BAR_LEN, specific_rate,
                                                                color=use_color, specific_char='*',
                                                                technique_color=True) + \
                   "   " + self.__get_printable_integer(self.state.progress_specific_amount) + "  " + self.VLINE + "\n"
        return template

    def __get_ui_line9(self):
        template = " " + self.VLINE + " Pending:      " + self.__get_printable_integer(self.state.fav_pending) + "/" + \
                   self.__get_printable_integer(self.state.path_pending) + \
                   " " + self.VRLINE + (23 * self.HLINE) + self.HDLINE + (16 * self.HLINE) + self.VLLINE + "\n"
        return template

    def __get_ui_line10(self):
        cpu_usage = self.__get_cpu_usage()

        if self.state.panics != 0:
            panics = self.__get_printable_integer(self.state.panics, color=(self.FAIL + self.BOLD)) + " " + \
                     self.__get_printable_integer(self.state.panics_unique, brackets=True,
                                                  color=(self.FAIL + self.BOLD))
        else:
            panics = self.__get_printable_integer(0) + " " + self.__get_printable_integer(0, brackets=True)

        template = " " + self.VLINE + " Skipped:      " + self.__get_printable_integer(self.state.fav_unfinished) + "/" + \
                   self.__get_printable_integer(self.state.path_unfinished) + \
                   " " + self.VLINE + " Panic:    " + panics + \
                   " " + self.VLINE + " CPU:     " + self.__get_printable_float(cpu_usage * 100.0, colored=True) + " " + self.VLINE + "\n"
        return template

    def __get_ui_line11(self):
        mem_usage = self.__get_mem_usage()

        if self.state.kasan_unique != 0:
            kasan = self.__get_printable_integer(self.state.kasan, color=(self.FAIL + self.BOLD)) + " " + \
                     self.__get_printable_integer(self.state.kasan_unique, brackets=True,
                                                  color=(self.FAIL + self.BOLD))
        else:
            kasan = self.__get_printable_integer(0) + " " + self.__get_printable_integer(0, brackets=True)

        template = " " + self.VLINE + " Payload-Size:     " + self.__get_printable_integer(self.state.payload_size) + \
                   "B " + self.VLINE + " KASan:    " + kasan + " " + self.VLINE + " RAM:    " + \
                   " " + self.__get_printable_float(mem_usage * 100.0, colored=True) + " " + self.VLINE + "\n"
        return template

    def __get_ui_line12(self):

        if self.state.reloads_unique != 0:
            reloads = self.__get_printable_integer(self.state.reloads, color=(self.FAIL + self.BOLD)) + " " + \
                    self.__get_printable_integer(self.state.reloads_unique, brackets=True,
                                                 color=(self.FAIL + self.BOLD))
        else:
            reloads = self.__get_printable_integer(0) + " " + self.__get_printable_integer(0, brackets=True)

        if len(self.state.technique) > self.TECHNIQUE_FIELD_LEN:
            technique = self.state.technique[:(self.TECHNIQUE_FIELD_LEN - 1)] + "."
        else:
            technique = self.state.technique
        technique = ((self.TECHNIQUE_FIELD_LEN - len(technique)) * ' ') + technique
        template = " " + self.VLINE + " Total:             " + self.__get_printable_integer(self.state.total) + \
                   " " + self.VLINE + " Timeout:  " + reloads + \
                   " " + self.VLINE + " " + technique + " " + self.VLINE + "\n"
        return template

    def __get_ui_line13(self):
        return " " + self.LBEDGE + (25 * self.HLINE) + self.HULINE + (23 * self.HLINE) + self.HULINE + (16 * self.HLINE) + self.RBEDGE \
               + "\n" + (47 * ' ') + "\n"  + "\n" # + self.__hexdump(self.state.payload[0:0x60], max_length=0x60) + "\n"

    def __get_printable_integer(self, value, brackets=False, color=""):
        if value >= 1000000000000:
            ret = str(value / 1000000000000.0)[:3]
            if ret[len(ret) - 2] == '.':
                ret = ret[:-2] + 'T'
        elif value >= 1000000000:
            ret = str(value / 1000000000.0)[:3] + "G"
            if ret[len(ret) - 2] == '.':
                ret = ret[:-2] + 'G'
        elif value >= 1000000:
            ret = str(value / 1000000.0)[:3] + "M"
            if ret[len(ret) - 2] == '.':
                ret = ret[:-2] + 'M'
        elif value >= 1000:
            ret = str(value / 1000.0)[:3] + "K"
            if ret[len(ret) - 2] == '.':
                ret = ret[:-2] + 'K'
        else:
            ret = str(value)
        if brackets:
            return ((4 - len(ret)) * ' ') + "(" + color + ret + self.ENDC + ")"
        return ((4 - len(ret)) * ' ') + color + ret + self.ENDC

    def __get_printable_payload_size(self, value):
        if value >= 1 << 40:
            ret = str(value >> 40) + "T"
        elif value >= 1 << 30:
            ret = str(value >> 30) + "G"
        elif value >= 1 << 20:
            ret = str(value >> 20) + "M"
        elif value >= 1 << 10:
            ret = str(value >> 10) + "K"
        else:
            ret = str(value) + ' '
        return ((4 - len(ret)) * ' ') + ret

    def __get_progress_bar(self, char_num, percent, specific_char='|', color=True, negativ=False, technique_color=False):
        progress_bar = ""
        progress_chars = int(char_num * percent)

        if progress_chars > char_num:
            progress_chars = char_num
        elif progress_chars == 0:
            if not self.approx_equal(percent, 0.0, 0.001):
                progress_chars = 1
        progress_bar += progress_chars * specific_char
        progress_bar += (char_num - progress_chars) * ' '

        if color:
            if technique_color:
                color_code = self.WARNING
            else:
                if percent < 0.25:
                    if negativ:
                        color_code = self.OKGREEN
                    else:
                        color_code = self.FAIL
                elif percent < 0.50:
                    color_code = self.WARNING
                else:
                    if negativ:
                        color_code = self.FAIL
                    else:
                        color_code = self.OKGREEN
        else:
            color_code = self.ENDC

        return "[" + color_code + progress_bar + self.ENDC + "]"

    def __get_diff_time(self, time_b):
        diff = time.gmtime(time.time() - time_b)
        days = int(time.strftime('%j', diff)) - 1
        days = ((3 - len(str(days))) * '0') + str(days)
        return days + time.strftime(':%H:%M:%S', diff)

    def __get_cpu_usage(self):
        return (100.0 - psutil.cpu_times_percent(interval=0.1).idle) / 100.0

    def __get_mem_usage(self):
        return psutil.virtual_memory().percent / 100.0

    def __get_printable_float(self, float_value, brackets=False, colored=False):
        color_value = ""
        if colored:
            if float_value <= 25.0:
                color_value = self.OKGREEN
            elif 25.0 < float_value <= 75.0:
                color_value = self.WARNING
            else:
                color_value = self.FAIL

        if float_value > 100.0:
            float_value = 100.0

        if self.approx_equal(100.0, float_value, 0.01):
            if brackets:
                return " (" + color_value + "100%" + self.ENDC + ")"
            return color_value + " 100%" + self.ENDC

        else:
            str_value = "%0.1f" % float_value
            if len(str_value) < 4:
                if brackets:
                    return "(" + color_value + "0" + str_value + "%" + self.ENDC + ")"
                return color_value + "0" + str_value + "%" + self.ENDC
            if brackets:
                return "(" + color_value + str_value + "%" + self.ENDC + ")"
            return color_value + str_value + "%" + self.ENDC
