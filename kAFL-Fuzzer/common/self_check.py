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

from fcntl import ioctl
import sys, os, subprocess

error_prefix = "[Error] "

def check_version():
    if sys.version_info < (2, 7, 0) or sys.version_info >= (3, 0, 0):
        print('\033[93m' + error_prefix + "This script requires python 2.7 or higher (except for python 3.x)!" + '\033[0m')
        return False
    return True

def check_packages():
    try:
        import mmh3
    except ImportError:
        print('\033[91m' + error_prefix + "Package 'mmh3' is missing!" + '\033[0m')
        return False

    try:
        import lz4
    except ImportError:
        print('\033[91m' + error_prefix + "Package 'lz4' is missing!" + '\033[0m')
        return False

    try:
        import psutil
    except ImportError:
        print('\033[91m' + error_prefix + "Package 'psutil' is missing!" + '\033[0m')
        return False

    try:
        import pygraphviz
    except ImportError:
        print('\033[91m' + error_prefix + "Package 'pygraphviz' is missing!" + '\033[0m')
        return False

    return True

def check_vmx_pt():
    from fcntl import ioctl

    KVMIO = 0xAE
    KVM_VMX_PT_SUPPORTED = KVMIO << (8) | 0xe4

    try:
        fd = open("/dev/kvm", "wb")
    except:
        print('\033[91m' + error_prefix + "KVM is not loaded!" + '\033[0m')
        return False

    try:
        ret = ioctl(fd, KVM_VMX_PT_SUPPORTED, 0)
    except IOError:
        print('\033[91m' + error_prefix + "VMX_PT is not loaded!" + '\033[0m')
        return False
    fd.close()

    if ret == 0:
        print('\033[91m' + error_prefix + "Intel PT is not supported on this CPU!" + '\033[0m')
        return False

    return True

def check_apple_osk(config):
    if config.argument_values["macOS"]:
        if config.config_values["APPLE-SMC-OSK"] == "":
            print('\033[91m' + error_prefix + "APPLE SMC OSK is missing in kafl.ini!" + '\033[0m')
            return False
    return True

def check_apple_ignore_msrs(config):
    if config.argument_values["macOS"]:
        try:
            f = open("/sys/module/kvm/parameters/ignore_msrs")
            if not 'Y' in f.read(1):
                print('\033[91m' + error_prefix + "KVM is not properly configured! Please execute the following command:" + '\033[0m' + "\n\n\tsudo su\n\techo 1 > /sys/module/kvm/parameters/ignore_msrs\n")
                return False
            else:
                return True
        except:
            pass
        finally:
            f.close()
        print('\033[91m' + error_prefix + "KVM is not ready?!" + '\033[0m')
        return False
    return True

def check_qemu_version(config):
    if not config.config_values["QEMU_KAFL_LOCATION"] or config.config_values["QEMU_KAFL_LOCATION"] == "":
        print('\033[91m' + error_prefix + "QEMU_KAFL_LOCATION is not set in kafl.ini!" + '\033[0m')
        return False

    if not os.path.exists(config.config_values["QEMU_KAFL_LOCATION"]):
        print('\033[91m' + error_prefix + "QEMU-PT executable does not exists..." + '\033[0m')
        return False

    output = ""
    try:
        proc = subprocess.Popen([config.config_values["QEMU_KAFL_LOCATION"], "-version"],stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = proc.stdout.readline()
    except:
        print('\033[91m' + error_prefix + "Binary is not executable...?" + '\033[0m')
        return False
    if not("QEMU-PT" in output and "(kAFL)" in output):
        print('\033[91m' + error_prefix + "Wrong QEMU-PT executable..." + '\033[0m')
        return False
    return True

def self_check():
    if not check_version():
        return False
    if not check_packages():
        return False
    if not check_vmx_pt():
        return False
    return True

def post_self_check(config):
    if not check_apple_ignore_msrs(config):
        return False
    if not check_apple_osk(config):
        return False
    if not check_qemu_version(config):
        return False
    return True