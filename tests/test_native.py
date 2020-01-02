import logging
import posixpath
import sys
import unittest

from unicorn import UC_HOOK_MEM_UNMAPPED, UC_HOOK_CODE

from androidemu.emulator import Emulator
from samples import debug_utils

logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)7s %(name)34s | %(message)s"
)

dir_samples = posixpath.join(posixpath.dirname(__file__), "..", "samples")


class TestNative(unittest.TestCase):

    def test_something(self):
        # Initialize emulator
        emulator = Emulator(
            vfp_inst_set=True,
            vfs_root=posixpath.join(dir_samples, "vfs")
        )

        emulator.load_library(posixpath.join(dir_samples, "example_binaries", "libdl.so"), do_init=False)
        emulator.load_library(posixpath.join(dir_samples, "example_binaries", "libc.so"), do_init=False)
        emulator.load_library(posixpath.join(dir_samples, "example_binaries", "libstdc++.so"), do_init=False)
        module = emulator.load_library(posixpath.join(posixpath.dirname(__file__), "test_binaries", "test_native.so"), do_init=False)

        print(module.base)

        emulator.mu.hook_add(UC_HOOK_CODE, debug_utils.hook_code)
        emulator.mu.hook_add(UC_HOOK_MEM_UNMAPPED, debug_utils.hook_unmapped)
        res = emulator.call_symbol(module, 'Java_com_aeonlucid_nativetesting_MainActivity_testOneArg', emulator.java_vm.address_ptr, 0x00, 'Hello', 'asd')

        print(res)
