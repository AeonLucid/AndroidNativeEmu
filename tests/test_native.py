import logging
import os
import sys
import unittest

from androidemu.emulator import Emulator

logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)7s %(name)34s | %(message)s"
)

dir_samples = os.path.join(os.path.dirname(__file__), "..", "examples")


class TestNative(unittest.TestCase):

    def testOneArg(self):
        # Initialize emulator
        emulator = Emulator(
            vfp_inst_set=True,
            vfs_root=os.path.join(dir_samples, "vfs")
        )

        emulator.load_library(os.path.join(dir_samples, "example_binaries", "32", "libdl.so"))
        emulator.load_library(os.path.join(dir_samples, "example_binaries", "32", "libc.so"))
        emulator.load_library(os.path.join(dir_samples, "example_binaries", "32", "libstdc++.so"))
        module = emulator.load_library(os.path.join(os.path.dirname(__file__), "test_binaries", "32", "test_native.so"))

        res = emulator.call_symbol(module, 'Java_com_aeonlucid_nativetesting_MainActivity_testOneArg', emulator.java_vm.jni_env.address_ptr, 0x00, 'Hello')

        self.assertEqual('Hello', res)

    def testSixArg(self):
        # Initialize emulator
        emulator = Emulator(
            vfp_inst_set=True,
            vfs_root=os.path.join(dir_samples, "vfs")
        )

        emulator.load_library(os.path.join(dir_samples, "example_binaries", "32", "libdl.so"))
        emulator.load_library(os.path.join(dir_samples, "example_binaries", "32", "libc.so"))
        emulator.load_library(os.path.join(dir_samples, "example_binaries", "32", "libstdc++.so"))
        module = emulator.load_library(os.path.join(os.path.dirname(__file__), "test_binaries", "32", "test_native.so"))

        res = emulator.call_symbol(module, 'Java_com_aeonlucid_nativetesting_MainActivity_testSixArg', emulator.java_vm.jni_env.address_ptr, 0x00, 'One', 'Two', 'Three', 'Four', 'Five', 'Six')

        self.assertEqual('OneTwoThreeFourFiveSix', res)
