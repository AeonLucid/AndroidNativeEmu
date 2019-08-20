import logging
import os
import time
from random import randint

import hexdump
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_R0

from androidemu import config
from androidemu.config import HOOK_MEMORY_BASE, HOOK_MEMORY_SIZE
from androidemu.cpu.interrupt_handler import InterruptHandler
from androidemu.cpu.syscall_handlers import SyscallHandlers
from androidemu.cpu.syscall_hooks import SyscallHooks
from androidemu.hooker import Hooker
from androidemu.internal.memory import Memory
from androidemu.internal.modules import Modules
from androidemu.java.helpers.native_method import native_write_args
from androidemu.java.java_classloader import JavaClassLoader
from androidemu.java.java_vm import JavaVM
from androidemu.native.hooks import NativeHooks
from androidemu.native.memory import NativeMemory
from androidemu.tracer import Tracer
from androidemu.vfs.file_system import VirtualFileSystem

logger = logging.getLogger(__name__)


class Emulator:
    """
    :type mu Uc
    :type modules Modules
    :type memory Memory
    """
    def __init__(self, vfs_root=None, vfp_inst_set=False):
        # Unicorn.
        self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        if vfp_inst_set:
            self._enable_vfp()

        # Android
        self.system_properties = {"libc.debug.malloc.options":""}

        # Stack.
        self.mu.mem_map(config.STACK_ADDR, config.STACK_SIZE)
        self.mu.reg_write(UC_ARM_REG_SP, config.STACK_ADDR + config.STACK_SIZE)

        # Executable data.
        self.modules = Modules(self)
        self.memory = Memory(self)

        # CPU
        self.interrupt_handler = InterruptHandler(self.mu)
        self.syscall_handler = SyscallHandlers(self.interrupt_handler)
        self.syscall_hooks = SyscallHooks(self.mu, self.syscall_handler)

        # File System
        if vfs_root is not None:
            self.vfs = VirtualFileSystem(vfs_root, self.syscall_handler)
        else:
            self.vfs = None

        # Hooker
        self.mu.mem_map(config.HOOK_MEMORY_BASE, config.HOOK_MEMORY_SIZE)
        self.hooker = Hooker(self, config.HOOK_MEMORY_BASE, config.HOOK_MEMORY_SIZE)

        # JavaVM
        self.java_classloader = JavaClassLoader()
        self.java_vm = JavaVM(self, self.java_classloader, self.hooker)

        # Native
        self.native_memory = NativeMemory(self.mu, config.HEAP_BASE, config.HEAP_SIZE, self.syscall_handler)
        self.native_hooks = NativeHooks(self, self.native_memory, self.modules, self.hooker)

        # Tracer
        self.tracer = Tracer(self.mu, self.modules)

    # https://github.com/unicorn-engine/unicorn/blob/8c6cbe3f3cabed57b23b721c29f937dd5baafc90/tests/regress/arm_fp_vfp_disabled.py#L15
    def _enable_vfp(self):
        # MRC p15, #0, r1, c1, c0, #2
        # ORR r1, r1, #(0xf << 20)
        # MCR p15, #0, r1, c1, c0, #2
        # MOV r1, #0
        # MCR p15, #0, r1, c7, c5, #4
        # MOV r0,#0x40000000
        # FMXR FPEXC, r0
        code = '11EE501F'
        code += '41F47001'
        code += '01EE501F'
        code += '4FF00001'
        code += '07EE951F'
        code += '4FF08040'
        code += 'E8EE100A'
        # vpush {d8}
        code += '2ded028b'

        address = 0x1000
        mem_size = 0x1000
        code_bytes = bytes.fromhex(code)

        try:
            self.mu.mem_map(address, mem_size)
            self.mu.mem_write(address, code_bytes)
            self.mu.reg_write(UC_ARM_REG_SP, address + mem_size)

            self.mu.emu_start(address | 1, address + len(code_bytes))
        finally:
            self.mu.mem_unmap(address, mem_size)

    def load_library(self, filename, do_init=True):
        libmod = self.modules.load_module(filename)
        if do_init:
            logger.debug("Calling Init for: %s " % filename)
            for fun_ptr in libmod.init_array:
                logger.debug("Calling Init function: %x " % fun_ptr)
                self.call_native(fun_ptr)
        return libmod

    def call_symbol(self, module, symbol_name, *argv):
        symbol = module.find_symbol(symbol_name)

        if symbol is None:
            logger.error('Unable to find symbol \'%s\' in module \'%s\'.' % (symbol_name, module.filename))
            return

        self.call_native(symbol.address, *argv)

    def call_native(self, addr, *argv):
        # Detect JNI call
        is_jni = False

        if len(argv) >= 1:
            is_jni = argv[0] == self.java_vm.address_ptr or argv[0] == self.java_vm.jni_env.address_ptr

        # TODO: Write JNI args to local ref table if jni.

        try:
            # Execute native call.
            native_write_args(self, *argv)
            stop_pos = randint(HOOK_MEMORY_BASE, HOOK_MEMORY_BASE + HOOK_MEMORY_SIZE) | 1
            self.mu.reg_write(UC_ARM_REG_LR, stop_pos)
            self.mu.emu_start(addr, stop_pos - 1)

            # Read result from locals if jni.
            if is_jni:
                result_idx = self.mu.reg_read(UC_ARM_REG_R0)
                result = self.java_vm.jni_env.get_local_reference(result_idx)

                if result is None:
                    return result

                return result.value
        finally:
            # Clear locals if jni.
            if is_jni:
                self.java_vm.jni_env.clear_locals()

    def dump(self, out_dir):
        os.makedirs(out_dir)

        for begin, end, prot in [reg for reg in self.mu.mem_regions()]:
            filename = "{:#010x}-{:#010x}.bin".format(begin, end)
            pathname = os.path.join(out_dir, filename)
            with open(pathname, "w") as f:
                f.write(hexdump.hexdump(self.mu.mem_read(begin, end - begin), result='return'))
