import logging
import os
from random import randint

import hexdump
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_R0, UC_ARM_REG_C13_C0_3

from androidemu.cpu.interrupt_handler import InterruptHandler
from androidemu.cpu.syscall_handlers import SyscallHandlers
from androidemu.cpu.syscall_hooks import SyscallHooks
from androidemu.cpu.syscall_hooks_memory import SyscallHooksMemory
from androidemu.hooker import Hooker
from androidemu.internal.modules import Modules
from androidemu.java.helpers.native_method import native_write_args
from androidemu.java.java_classloader import JavaClassLoader
from androidemu.java.java_vm import JavaVM
from androidemu.memory import STACK_ADDR, STACK_SIZE, HOOK_MEMORY_BASE, HOOK_MEMORY_SIZE
from androidemu.memory.memory_manager import MemoryManager
from androidemu.native.hooks import NativeHooks
from androidemu.tracer import Tracer
from androidemu.utils.memory_helpers import write_utf8
from androidemu.vfs.file_system import VirtualFileSystem

logger = logging.getLogger(__name__)


class Emulator:
    """
    :type uc Uc
    :type modules Modules
    """
    def __init__(self, vfs_root: str = None, vfp_inst_set: bool = False):
        # Unicorn.
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        if vfp_inst_set:
            self._enable_vfp()

        # Android
        self.system_properties = {"libc.debug.malloc.options": ""}

        # Stack.
        self.uc.mem_map(STACK_ADDR, STACK_SIZE)
        self.uc.reg_write(UC_ARM_REG_SP, STACK_ADDR + STACK_SIZE)

        # Executable data.
        self.modules = Modules(self)
        self.memory_manager = MemoryManager(self.uc)

        # CPU
        self.interrupt_handler = InterruptHandler(self.uc)
        self.syscall_handler = SyscallHandlers(self.interrupt_handler)
        self.syscall_hooks = SyscallHooks(self.uc, self.syscall_handler, self.modules)
        self.syscall_hooks_memory = SyscallHooksMemory(self.uc, self.memory_manager, self.syscall_handler)

        # File System
        if vfs_root is not None:
            self.vfs = VirtualFileSystem(vfs_root, self.syscall_handler)
        else:
            self.vfs = None

        # Hooker
        self.uc.mem_map(HOOK_MEMORY_BASE, HOOK_MEMORY_SIZE)
        self.hooker = Hooker(self, HOOK_MEMORY_BASE, HOOK_MEMORY_SIZE)

        # JavaVM
        self.java_classloader = JavaClassLoader()
        self.java_vm = JavaVM(self, self.java_classloader, self.hooker)

        # Native
        self.native_hooks = NativeHooks(self, self.memory_manager, self.modules, self.hooker)

        # Tracer
        self.tracer = Tracer(self.uc, self.modules)

        # Thread.
        self._setup_thread_register()

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
            self.uc.mem_map(address, mem_size)
            self.uc.mem_write(address, code_bytes)
            self.uc.reg_write(UC_ARM_REG_SP, address + mem_size)

            self.uc.emu_start(address | 1, address + len(code_bytes))
        finally:
            self.uc.mem_unmap(address, mem_size)

    def _setup_thread_register(self):
        """
        Set up thread register.
        This is currently not accurate and just filled with garbage to ensure the emulator does not crash.

        https://developer.arm.com/documentation/ddi0211/k/system-control-coprocessor/system-control-coprocessor-register-descriptions/c13--thread-and-process-id-registers
        """
        thread_info_size = 64
        thread_info = self.memory_manager.allocate(thread_info_size * 5)

        thread_info_1 = thread_info + (thread_info_size * 0)
        thread_info_2 = thread_info + (thread_info_size * 1)
        thread_info_3 = thread_info + (thread_info_size * 2)
        thread_info_4 = thread_info + (thread_info_size * 3)
        thread_info_5 = thread_info + (thread_info_size * 4)

        # Thread name
        write_utf8(self.uc, thread_info_5, "AndroidNativeEmu")

        # R4
        self.uc.mem_write(thread_info_2 + 0x4, int(thread_info_5).to_bytes(4, byteorder='little'))
        self.uc.mem_write(thread_info_2 + 0xC, int(thread_info_3).to_bytes(4, byteorder='little'))

        # R1
        self.uc.mem_write(thread_info_1 + 0x4, int(thread_info_4).to_bytes(4, byteorder='little'))
        self.uc.mem_write(thread_info_1 + 0xC, int(thread_info_2).to_bytes(4, byteorder='little'))
        self.uc.reg_write(UC_ARM_REG_C13_C0_3, thread_info_1)

    def load_library(self, filename, do_init=True):
        libmod = self.modules.load_module(filename)
        if do_init:
            logger.debug("Calling init for: %s " % filename)
            for fun_ptr in libmod.init_array:
                logger.debug("Calling init function: %x " % fun_ptr)
                self.call_native(fun_ptr, 0, 0, 0)
        return libmod

    def call_symbol(self, module, symbol_name, *argv, is_return_jobject=True):
        symbol = module.find_symbol(symbol_name)

        if symbol is None:
            logger.error('Unable to find symbol \'%s\' in module \'%s\'.' % (symbol_name, module.filename))
            return

        return self.call_native(symbol.address, *argv, is_return_jobject=is_return_jobject)

    def call_native(self, addr, *argv, is_return_jobject=True):
        # Detect JNI call
        is_jni = False

        if len(argv) >= 1:
            is_jni = argv[0] == self.java_vm.address_ptr or argv[0] == self.java_vm.jni_env.address_ptr

        # TODO: Write JNI args to local ref table if jni.

        try:
            # Execute native call.
            self.uc.reg_write(UC_ARM_REG_SP, STACK_ADDR + STACK_SIZE)
            native_write_args(self, *argv)
            stop_pos = randint(HOOK_MEMORY_BASE, HOOK_MEMORY_BASE + HOOK_MEMORY_SIZE) | 1
            self.uc.reg_write(UC_ARM_REG_LR, stop_pos)
            self.uc.emu_start(addr, stop_pos - 1)

            # Read result from locals if jni.
            if is_jni and is_return_jobject:
                result_idx = self.uc.reg_read(UC_ARM_REG_R0)
                result = self.java_vm.jni_env.get_local_reference(result_idx)

                if result is None:
                    return result

                return result.value
            else:
                return self.uc.reg_read(UC_ARM_REG_R0)
        finally:
            # Clear locals if jni.
            if is_jni:
                self.java_vm.jni_env.clear_locals()

    def dump(self, out_dir):
        os.makedirs(out_dir)

        for begin, end, prot in [reg for reg in self.uc.mem_regions()]:
            filename = "{:#010x}-{:#010x}.bin".format(begin, end)
            pathname = os.path.join(out_dir, filename)
            with open(pathname, "w") as f:
                f.write(hexdump.hexdump(self.uc.mem_read(begin, end - begin), result='return'))
