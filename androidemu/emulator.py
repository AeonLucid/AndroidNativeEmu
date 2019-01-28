from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM
from unicorn.arm_const import UC_ARM_REG_SP

from androidemu import config
from androidemu.hooker import Hooker
from androidemu.internal.memory import Memory
from androidemu.internal.modules import Modules
from androidemu.java.java_vm import JavaVM
from androidemu.native.hooks import NativeHooks
from androidemu.native.memory import NativeMemory


class Emulator:

    """
    :type mu Uc
    :type modules Modules
    :type memory Memory
    """
    def __init__(self):
        # Unicorn.
        self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        # Stack.
        self.mu.mem_map(config.STACK_ADDR, config.STACK_SIZE)
        self.mu.reg_write(UC_ARM_REG_SP, config.STACK_ADDR + config.STACK_SIZE)

        # Executable data.
        self.modules = Modules(self)
        self.memory = Memory(self)

        # Hooker
        self.mu.mem_map(config.MEMORY_BASE, config.MEMORY_SIZE)
        self.hooker = Hooker(self.mu, config.MEMORY_BASE, config.MEMORY_SIZE)

        # JavaVM
        self.java_vm = JavaVM(self.hooker)

        # Native
        self.native_memory = NativeMemory(config.MEMORY_BASE, config.MEMORY_SIZE)
        self.native_hooks = NativeHooks(self.native_memory, self.modules, self.hooker)

    def load_library(self, filename):
        return self.modules.load_module(filename)
