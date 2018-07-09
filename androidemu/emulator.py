from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM
from unicorn.arm_const import UC_ARM_REG_SP

from androidemu import config
from androidemu.internal.memory import Memory
from androidemu.internal.modules import Modules


class Emulator:

    """
    :type filename str
    :type mu Uc
    :type memory Memory
    """
    def __init__(self, filename):
        self.filename = filename

        # Initialize unicorn.
        self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        # Initialize stack.
        self.mu.mem_map(config.STACK_ADDR, config.STACK_SIZE)
        self.mu.reg_write(UC_ARM_REG_SP, config.STACK_ADDR + config.STACK_SIZE)

        self.modules = Modules(self)
        self.memory = Memory(self)

    def load(self):
        self.modules.load_module(self.filename)
