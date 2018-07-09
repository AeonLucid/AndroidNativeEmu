from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM

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
        self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        self.modules = Modules(self)
        self.memory = Memory(self)

    def load(self):
        self.modules.load_module(self.filename)
