from unicorn import Uc
from unicorn.arm_const import *


class ForkInfo:

    def __init__(self, uc: Uc, pid):
        self._uc = uc
        self._registers = dict()
        self.pid = pid

    def save_state(self):
        """
        We are forking, so save everything there is to save.
        """
        for i in range(UC_ARM_REG_INVALID, UC_ARM_REG_ENDING + 1):
            self._registers[i] = self._uc.reg_read(i)

    def load_state(self):
        for i in range(UC_ARM_REG_INVALID, UC_ARM_REG_ENDING + 1):
            self._uc.reg_write(i, self._registers[i])
