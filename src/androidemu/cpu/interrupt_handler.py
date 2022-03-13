import logging

from unicorn import *
from unicorn.arm_const import *

logger = logging.getLogger(__name__)


class InterruptHandler:

    """
    :type uc Uc
    """
    def __init__(self, uc):
        self._uc = uc
        self._uc.hook_add(UC_HOOK_INTR, self._hook_interrupt)
        self._handlers = dict()

    def _hook_interrupt(self, uc, intno, data):
        if intno in self._handlers:
            self._handlers[intno](uc)
        else:
            logger.error("Unhandled interrupt %d at %x, stopping emulation" % (intno, self._uc.reg_read(UC_ARM_REG_PC)))
            self._uc.emu_stop()

    def set_handler(self, intno, handler):
        self._handlers[intno] = handler
