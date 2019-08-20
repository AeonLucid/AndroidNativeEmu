import logging

from unicorn import *

from androidemu.internal.modules import Modules

logger = logging.getLogger(__name__)


class Tracer:
    def __init__(self, uc: Uc, modules: Modules):
        self._uc = uc
        self._modules = modules

    def enable(self):
        self._uc.hook_add(UC_HOOK_BLOCK, self._hook_block)

    def _hook_block(self, uc: Uc, address, size, user_data):
        (name, symbol) = self._modules.find_symbol(address | 1)

        if symbol is not None:
            print(name)
