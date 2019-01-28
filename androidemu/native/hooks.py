import logging

from androidemu.hooker import Hooker
from androidemu.native.memory import NativeMemory

from androidemu.java.helpers.native_method import native_method

logger = logging.getLogger(__name__)


class NativeHooks:

    """
    :type memory NativeMemory
    :type modules Modules
    :type hooker Hooker
    """
    def __init__(self, memory, modules, hooker):
        self._memory = memory

        modules.add_symbol_hook('malloc', hooker.write_function(self.malloc) + 1)
        modules.add_symbol_hook('memcpy', hooker.write_function(self.memcpy) + 1)

    @native_method
    def malloc(self, mu, size):
        # TODO: Actually reserve memory with checks.
        logger.warning("Application requested %d bytes." % size)
        return 0x10

    @native_method
    def memcpy(self, mu, dst, src, count):
        # TODO: Actually copy memory with checks.
        logger.warning("Application copies %d bytes from 0x%x to 0x%x." % (count, src, dst))
        return 0x10
