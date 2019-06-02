import logging

from androidemu.hooker import Hooker
from androidemu.native.memory import NativeMemory

from androidemu.java.helpers.native_method import native_method
from androidemu.utils import memory_helpers

logger = logging.getLogger(__name__)


class NativeHooks:
    """
    :type memory NativeMemory
    :type modules Modules
    :type hooker Hooker
    """

    def __init__(self, emu, memory, modules, hooker):
        self._emu = emu
        self._memory = memory
        self.atexit = []

        modules.add_symbol_hook('__system_property_get', hooker.write_function(self.system_property_get) + 1)
        modules.add_symbol_hook('pthread_create', hooker.write_function(self.pthread_create) + 1)
        modules.add_symbol_hook('fork', hooker.write_function(self.nop('fork')) + 1)
        modules.add_symbol_hook('vfork', hooker.write_function(self.nop('vfork')) + 1)
        modules.add_symbol_hook('dladdr', hooker.write_function(self.nop('dladdr')) + 1)
        modules.add_symbol_hook('dlsym', hooker.write_function(self.nop('dlsym')) + 1)
        modules.add_symbol_hook('tolower', hooker.write_function(self.tolower) + 1)
        modules.add_symbol_hook('strcmpi', hooker.write_function(self.nop('strcmpi')) + 1)

    @native_method
    def tolower(self, uc, charr):
        logger.debug("Called tolower(%s)" % chr(charr))
        return ord(chr(charr).lower())

    @native_method
    def system_property_get(self, uc, name_ptr, buf_ptr):
        name = memory_helpers.read_utf8(uc, name_ptr)
        logger.debug("Called __system_property_get(%s, 0x%x)" % (name, buf_ptr))

        if name in self._emu.system_properties:
            memory_helpers.write_utf8(uc, buf_ptr, self._emu.system_properties[name])
        else:
            raise ValueError('%s was not found in system_properties dictionary.' % name)

        return None

    @native_method
    def pthread_create(self, uc, thread_ptr, attr, start_ptr, arg_ptr):
        logger.debug("Called pthread_create(0x%x, 0x%x, 0x%x, 0x%x)" % (thread_ptr, attr, start_ptr, arg_ptr))

    def nop(self, name):
        @native_method
        def nop_inside(emu):
            raise NotImplementedError('Symbol hook not implemented %s' % name)
        return nop_inside
