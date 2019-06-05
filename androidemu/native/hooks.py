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
        modules.add_symbol_hook('dladdr', hooker.write_function(self.nop('dladdr')) + 1)
        modules.add_symbol_hook('dlsym', hooker.write_function(self.nop('dlsym')) + 1)
        modules.add_symbol_hook('dlopen', hooker.write_function(self.nop('dlopen')) + 1)
        modules.add_symbol_hook('pthread_create', hooker.write_function(self.nop('pthread_create')) + 1)
        modules.add_symbol_hook('pthread_join', hooker.write_function(self.nop('pthread_join')) + 1)
        modules.add_symbol_hook('vfprintf', hooker.write_function(self.nop('vfprintf')) + 1)
        modules.add_symbol_hook('fprintf', hooker.write_function(self.nop('fprintf')) + 1)

    @native_method
    def system_property_get(self, uc, name_ptr, buf_ptr):
        name = memory_helpers.read_utf8(uc, name_ptr)
        logger.debug("Called __system_property_get(%s, 0x%x)" % (name, buf_ptr))

        if name in self._emu.system_properties:
            memory_helpers.write_utf8(uc, buf_ptr, self._emu.system_properties[name])
        else:
            raise ValueError('%s was not found in system_properties dictionary.' % name)

        return None

    def nop(self, name):
        @native_method
        def nop_inside(emu):
            raise NotImplementedError('Symbol hook not implemented %s' % name)
        return nop_inside
