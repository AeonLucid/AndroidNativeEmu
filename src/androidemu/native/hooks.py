import logging
import os

from androidemu.hooker import Hooker
from androidemu.internal.modules import Modules
from androidemu.native.memory import NativeMemory

from androidemu.java.helpers.native_method import native_method, native_read_args
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
        self._modules = modules
        self.atexit = []

        modules.add_symbol_hook('__system_property_get', hooker.write_function(self.system_property_get) + 1)
        modules.add_symbol_hook('__android_log_print', hooker.write_function(self.android_log_print) + 1)
        modules.add_symbol_hook('dlopen', hooker.write_function(self.dlopen) + 1)
        modules.add_symbol_hook('dlclose', hooker.write_function(self.dlclose) + 1)
        modules.add_symbol_hook('dladdr', hooker.write_function(self.dladdr) + 1)
        modules.add_symbol_hook('dlsym', hooker.write_function(self.dlsym) + 1)
        modules.add_symbol_hook('vfprintf', hooker.write_function(self.vfprintf) + 1)
        modules.add_symbol_hook('pthread_create', hooker.write_function(self.nop('pthread_create')) + 1)
        modules.add_symbol_hook('pthread_join', hooker.write_function(self.nop('pthread_join')) + 1)
        modules.add_symbol_hook('fprintf', hooker.write_function(self.nop('fprintf')) + 1)
        modules.add_symbol_hook('dlerror', hooker.write_function(self.nop('dlerror')) + 1)

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
    def android_log_print(self, uc, log_level, log_tag_ptr, log_format_ptr):
        params_count = len(locals())
        log_tag = memory_helpers.read_utf8(uc, log_tag_ptr)
        fmt = memory_helpers.read_utf8(uc, log_format_ptr)

        args_type = []
        args_count = 0
        i = 0
        while i < len(fmt):
            if fmt[i] == '%':
                if fmt[i+1] in ['s', 'd', 'p']:
                    args_type.append(fmt[i+1])
                    args_count += 1
                    i += 1
            i += 1

        other_args = native_read_args(uc, params_count - 2 + args_count)[params_count-2:]
        args = []
        for i in range(args_count):
            if args_type[i] == 's':
                args.append(memory_helpers.read_utf8(uc, other_args[i]))
            elif args_type[i] == 'd' or args_type[i] == 'p':
                args.append(other_args[i])

        # python not support %p format
        fmt = fmt.replace('%p', '0x%x')
        logger.debug("Called __android_log_print(%d, %s, %s)" % (log_level, log_tag, fmt % tuple(args)))

        return None

    @native_method
    def dlopen(self, uc, path):
        path = memory_helpers.read_utf8(uc, path)
        logger.debug("Called dlopen(%s)" % path)

        if path == 'libvendorconn.so':
            lib = os.path.realpath(os.path.join(os.path.dirname(__file__), '..', 'libs', 'libvendorconn_32.so'))
            mod = self._emu.load_library(lib)

            return mod.base

        return None

    @native_method
    def dlclose(self, uc, handle):
        """
        The function dlclose() decrements the reference count on the dynamic library handle handle.
        If the reference count drops to zero and no other loaded libraries use symbols in it, then the dynamic library is unloaded.
        """
        logger.debug("Called dlclose(0x%x)" % handle)
        return 0

    @native_method
    def dladdr(self, uc, addr, info):
        logger.debug("Called dladdr(0x%x, 0x%x)" % (addr, info))

        infos = memory_helpers.read_uints(uc, info, 4)
        Dl_info = {}

        nm = self._emu.native_memory
        isfind = False
        for mod in self._modules.modules:
            if mod.base <= addr < mod.base + mod.size:
                dli_fname = nm.allocate(len(mod.filename) + 1)
                memory_helpers.write_utf8(uc, dli_fname, mod.filename + '\x00')
                memory_helpers.write_uints(uc, addr, [dli_fname, mod.base, 0, 0])
                return 1

    @native_method
    def dlsym(self, uc, handle, symbol):
        symbol_str = memory_helpers.read_utf8(uc, symbol)
        logger.debug("Called dlsym(0x%x, %s)" % (handle, symbol_str))

        if handle == 0xffffffff:
            sym = self._modules.find_symbol_name(symbol_str)
        else:
            module = self._modules.find_module(handle)

            if module is None:
                raise Exception('Module not found for address 0x%x' % symbol)

            sym = module.find_symbol(symbol)

        if sym is None:
            return 0

        raise NotImplementedError

    @native_method
    def vfprintf(self, uc, FILE, format, va_list):
        # int vfprintf ( FILE * stream, const char * format, va_list arg );
        struct_FILE = memory_helpers.read_byte_array(uc, FILE, 18)
        c_string = memory_helpers.read_utf8(uc, format)

        args = []
        result_string = ""
        for i in range(0,len(c_string)):
            if c_string[i] == '%':
                if c_string[i+1] == "d":
                    args.append(memory_helpers.read_uints(uc,va_list,1)[0])
                elif c_string[i+1] == "c":
                    args.append(chr(memory_helpers.read_byte_array(uc,va_list,1)[0]))
                elif c_string[i+1] == "s":
                    s_addr = memory_helpers.read_ptr(uc, va_list)
                    args.append(memory_helpers.read_cString(uc, s_addr)[0])
                else:
                    result_string += c_string[i:i+2]
                    # TODO more format support
                va_list += 4
                result_string += "{0["+str(len(args)-1)+"]}"
                continue
            if i>=1:
                if c_string[i-1] == '%' or c_string[i] == '%':
                    continue
            result_string += c_string[i]

        result_string = result_string.format(args)
        logger.debug("Called vfprintf(%r)" % result_string)


    def nop(self, name):
        @native_method
        def nop_inside(emu):
            raise NotImplementedError('Symbol hook not implemented %s' % name)
        return nop_inside
