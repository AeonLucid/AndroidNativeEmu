import logging
import posixpath
import sys

from unicorn import UcError, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED, Uc, UC_PROT_ALL
from unicorn.arm_const import *

from androidemu.emulator import Emulator
from androidemu.java.helpers.native_method import native_method
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def

from samples import debug_utils


class XGorgen(metaclass=JavaClassDef, jvm_name='com/ss/sys/ces/a'):
    def __init__(self):
        pass

    @java_method_def(name='leviathan', signature='(I[B)[B', native=True)
    def leviathan(self, mu):
        pass

    def test(self):
        pass


class secuni_b(metaclass=JavaClassDef, jvm_name='com/ss/sys/secuni/b/c'):
    def __init__(self):
        pass

    @java_method_def(name='n0', signature='(Landroid/content/Context;)[B', native=True)
    def n0(self, mu):
        pass

    @java_method_def(name='n1', signature='(Landroid/content/Context;Ljava/lang/String;)I', native=True)
    def n1(self, mu):
        pass


class UserInfo(metaclass=JavaClassDef, jvm_name='com/ss/android/common/applog/UserInfo'):
    def __init__(self):
        pass


class java_lang_System(metaclass=JavaClassDef, jvm_name='java/lang/System'):
    def __init__(self):
        pass

    @java_method_def(name='getProperty', args_list=["jstring"], signature='(Ljava/lang/String;)Ljava/lang/String;',
                     native=False)
    def getProperty(self, *args, **kwargs):
        print(args[0].value)
        return "2.1.0"


class java_lang_StackTraceElement(metaclass=JavaClassDef, jvm_name='java/lang/StackTraceElement'):
    def __init__(self, _name):
        self.name = _name

    @java_method_def(native=False, name='getClassName', signature="()Ljava/lang/String;")
    def getClassName(self, *args, **kwargs):
        return self.name


class java_lang_Thread(metaclass=JavaClassDef, jvm_name='java/lang/Thread'):
    def __init__(self):
        pass

    @java_method_def(name="currentThread", signature='()Ljava/lang/Thread;', native=False)
    def currentThread(self, *args, **kwargs):
        return java_lang_Thread()

    @java_method_def(name="getStackTrace", signature='()[Ljava/lang/StackTraceElement;', native=False)
    def getStackTrace(self, *args, **kwargs):
        return [java_lang_StackTraceElement("dalvik.system.VMStack"),
                java_lang_StackTraceElement("java.lang.Thread"),
                java_lang_StackTraceElement("com.ss.sys.ces.a"),
                java_lang_StackTraceElement("com.yf.douyintool.MainActivity"),
                java_lang_StackTraceElement("java.lang.reflect.Method"),
                java_lang_StackTraceElement("java.lang.reflect.Method"),
                java_lang_StackTraceElement("android.support.v7.app.AppCompatViewInflater$DeclaredOnClickListener"),
                java_lang_StackTraceElement("android.view.View"),
                java_lang_StackTraceElement("android.os.Handler"),
                java_lang_StackTraceElement("android.os.Handler"),
                java_lang_StackTraceElement("android.os.Looper"),
                java_lang_StackTraceElement("android.app.ActivityThread"),
                java_lang_StackTraceElement("java.lang.reflect.Method"),
                java_lang_StackTraceElement("java.lang.reflect.Method"),
                java_lang_StackTraceElement("com.android.internal.os.ZygoteInit$MethodAndArgsCaller"),
                java_lang_StackTraceElement("com.android.internal.os.ZygoteInit"),
                java_lang_StackTraceElement("dalvik.system.NativeStart")
                ]


# Configure logging
logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)7s %(name)34s | %(message)s"
)

logger = logging.getLogger(__name__)

# Initialize emulator
emulator = Emulator(
    vfp_inst_set=True,
    vfs_root=posixpath.join(posixpath.dirname(__file__), "vfs")
)

# Register Java class.
# emulator.java_classloader.add_class(MainActivity)
emulator.java_classloader.add_class(XGorgen)
emulator.java_classloader.add_class(secuni_b)
emulator.java_classloader.add_class(UserInfo)
emulator.java_classloader.add_class(java_lang_System)
emulator.java_classloader.add_class(java_lang_Thread)
emulator.java_classloader.add_class(java_lang_StackTraceElement)

# Load all libraries.
emulator.load_library("./example_binaries/libdl.so")
emulator.load_library("./example_binaries/libc.so")
emulator.load_library("./example_binaries/libstdc++.so")
emulator.load_library("./example_binaries/libm.so")
lib_module = emulator.load_library("./example_binaries/libcms.so")

# Show loaded modules.
logger.info("Loaded modules:")

for module in emulator.modules:
    logger.info("=> 0x%08x - %s" % (module.base, module.filename))

# Debug
# emulator.mu.hook_add(UC_HOOK_CODE, debug_utils.hook_code)
emulator.mu.hook_add(UC_HOOK_MEM_UNMAPPED, debug_utils.hook_unmapped)
# emulator.mu.hook_add(UC_HOOK_MEM_WRITE, debug_utils.hook_mem_write)
# emulator.mu.hook_add(UC_HOOK_MEM_READ, debug_utils.hook_mem_read)

try:
    # Run JNI_OnLoad.
    #   JNI_OnLoad will call 'RegisterNatives'.
    emulator.call_symbol(lib_module, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0x00)

    # bypass douyin checks
    with open("./misc/app_process32", 'rb') as ap:
        data = ap.read()
        len1 = len(data) + 1024 - (len(data) % 1024)
        emulator.mu.mem_map(0xab006000, len1)
        emulator.mu.mem_write(0xab006000, data)

    x = XGorgen()
    data = 'acde74a94e6b493a3399fac83c7c08b35D58B21D9582AF77647FC9902E36AE70f9c001e9334e6e94916682224fbe4e5f00000000000000000000000000000000'
    data = bytearray(bytes.fromhex(data))
    result = x.leviathan(emulator, 1562848170, data)

    print(''.join(['%02x' % b for b in result]))
    # 037d560d0000903e34fb093f1d21e78f3bdf3fbebe00b124becc
    # 036d2a7b000010f4d05395b7df8b0ec2b5ec085b938a473a6a51
    # 036d2a7b000010f4d05395b7df8b0ec2b5ec085b938a473a6a51

    # 0300000000002034d288fe8d6b95b778105cc36eade709d2b500
    # 0300000000002034d288fe8d6b95b778105cc36eade709d2b500
    # 0300000000002034d288fe8d6b95b778105cc36eade709d2b500
    # Dump natives found.

#  for method in MainActivity.jvm_methods.values():
#      if method.native:
#         logger.info("- [0x%08x] %s - %s" % (method.native_addr, method.name, method.signature))
except UcError as e:
    print("Exit at %x" % emulator.mu.reg_read(UC_ARM_REG_PC))
    raise
