import logging
import sys
import posixpath

from unicorn import UC_HOOK_CODE, UcError
from unicorn.arm_const import *

import debug_utils
from androidemu.emulator import Emulator
from androidemu.java.helpers.java_class_def import JavaClassDef


# Create java class.
class MainActivity(metaclass=JavaClassDef, jvm_name='local/myapp/testnativeapp/MainActivity'):

    def __init__(self):
        pass


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
emulator.java_classloader.add_class(MainActivity)

# Load all libraries.
emulator.load_library("example_binaries/libdl.so")
emulator.load_library("example_binaries/libc.so")
emulator.load_library("example_binaries/libstdc++.so")
emulator.load_library("example_binaries/libm.so")
base_address = emulator.load_library("example_binaries/libnative-lib_jni.so")

# Show loaded modules.
logger.info("Loaded modules:")

for module in emulator.modules:
    logger.info("=> 0x%08x - %s" % (module.base_addr, module.filename))

# Debug
# emulator.mu.hook_add(UC_HOOK_CODE, debug_utils.hook_code)
# emulator.mu.hook_add(UC_HOOK_MEM_UNMAPPED, debug_utils.hook_unmapped)
# emulator.mu.hook_add(UC_HOOK_MEM_WRITE, debug_utils.hook_mem_write)
# emulator.mu.hook_add(UC_HOOK_MEM_READ, debug_utils.hook_mem_read)

# Prepare registers for JNI_OnLoad.
emulator.mu.reg_write(UC_ARM_REG_R0, emulator.java_vm.address_ptr)  # JavaVM* vm
emulator.mu.reg_write(UC_ARM_REG_R1, 0x00)  # void* reserved

# Run JNI_OnLoad.
try:
    emulator.mu.emu_start(base_address + 0x7DEC + 1, base_address + 0x7EEA)

    # Dump natives found.
    logger.info("Exited EMU.")
    logger.info("Native methods registered to MainActivity:")

    for (name, sig, ptr) in MainActivity.jvm_natives:
        logger.info("- [0x%08x] %s - %s" % (ptr, name, sig))
except UcError as e:
    print("Exit at %x" % emulator.mu.reg_read(UC_ARM_REG_PC))
    raise

