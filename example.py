from unicorn import UC_HOOK_CODE
from unicorn.arm_const import *

from androidemu.emulator import Emulator

# Initialize emulator
emulator = Emulator()
emulator.load_library("example_binaries/libc.so")
my_base = emulator.load_library("example_binaries/libnative-lib.so")

# Show loaded modules.
print("Loaded modules:")

for module in emulator.modules:
    print("[0x%x] %s" % (module.base_addr, module.filename))


# Add debugging.
def hook_code(mu, address, size, user_data):
    instruction = mu.mem_read(address, size)
    instruction_str = ''.join('{:02x} '.format(x) for x in instruction)

    print('# Tracing instruction at 0x%x, instruction size = 0x%x, instruction = %s' % (address, size, instruction_str))


emulator.mu.hook_add(UC_HOOK_CODE, hook_code)

# Runs a method of "libnative-lib.so" that calls an imported
# function "strlen" from "libc.so".
emulator.mu.emu_start(my_base + 0x7E6 + 1, my_base + 0x7EA)

print("String length is: %i" % emulator.mu.reg_read(UC_ARM_REG_R0))
