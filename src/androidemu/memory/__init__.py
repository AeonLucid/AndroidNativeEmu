import ctypes

# Memory addresses

STACK_ADDR = 0x10000000
STACK_SIZE = 0x00100000

HOOK_MEMORY_BASE = 0x20000000
HOOK_MEMORY_SIZE = 0x00200000

MODULES_MIN = 0xA0000000
MODULES_MAX = 0xC0000000

HEAP_MIN = 0xD0000000
HEAP_MAX = 0xD0200000

MAPPING_MIN = 0xE0000000
MAPPING_MAX = 0xF0000000

# Alignment
UC_MEM_ALIGN = 0x1000


def align(addr, size, growl):
    to = ctypes.c_uint64(UC_MEM_ALIGN).value
    mask = ctypes.c_uint64(0xFFFFFFFFFFFFFFFF).value ^ ctypes.c_uint64(to - 1).value
    right = addr + size
    right = (right + to - 1) & mask
    addr &= mask
    size = right - addr
    if growl:
        size = (size + to - 1) & mask
    return addr, size
