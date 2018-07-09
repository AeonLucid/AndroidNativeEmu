import ctypes

UC_MEM_ALIGN = 0x1000

PF_X = 0x1  # Executable
PF_W = 0x2  # Writable
PF_R = 0x4  # Readable


# Thansk to https://github.com/lunixbochs/usercorn/blob/master/go/mem.go
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


def get_segment_protection(prot_in):
    prot = 0

    if prot_in & PF_R is not 0:
        prot |= 1

    if prot_in & PF_W is not 0:
        prot |= 2

    if prot_in & PF_X is not 0:
        prot |= 4

    return prot
