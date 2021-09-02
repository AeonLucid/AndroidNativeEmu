PF_X = 0x1  # Executable
PF_W = 0x2  # Writable
PF_R = 0x4  # Readable


def get_segment_protection(prot_in):
    prot = 0

    if (prot_in & PF_R) != 0:
        prot |= 1

    if (prot_in & PF_W) != 0:
        prot |= 2

    if (prot_in & PF_X) != 0:
        prot |= 4

    return prot
