import logging

from androidemu import config
from androidemu.internal import align

logger = logging.getLogger(__name__)


class Memory:

    """
    :type emu androidemu.emulator.Emulator
    """
    def __init__(self, emu):
        self.emu = emu
        self.counter_memory = config.BASE_ADDR
        self.counter_stack = config.STACK_ADDR + config.STACK_SIZE

    def mem_reserve(self, size):
        (_, size_aligned) = align(0, size, True)
        ret = self.counter_memory
        self.counter_memory += size_aligned
        return ret

    def mem_map(self, address, size, prot):
        (address, size) = align(address, size, True)

        self.emu.mu.mem_map(address, size, prot)

        logger.debug("=> Mapping memory page 0x%08x - 0x%08x, size 0x%08x, prot %s" % (address, address + size, size,
                                                                                       prot))

    def mem_write(self, address, data):
        self.emu.mu.mem_write(address, data)

    def mem_read(self, address, size):
        return self.emu.mu.mem_read(address, size)


