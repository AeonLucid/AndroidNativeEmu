from androidemu import config
from androidemu.internal import align


class Memory:

    """
    :type emu androidemu.emulator.Emulator
    """
    def __init__(self, emu):
        self.emu = emu
        self.counter_memory = config.BASE_ADDR
        self.counter_stack = config.STACK_ADDR + config.STACK_SIZE

    def mem_reserve(self, size):
        ret = self.counter_memory
        self.counter_memory += size
        return ret

    def mem_map(self, address, size, prot):
        (address, size) = align(address, size, True)

        self.emu.mu.mem_map(address, size, prot)

        print("Mapping memory page on addr %02x - %02x size %02x prot %s" % (address, address + size, size, prot))

    def mem_write(self, address, data):
        self.emu.mu.mem_write(address, data)
