from collections import OrderedDict

from unicorn import *

PAGE_SIZE = 0x1000
MAX_ALLOWABLE_SEG_SIZE = 1024 * 1024 * 1024


class UnicornSimpleHeap:

    def __init__(self, uc: Uc, heap_min_addr, heap_max_addr):
        self._uc = uc
        self._heap_min_addr = heap_min_addr
        self._heap_max_addr = heap_max_addr
        self._blocks = OrderedDict()

    def map(self, size, prot=UC_PROT_READ | UC_PROT_WRITE):
        if size <= 0:
            raise Exception('Heap map size was <= 0.')

        data_addr = None
        data_size = self.align_page_up(size)

        available_start = None
        available_size = 0

        # Find empty space big enough for data_size.
        for addr in range(self._heap_min_addr, self._heap_max_addr, PAGE_SIZE):
            if addr in self._blocks:
                available_start = None
                available_size = 0
                continue

            if available_start is None:
                available_start = addr

            available_size = available_size + PAGE_SIZE

            if available_size == data_size:
                data_addr = available_start
                break

        # Check if nothing was found.
        if data_addr is None:
            raise Exception('Failed to mmap memory.')

        # Reserve.
        for addr in range(data_addr, data_addr + data_size, PAGE_SIZE):
            self._blocks[addr] = 1

        # Actually map in emulator.
        self._uc.mem_map(data_addr, data_size, perms=prot)

        return data_addr

    def protect(self, addr, len_in, prot):
        if not self.is_multiple(addr):
            raise Exception('addr was not multiple of page size (%d, %d).' % (addr, PAGE_SIZE))

        if not self.is_multiple(len_in):
            raise Exception('len_in was not multiple of page size (%d, %d).' % (addr, PAGE_SIZE))

        for addr_in in range(addr, addr + len_in - 1, PAGE_SIZE):
            if addr_in in self._blocks:
                self._uc.mem_protect(addr_in, len_in, prot)

        return True

    def unmap(self, addr, size):
        if not self.is_multiple(addr):
            raise Exception('addr was not multiple of page size (%d, %d).' % (addr, PAGE_SIZE))

        for addr_in in range(addr, self.align_page_up(addr + size), PAGE_SIZE):
            if addr_in in self._blocks:
                self._uc.mem_unmap(addr_in, PAGE_SIZE)
                self._blocks.pop(addr_in)
            else:
                raise Exception('Attempted to unmap memory that was not mapped.')

        return True

    @staticmethod
    def is_multiple(addr):
        return addr % PAGE_SIZE == 0

    @staticmethod
    def align_page_up(size):
        return (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)

    @staticmethod
    def align_page_down(size):
        return size & ~(PAGE_SIZE - 1)
