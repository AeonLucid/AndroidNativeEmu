from unicorn import Uc

from androidemu.memory import *
from androidemu.memory.allocator_heap import HeapAllocator
from androidemu.memory.allocator_incremental import IncrementalAllocator


class MemoryManager:

    def __init__(self, uc: Uc):
        self._uc = uc
        self._heap = HeapAllocator(HEAP_MIN, HEAP_MAX, uc)
        self._modules = IncrementalAllocator(MODULES_MIN, MODULES_MAX)
        self._mappings = IncrementalAllocator(MAPPING_MIN, MAPPING_MAX)

    def allocate(self, size: int) -> int:
        """
        Allocate bytes on the heap.
        """
        return self._heap.allocate(size)

    def free(self, addr: int):
        """
        Free bytes on the heap.
        """
        self._heap.free(addr)

    def reserve_module(self, size) -> (int, int):
        """
        Reserve bytes for a module.
        The caller is responsible for mapping the address into Unicorn.
        """
        return self._modules.reserve(size)

    def mapping_map(self, size: int, prot: int) -> int:
        """
        Memory mapping for the mmap syscall.
        """
        (addr, size_aligned) = self._mappings.reserve(size)

        self._uc.mem_map(addr, size_aligned, prot)

        return addr

    def mapping_unmap(self, addr: int, size: int):
        """
        Memory unmapping for the unmap syscall.
        """
        if MAPPING_MIN <= addr <= MAPPING_MAX:
            self._uc.mem_unmap(addr, size)

    def mapping_protect(self, addr: int, size: int, prot: int):
        """
        Memory unmapping for the unmap syscall.
        """
        if MAPPING_MIN <= addr <= MAPPING_MAX:
            self._uc.mem_protect(addr, size, prot)
