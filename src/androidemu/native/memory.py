from unicorn import Uc, UC_PROT_READ, UC_PROT_WRITE
from androidemu.cpu.syscall_handlers import SyscallHandlers
from androidemu.native.memory_heap import UnicornSimpleHeap


class NativeMemory:

    """
    :type mu Uc
    :type syscall_handler SyscallHandlers
    """
    def __init__(self, mu, memory_base, memory_size, syscall_handler):
        self._mu = mu
        self._heap = UnicornSimpleHeap(mu, memory_base, memory_base + memory_size)
        self._memory_base = memory_base
        self._memory_current = memory_base
        self._memory_size = memory_size
        self._syscall_handler = syscall_handler
        self._syscall_handler.set_handler(0x5B, "munmap", 2, self._handle_munmap)
        self._syscall_handler.set_handler(0x7D, "mprotect", 3, self._handle_mprotect)
        self._syscall_handler.set_handler(0xC0, "mmap2", 6, self._handle_mmap2)
        self._syscall_handler.set_handler(0xDC, "madvise", 3, self._handle_madvise)

    def allocate(self, length, prot=UC_PROT_READ | UC_PROT_WRITE):
        return self._heap.map(length, prot)

    def free(self, addr, length):
        self._heap.unmap(addr, length)

    def _handle_munmap(self, uc, addr, len_in):
        self._heap.unmap(addr, len_in)

    def _handle_mmap2(self, mu, addr, length, prot, flags, fd, offset):
        """
        void *mmap2(void *addr, size_t length, int prot, int flags, int fd, off_t pgoffset);
        """

        # MAP_FILE	    0
        # MAP_SHARED	0x01
        # MAP_PRIVATE	0x02
        # MAP_FIXED	    0x10
        # MAP_ANONYMOUS	0x20

        return self._heap.map(length, prot)

    def _handle_madvise(self, mu, start, len_in, behavior):
        """
        int madvise(void *addr, size_t length, int advice);
        The kernel is free to ignore the advice.
        On success madvise() returns zero. On error, it returns -1 and errno is set appropriately.
        """
        # We don't need your advise.
        return 0

    def _handle_mprotect(self, mu, addr, len_in, prot):
        """
        int mprotect(void *addr, size_t len, int prot);

        mprotect() changes protection for the calling process's memory page(s) containing any part of the address
        range in the interval [addr, addr+len-1]. addr must be aligned to a page boundary.
        """
        self._heap.protect(addr, len_in, prot)
        return 0
