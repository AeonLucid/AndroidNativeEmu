from unicorn import Uc
from androidemu.cpu.syscall_handlers import SyscallHandlers


class NativeMemory:

    """
    :type mu Uc
    :type syscall_handler SyscallHandlers
    """
    def __init__(self, mu, memory_base, memory_size, syscall_handler):
        self._mu = mu
        self._memory_base = memory_base
        self._memory_current = memory_base
        self._memory_size = memory_size
        self._syscall_handler = syscall_handler
        self._syscall_handler.set_handler(0x7D, "mprotect", 6, self._handle_mmap2)
        self._syscall_handler.set_handler(0xC0, "mmap2", 6, self._handle_mmap2)
        self._syscall_handler.set_handler(0xDC, "madvise", 3, self._handle_madvise)

    def allocate(self, length, prot=7):
        alloc_base = self._memory_current

        if alloc_base + length > self._memory_base + self._memory_size:
            raise OverflowError("Our native memory is overflowing..")

        self._mu.mem_map(alloc_base, length, perms=prot)
        self._memory_current += length

        return alloc_base

    def _handle_mmap2(self, mu, addr, length, prot, flags, fd, offset):
        """
        void *mmap2(void *addr, size_t length, int prot, int flags, int fd, off_t pgoffset);
        """
        return self.allocate(length, prot=prot)

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
        if addr < self._memory_base and addr + len_in > self._memory_base + self._memory_size:
            raise RuntimeError("Tried to protect memory not in the native range..")

        self._mu.mem_protect(addr, len_in, perms=prot)
        return 0
