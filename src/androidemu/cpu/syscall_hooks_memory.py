from unicorn import Uc
from androidemu.cpu.syscall_handlers import SyscallHandlers
from androidemu.memory.memory_manager import MemoryManager

from androidemu.memory import UC_MEM_ALIGN, align

class SyscallHooksMemory:

    def __init__(self, uc: Uc, memory: MemoryManager, syscall_handler: SyscallHandlers):
        self._uc = uc
        self._memory = memory
        self._syscall_handler = syscall_handler
        self._syscall_handler.set_handler(0x5B, "munmap", 2, self._handle_munmap)
        self._syscall_handler.set_handler(0x7D, "mprotect", 3, self._handle_mprotect)
        self._syscall_handler.set_handler(0xC0, "mmap2", 6, self._handle_mmap2)
        self._syscall_handler.set_handler(0xDC, "madvise", 3, self._handle_madvise)

    def _handle_munmap(self, uc, addr, len_in):
        self._memory.mapping_unmap(addr, len_in)

    def _handle_mmap2(self, uc, addr, length, prot, flags, fd, offset):
        """
        void *mmap2(void *addr, size_t length, int prot, int flags, int fd, off_t pgoffset);
        """

        # MAP_FILE	    0
        # MAP_SHARED	0x01
        # MAP_PRIVATE	0x02
        # MAP_FIXED	    0x10
        # MAP_ANONYMOUS	0x20

        if((flags & 0x10) != 0):
            if self._handle_mprotect(uc, addr, length, prot) == 0:
                return addr

            return -1
       
        return self._memory.mapping_map(length, prot)

    def _handle_madvise(self, uc, start, len_in, behavior):
        """
        int madvise(void *addr, size_t length, int advice);
        The kernel is free to ignore the advice.
        On success madvise() returns zero. On error, it returns -1 and errno is set appropriately.
        """
        # We don't need your advise.
        return 0

    def _handle_mprotect(self, uc, addr, len_in, prot):
        """
        int mprotect(void *addr, size_t len, int prot);

        mprotect() changes protection for the calling process's memory page(s) containing any part of the address
        range in the interval [addr, addr+len-1]. addr must be aligned to a page boundary.
        """

        addr2, len_in = align(addr, len_in, True)
        if addr2 != addr:
            return -1

        self._memory.mapping_protect(addr, len_in, prot)
        return 0
