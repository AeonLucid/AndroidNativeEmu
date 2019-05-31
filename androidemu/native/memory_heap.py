from unicorn import *
from unicorn.arm64_const import *

# Page size required by Unicorn
UNICORN_PAGE_SIZE = 0x1000

# Max allowable segment size (1G)
MAX_ALLOWABLE_SEG_SIZE = 1024 * 1024 * 1024

# Alignment functions to align all memory segments to Unicorn page boundaries (4KB pages only)
ALIGN_PAGE_DOWN = lambda x: x & ~(UNICORN_PAGE_SIZE - 1)
ALIGN_PAGE_UP = lambda x: (x + UNICORN_PAGE_SIZE - 1) & ~(UNICORN_PAGE_SIZE-1)


# Implementation from
# https://github.com/Battelle/afl-unicorn/blob/44a50c8a9426ffe4ad8714ef8a35dc011e62f739/unicorn_mode/helper_scripts/unicorn_loader.py#L45
class UnicornSimpleHeap:
    """ Use this class to provide a simple heap implementation. This should
        be used if malloc/free calls break things during emulation.
    """

    # Helper data-container used to track chunks
    class HeapChunk(object):
        def __init__(self,  data_addr, data_size):
            self.data_addr = data_addr
            self.data_size = data_size

        # Returns true if the specified buffer is completely within the chunk, else false
        def is_buffer_in_chunk(self, addr, size):
            if addr >= self.data_addr and ((addr + size) <= (self.data_addr + self.data_size)):
                return True
            else:
                return False

    _uc = None              # Unicorn engine instance to interact with
    _chunks = []            # List of all known chunks
    _debug_print = False    # True to print debug information

    def __init__(self, uc, heap_min_addr, heap_max_addr, debug_print=False):
        self._uc = uc
        self._heap_min_addr = heap_min_addr
        self._heap_max_addr = heap_max_addr
        self._debug_print = debug_print

        # Add the watchpoint hook that will be used to implement psuedo-guard page support
        # self._uc.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, self.__check_mem_access)

    def malloc(self, size, prot=UC_PROT_READ | UC_PROT_WRITE):
        # Figure out the overall size to be allocated/mapped
        #    - Allocate at least 1 4k page of memory to make Unicorn happy
        data_size = ALIGN_PAGE_UP(size)
        # Gross but efficient way to find space for the chunk:
        chunk = None
        for addr in range(self._heap_min_addr, self._heap_max_addr, UNICORN_PAGE_SIZE):
            try:
                self._uc.mem_map(addr, data_size, prot)
                chunk = self.HeapChunk(addr, data_size)
                if self._debug_print:
                    print("Allocating 0x{0:x}-byte chunk @ 0x{1:016x}".format(chunk.data_size, chunk.data_addr))
                break
            except UcError as e:
                continue
        # Something went very wrong
        if chunk is None:
            raise Exception("Oh no.")
        self._chunks.append(chunk)
        return chunk.data_addr

    def calloc(self, size, count):
        # Simple wrapper around malloc with calloc() args
        return self.malloc(size * count)

    def realloc(self, ptr, new_size):
        # Wrapper around malloc(new_size) / memcpy(new, old, old_size) / free(old)
        if self._debug_print:
            print("Reallocating chunk @ 0x{0:016x} to be 0x{1:x} bytes".format(ptr, new_size))
        old_chunk = None
        for chunk in self._chunks:
            if chunk.data_addr == ptr:
                old_chunk = chunk
        new_chunk_addr = self.malloc(new_size)
        if old_chunk is not None:
            self._uc.mem_write(new_chunk_addr, str(self._uc.mem_read(old_chunk.data_addr, old_chunk.data_size)))
            self.free(old_chunk.data_addr)
        return new_chunk_addr

    def protect(self, addr, len_in, prot):
        for chunk in self._chunks:
            if chunk.is_buffer_in_chunk(addr, len_in):
                self._uc.mem_protect(chunk.data_addr, chunk.data_size, perms=prot)
                return True
        return False

    def free(self, addr):
        for chunk in self._chunks:
            if chunk.is_buffer_in_chunk(addr, 1):
                if self._debug_print:
                    print("Freeing 0x{0:x}-byte chunk @ 0x{0:016x}".format(chunk.data_addr, chunk.data_size))
                self._uc.mem_unmap(chunk.data_addr, chunk.data_size)
                self._chunks.remove(chunk)
                return True
        return False
