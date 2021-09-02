from typing import Optional

from unicorn import Uc, UC_PROT_READ, UC_PROT_WRITE

from androidemu.memory.allocator import HeapAllocatorError


class HeapBlock:
    next: Optional['HeapBlock']

    def __init__(self):
        self.address = 0
        self.size = 0
        self.free = False
        self.next = None


class HeapAllocator:
    """
    Distributes allocated memory using a simple malloc implementation.
    https://danluu.com/malloc-tutorial/
    """

    def __init__(self, start: int, end: int, uc: Uc = None):
        """
        :param int start: Start address of the heap.
        :param int end: End address of the heap.
        """
        self._start = start
        self._pos = start
        self._end = end
        self._head = None

        if uc is not None:
            self._init_uc(uc)

    def allocate(self, size: int) -> int:
        """
        :param int size: The amount of bytes to allocate.
        """
        if size <= 0:
            return 0

        block = None

        if self._head is None:
            block = self._create_block(size)
            self._head = block
        else:
            block, prev = self._find_free_block(size)

            if not block:
                block = self._create_block(size, prev)
            elif block.size != size:
                block = self._split_block(block, size)

            block.free = False

        return block.address

    def free(self, address: int):
        if address == 0:
            return

        block, prev = self._find_block(address)

        if block is None:
            raise HeapAllocatorError('Attempted to free non existing block at 0x%x' % address)

        block.free = True

        self._merge_block(block)
        self._merge_block(prev)

    def _create_block(self, size: int, last: HeapBlock = None) -> HeapBlock:
        """
        Create a block and add it to the end of the heap list.
        """
        # Create new block.
        block = HeapBlock()
        block.address = self._increment_data(size)
        block.size = size
        block.free = False
        block.next = None

        # Append to last block.
        if last is not None:
            last.next = block

        return block

    def _find_block(self, address: int) -> (Optional[HeapBlock], Optional[HeapBlock]):
        """
        Finds the block that was assigned to the given address.
        """
        prev = None
        block = self._head

        while block is not None and block.address != address:
            prev = block
            block = block.next

        return block, prev

    def _find_free_block(self, size: int) -> (Optional[HeapBlock], Optional[HeapBlock]):
        """
        Attempts to find a free block that can contain the requested size.
        """
        prev = None
        block = self._head

        while block is not None and not (block.free and block.size >= size):
            prev = block
            block = block.next

        return block, prev

    def _merge_block(self, block: HeapBlock):
        """
        Merges the given block and it's next block together if both are free.
        """
        if block is None:
            return

        if block.free and block.next is not None and block.next.free:
            block.size = block.size + block.next.size
            block.next = block.next.next

    def _split_block(self, block: HeapBlock, size: int) -> HeapBlock:
        """
        Splits a block into the requested size by making the given block smaller
        and appending the remainder as a new block.
        """
        if not block.free:
            raise HeapAllocatorError('Attempted to split non-free block')

        # Create new block.
        new_block = HeapBlock()
        new_block.address = block.address + size
        new_block.size = block.size - size
        new_block.free = True
        new_block.next = block.next

        # Assign the block as the next of the current block.
        block.next = new_block

        # Resize current block.
        block.size = size

        return block

    def _increment_data(self, size: int):
        """
        Increments the current pointer, which simulates the sbrk call.
        https://linux.die.net/man/2/sbrk
        """
        res = self._pos
        self._pos += size
        return res

    def _init_uc(self, uc: Uc):
        uc.mem_map(self._start, self._end - self._start, UC_PROT_READ | UC_PROT_WRITE)
