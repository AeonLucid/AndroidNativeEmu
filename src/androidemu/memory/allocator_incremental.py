from androidemu.memory import align
from androidemu.memory.allocator import IncrementalAllocatorError


class IncrementalAllocator:
    """
    Distributes memory using a simple increment.
    It is assumed that the memory region is not mapped before hand.

    This is mostly used for loading modules.
    """

    def __init__(self, start: int, end: int):
        self._pos = start
        self._end = end

    def reserve(self, size) -> (int, int):
        """
        Returns an Unicorn page aligned mapping.
        """
        (_, size_aligned) = align(0, size, True)
        ret = self._pos
        self._pos += size_aligned

        if self._pos > self._end:
            raise IncrementalAllocatorError("Reserve went out of bounds")

        return ret, size_aligned
