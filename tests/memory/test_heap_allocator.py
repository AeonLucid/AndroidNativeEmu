import unittest

from androidemu.memory.heap_allocator import HeapAllocator

HEAP_START = 0x1000
HEAP_END = 0x2000


class TestHeapAllocator(unittest.TestCase):

    def test_allocate(self):
        heap = HeapAllocator(HEAP_START, HEAP_END)

        self.assertEqual(HEAP_START, heap.allocate(32))
        self.assertEqual(HEAP_START + 32, heap.allocate(32))
        self.assertEqual(HEAP_START + 64, heap.allocate(32))

    def test_allocate_with_simple_free(self):
        heap = HeapAllocator(HEAP_START, HEAP_END)

        self.assertEqual(HEAP_START, heap.allocate(32))
        self.assertEqual(HEAP_START + 32, heap.allocate(32))
        self.assertEqual(HEAP_START + 64, heap.allocate(32))

        # Free block in the middle.
        heap.free(HEAP_START + 32)

        # Expect allocation to take the middle block.
        self.assertEqual(HEAP_START + 32, heap.allocate(32))

        # Expect allocation to create a new block.
        self.assertEqual(HEAP_START + 96, heap.allocate(32))
