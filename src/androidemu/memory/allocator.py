class AllocatorError(Exception):
    pass


class HeapAllocatorError(AllocatorError):
    pass


class IncrementalAllocatorError(AllocatorError):
    pass
