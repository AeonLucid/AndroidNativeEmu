from abc import ABC, abstractmethod

from unicorn import Uc


class MemoryAccess(ABC):

    def __init__(self, uc: Uc):
        self._uc = uc

    def write(self, addr: int, data):
        self._uc.mem_write(addr, data)

    @abstractmethod
    def write_u8(self, addr: int, value: int):
        pass

    @abstractmethod
    def write_u16(self, addr: int, value: int):
        pass

    @abstractmethod
    def write_u32(self, addr: int, value: int):
        pass

    @abstractmethod
    def write_u64(self, addr: int, value: int):
        pass

    def _write_int(self, addr, value, byte_count):
        self._uc.mem_write(addr, value.to_bytes(byte_count, byteorder='little'))


class MemoryAccess32(MemoryAccess):

    def __init__(self, uc: Uc):
        super().__init__(uc)

    def write_u8(self, addr: int, value: int):
        self._write_int(addr, value, 1)

    def write_u16(self, addr: int, value: int):
        self._write_int(addr, value, 2)

    def write_u32(self, addr: int, value: int):
        self._write_int(addr, value, 4)

    def write_u64(self, addr: int, value: int):
        self._write_int(addr, value, 8)


class MemoryAccess64(MemoryAccess):

    def __init__(self, uc: Uc):
        super().__init__(uc)

    def write_u8(self, addr: int, value: int):
        self._write_int(addr, value, 1)

    def write_u16(self, addr: int, value: int):
        self._write_int(addr, value, 2)

    def write_u32(self, addr: int, value: int):
        self._write_int(addr, value, 4)

    def write_u64(self, addr: int, value: int):
        self._write_int(addr, value, 8)
