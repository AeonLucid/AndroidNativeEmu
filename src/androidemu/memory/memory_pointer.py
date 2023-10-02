from unicorn import Uc


class Pointer:

    def __init__(self, uc: Uc, address: int):
        self._uc = uc
        self._address = address

    def write_int(self, offset: int, value: int):
        self._uc.mem_write(self._address + offset, value.to_bytes(4, byteorder='little'))

    def read_int(self, offset: int) -> int:
        data = self._uc.mem_read(self._address + offset, 4)
        address = int.from_bytes(data, byteorder='little')

        return address

    def read_ptr(self, offset: int) -> 'Pointer':
        return Pointer(self._uc, self.read_int(offset))
