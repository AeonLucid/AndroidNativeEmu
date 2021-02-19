import hexdump
import struct


def hex_dump(mu, address, size):
    data = mu.mem_read(address, size)
    return hexdump.hexdump(data)


def read_ptr(mu, address):
    return int.from_bytes(mu.mem_read(address, 4), byteorder='little')


def read_byte_array(mu, address, size):
    return mu.mem_read(address, size)


def read_utf8(mu, address):
    buffer_address = address
    buffer_read_size = 32
    buffer = b""
    null_pos = None

    # Keep reading until we read something that contains a null terminator.
    while null_pos is None:
        buf_read = mu.mem_read(buffer_address, buffer_read_size)
        if b'\x00' in buf_read:
            null_pos = len(buffer) + buf_read.index(b'\x00')
        buffer += buf_read
        buffer_address += buffer_read_size

    return buffer[:null_pos].decode("utf-8")


def read_cString(mu, address):
    # read string null-terminated, return string and length
    buffer_address = address
    buffer_read_size = 1
    buffer = b""
    null_pos = None

    while null_pos is None:
        buf_read = mu.mem_read(buffer_address, buffer_read_size)
        if b'\x00' in buf_read:
            null_pos = len(buffer) + buf_read.index(b'\x00')
        buffer += buf_read
        buffer_address += buffer_read_size

    return buffer[:null_pos].decode("utf-8"),null_pos


def read_uints(mu, address, num=1):
    data = mu.mem_read(address, num * 4)
    return struct.unpack("I" * num, data)


def write_utf8(mu, address, value):
    mu.mem_write(address, value.encode(encoding="utf-8") + b"\x00")


def write_uints(mu, address, num):
    l = []
    if not isinstance(num, list):
        l = [num]
    else:
        l = num

    for v in l:
        mu.mem_write(address, int(v).to_bytes(4, byteorder='little'))
        address += 4
