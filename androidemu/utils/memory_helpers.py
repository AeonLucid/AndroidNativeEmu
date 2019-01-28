import hexdump


def hex_dump(mu, address, size):
    data = mu.mem_read(address, size)
    return hexdump.hexdump(data)


def read_ptr(mu, address):
    return int.from_bytes(mu.mem_read(address, 4), byteorder='little')


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
