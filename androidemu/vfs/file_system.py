import logging
import os
import posixpath
import sys

from androidemu.config import WRITE_FSTAT_TIMES
from androidemu.cpu.syscall_handlers import SyscallHandlers
from androidemu.utils import memory_helpers

logger = logging.getLogger(__name__)


class VirtualFile:

    def __init__(self, name, file_descriptor):
        self.name = name
        self.descriptor = file_descriptor


class VirtualFileSystem:

    """
    :type syscall_handler SyscallHandlers
    """
    def __init__(self, root_path, syscall_handler):
        self._root_path = root_path

        # TODO: Improve fd logic.
        self._file_descriptor_counter = 3
        self._file_descriptors = dict()
        self._file_descriptors[0] = VirtualFile('stdin', 0)
        self._file_descriptors[1] = VirtualFile('stdout', 1)
        self._file_descriptors[2] = VirtualFile('stderr', 2)

        syscall_handler.set_handler(0x3, "read", 3, self._handle_read)
        syscall_handler.set_handler(0x5, "open", 3, self._handle_open)
        syscall_handler.set_handler(0x6, "close", 1, self._handle_close)
        syscall_handler.set_handler(0x92, "writev", 3, self._handle_writev)
        syscall_handler.set_handler(0xC5, "fstat64", 2, self._handle_fstat64)
        syscall_handler.set_handler(0x142, "openat", 4, self._handle_openat)

    def _store_fd(self, name, file_descriptor):
        next_fd = self._file_descriptor_counter
        self._file_descriptor_counter += 1
        self._file_descriptors[next_fd] = VirtualFile(name, file_descriptor)
        return next_fd

    def _open_file(self, filename):
        # Special cases, such as /dev/urandom.
        orig_filename = filename

        if filename == '/dev/urandom':
            logger.info("File opened '%s'" % filename)
            return self._store_fd('/dev/urandom', 'urandom')

        if filename.startswith("/"):
            filename = filename[1:]

        file_path = posixpath.join(self._root_path, filename)
        file_path = posixpath.normpath(file_path)

        if posixpath.commonpath([file_path, self._root_path]) != self._root_path:
            raise RuntimeError("Emulated binary tried to escape vfs jail.")

        if os.path.isfile(file_path):
            logger.info("File opened '%s'" % orig_filename)
            return self._store_fd(orig_filename, os.open(file_path, flags=os.O_RDWR | os.O_BINARY))
        else:
            logger.info("File does not exist %s" % file_path)
            return -1

    def _handle_read(self, mu, fd, buf_addr, count):
        """
        ssize_t read(int fd, void *buf, size_t count);

        On files that support seeking, the read operation commences at the current file offset, and the file offset
        is incremented by the number of bytes read. If the current file offset is at or past the end of file,
        no bytes are read, and read() returns zero.

        If count is zero, read() may detect the errors described below. In the absence of any errors, or if read()
        does not check for errors, a read() with a count of 0 returns zero and has no other effects.

        If count is greater than SSIZE_MAX, the result is unspecified.
        """
        if fd <= 2:
            raise NotImplementedError("Unsupported read operation for file descriptor %d." % fd)

        if fd not in self._file_descriptors:
            # TODO: Return valid error.
            raise NotImplementedError()

        file = self._file_descriptors[fd]

        logger.info("Reading %d bytes from '%s'" % (count, file.name))

        if file.descriptor == 'urandom':
            buf = os.urandom(count)
        else:
            buf = os.read(file.descriptor, count)

        result = len(buf)
        mu.mem_write(buf_addr, buf)
        return result

    def _handle_open(self, mu, filename_ptr, flags, mode):
        """
        int open(const char *pathname, int flags, mode_t mode);

        return the new file descriptor, or -1 if an error occurred (in which case, errno is set appropriately).
        """
        filename = memory_helpers.read_utf8(mu, filename_ptr)

        return self._open_file(filename)

    def _handle_close(self, mu, fd):
        """
        int close(int fd);

        close() closes a file descriptor, so that it no longer refers to any file and may be reused. Any record locks
        (see fcntl(2)) held on the file it was associated with, and owned by the process, are removed (regardless of
        the file descriptor that was used to obtain the lock).

        close() returns zero on success. On error, -1 is returned, and errno is set appropriately.
        """
        if fd not in self._file_descriptors:
            return 0

        file = self._file_descriptors[fd]

        if file.descriptor != 'urandom':
            logger.info("File closed '%s'" % file.name)
            os.close(file.descriptor)
        else:
            logger.info("File closed '%s'" % '/dev/urandom')

        return 0

    def _handle_writev(self, mu, fd, vec, vlen):
        if fd == 2:
            for i in range(0, vlen):
                addr = memory_helpers.read_ptr(mu, (i * 8) + vec)
                size = memory_helpers.read_ptr(mu, (i * 8) + vec + 4)
                sys.stderr.buffer.write(mu.mem_read(addr, size))

            return 0

        raise NotImplementedError()

    def _handle_fstat64(self, mu, fd, buf_ptr):
        """
        These functions return information about a file. No permissions are required on the file itself, but-in the
        case of stat() and lstat() - execute (search) permission is required on all of the directories in path that
        lead to the file.

        fstat() is identical to stat(), except that the file to be stat-ed is specified by the file descriptor fd.
        """
        if fd not in self._file_descriptors:
            return -1

        file = self._file_descriptors[fd]
        logger.info("File stat64 '%s'" % file.name)

        stat = os.fstat(file.descriptor)

        mu.mem_write(buf_ptr, stat.st_dev.to_bytes(8, byteorder='little'))
        # PAD 4
        mu.mem_write(buf_ptr + 12, stat.st_ino.to_bytes(8, byteorder='little'))
        mu.mem_write(buf_ptr + 20, stat.st_mode.to_bytes(4, byteorder='little'))
        mu.mem_write(buf_ptr + 24, stat.st_nlink.to_bytes(4, byteorder='little'))
        mu.mem_write(buf_ptr + 28, stat.st_uid.to_bytes(8, byteorder='little'))
        mu.mem_write(buf_ptr + 36, stat.st_gid.to_bytes(8, byteorder='little'))
        mu.mem_write(buf_ptr + 44, int(0).to_bytes(8, byteorder='little'))  # st_rdev
        # PAD 4
        mu.mem_write(buf_ptr + 56, stat.st_size.to_bytes(8, byteorder='little'))
        mu.mem_write(buf_ptr + 64, int(0).to_bytes(8, byteorder='little'))  # st_blksize
        mu.mem_write(buf_ptr + 72, int(0).to_bytes(8, byteorder='little'))  # st_blocks

        if WRITE_FSTAT_TIMES:
            mu.mem_write(buf_ptr + 80, int(stat.st_atime).to_bytes(4, byteorder='little'))
            mu.mem_write(buf_ptr + 84, int(stat.st_atime_ns).to_bytes(4, byteorder='little'))
            mu.mem_write(buf_ptr + 88, int(stat.st_mtime).to_bytes(4, byteorder='little'))
            mu.mem_write(buf_ptr + 92, int(stat.st_mtime_ns).to_bytes(4, byteorder='little'))
            mu.mem_write(buf_ptr + 96, int(stat.st_ctime).to_bytes(4, byteorder='little'))
            mu.mem_write(buf_ptr + 100, int(stat.st_ctime_ns).to_bytes(4, byteorder='little'))
        else:
            mu.mem_write(buf_ptr + 80, int(0).to_bytes(4, byteorder='little'))
            mu.mem_write(buf_ptr + 84, int(0).to_bytes(4, byteorder='little'))
            mu.mem_write(buf_ptr + 88, int(0).to_bytes(4, byteorder='little'))
            mu.mem_write(buf_ptr + 92, int(0).to_bytes(4, byteorder='little'))
            mu.mem_write(buf_ptr + 96, int(0).to_bytes(4, byteorder='little'))
            mu.mem_write(buf_ptr + 100, int(0).to_bytes(4, byteorder='little'))

        # New..
        # mu.mem_write(buf_ptr + 104, stat.st_ino.to_bytes(8, byteorder='little'))

        return 0

    def _handle_openat(self, mu, dfd, filename_ptr, flags, mode):
        """
        int openat(int dirfd, const char *pathname, int flags, mode_t mode);

        On success, openat() returns a new file descriptor.
        On error, -1 is returned and errno is set to indicate the error.

        EBADF
            dirfd is not a valid file descriptor.
        ENOTDIR
            pathname is relative and dirfd is a file descriptor referring to a file other than a directory.
        """
        filename = memory_helpers.read_utf8(mu, filename_ptr)

        if not filename.startswith("/") and dfd != 0:
            raise NotImplementedError("Directory file descriptor has not been implemented yet.")

        return self._open_file(filename)
