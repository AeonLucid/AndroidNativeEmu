import logging
import os
import posixpath

from androidemu.cpu.syscall_handlers import SyscallHandlers
from androidemu.utils import memory_helpers

logger = logging.getLogger(__name__)


class VirtualFileSystem:

    """
    :type syscall_handler SyscallHandlers
    """
    def __init__(self, root_path, syscall_handler):
        self._root_path = root_path
        self._file_descriptors = [0, 1, 2]
        syscall_handler.set_handler(0x3, "read", 3, self._handle_read)
        syscall_handler.set_handler(0x6, "close", 1, self._handle_close)
        syscall_handler.set_handler(0x142, "openat", 4, self._handle_openat)

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

        file_handle = self._file_descriptors[fd]
        buf = os.read(file_handle, count)
        result = len(buf)
        mu.mem_write(buf_addr, buf)
        return result

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

        os.close(self._file_descriptors[fd])
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

        if filename.startswith("/"):
            filename = filename[1:]

        file_path = posixpath.join(self._root_path, filename)
        file_path = posixpath.normpath(file_path)

        if posixpath.commonpath([file_path, self._root_path]) != self._root_path:
            raise RuntimeError("Emulated binary tried to escape vfs jail.")

        if os.path.isfile(file_path):
            logger.info("File opened '%s'" % filename)
            self._file_descriptors.append(os.open(file_path, flags=os.O_RDWR | os.O_BINARY))
            return len(self._file_descriptors) - 1
        else:
            logger.info("File does not exist %s" % file_path)
            return -1
