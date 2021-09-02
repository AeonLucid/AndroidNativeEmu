import logging
import os
import pathlib
import posixpath

from unicorn import UC_HOOK_MEM_UNMAPPED, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ, UC_HOOK_BLOCK

from androidemu.config import WRITE_FSTAT_TIMES
from androidemu.cpu.syscall_handlers import SyscallHandlers
from androidemu.utils import memory_helpers
from androidemu.vfs import file_helpers

logger = logging.getLogger(__name__)

OVERRIDE_URANDOM = False
OVERRIDE_URANDOM_BYTE = b"\x00"


class VirtualFile:

    def __init__(self, name, file_descriptor, name_virt=None):
        self.name = name
        self.name_virt = name_virt
        self.descriptor = file_descriptor


class VirtualFileSystem:

    def __init__(self, root_path: str, syscall_handler: SyscallHandlers):
        self._root_path = pathlib.Path(root_path).resolve()

        # TODO: Improve fd logic.
        self._file_descriptor_counter = 3
        self._file_descriptors = dict()
        self._file_descriptors[0] = VirtualFile('stdin', 0)
        self._file_descriptors[1] = VirtualFile('stdout', 1)
        self._file_descriptors[2] = VirtualFile('stderr', 2)

        syscall_handler.set_handler(0x3, "read", 3, self._handle_read)
        syscall_handler.set_handler(0x5, "open", 3, self._handle_open)
        syscall_handler.set_handler(0x6, "close", 1, self._handle_close)
        syscall_handler.set_handler(0x21, "access", 2, self._handle_access)
        syscall_handler.set_handler(0x92, "writev", 3, self._handle_writev)
        syscall_handler.set_handler(0xC3, "stat64", 2, self._handle_stat64)
        syscall_handler.set_handler(0xC5, "fstat64", 2, self._handle_fstat64)
        syscall_handler.set_handler(0x142, "openat", 4, self._handle_openat)
        syscall_handler.set_handler(0x147, "fstatat64", 4, self._handle_fstatat64)

    def translate_path(self, filename) -> pathlib.Path:
        if filename.startswith("/"):
            filename = filename[1:]

        if os.name == 'nt':
            filename = filename.replace(':', '_')

        file_path = self._root_path.joinpath(filename).resolve()

        if not file_path.is_relative_to(self._root_path):
            raise RuntimeError("Emulator tried to read outside vfs ('%s' not in '%s')." % (file_path, self._root_path))

        return file_path

    def _store_fd(self, name, name_virt, file_descriptor):
        next_fd = self._file_descriptor_counter
        self._file_descriptor_counter += 1
        self._file_descriptors[next_fd] = VirtualFile(name, file_descriptor, name_virt=name_virt)
        return next_fd

    def _open_file(self, filename):
        # Special cases, such as /dev/urandom.
        orig_filename = filename

        if filename == '/dev/urandom':
            logger.info("File opened '%s'" % filename)
            return self._store_fd('/dev/urandom', None, 'urandom')

        file_path = self.translate_path(filename)

        if os.path.isfile(file_path):
            logger.info("File opened '%s'" % orig_filename)
            flags = os.O_RDWR
            if hasattr(os, "O_BINARY"):
                flags |= os.O_BINARY
            return self._store_fd(orig_filename, file_path, os.open(file_path, flags=flags))
        else:
            logger.warning("File does not exist '%s'" % orig_filename)
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
            logger.warning("No such file descriptor index %s in VirtualFileSystem" % fd)
            mu.emu_stop()

        file = self._file_descriptors[fd]

        logger.info("Reading %d bytes from '%s'" % (count, file.name))

        if file.descriptor == 'urandom':
            if OVERRIDE_URANDOM:
                buf = OVERRIDE_URANDOM_BYTE * count
            else:
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

        if fd <= 2:
            # if file.name == 'stdin':
            #     mu.hook_add(UC_HOOK_BLOCK, debug_utils.hook_block)
            logger.info("File closed '%s'" % file.name)
            return 0

        if file.descriptor != 'urandom':
            logger.info("File closed '%s'" % file.name)
            os.close(file.descriptor)
        else:
            logger.info("File closed '%s'" % '/dev/urandom')

        return 0

    def _handle_access(self, mu, filename_ptr, flags):
        filename = memory_helpers.read_utf8(mu, filename_ptr)
        filename_virt = self.translate_path(filename)

        logger.warning("Path '%s' exists %s" % (filename, os.path.isfile(filename_virt)))

        if os.path.isfile(filename_virt):
            return 0

        return -1

    def _handle_writev(self, mu, fd, vec, vlen):
        if fd == 2:
            for i in range(0, vlen):
                addr = memory_helpers.read_ptr(mu, (i * 8) + vec)
                size = memory_helpers.read_ptr(mu, (i * 8) + vec + 4)
                data = bytes(mu.mem_read(addr, size)).decode(encoding='UTF-8')

                logger.error('Writev %s' % data)

            return 0

        raise NotImplementedError()

    def _handle_stat64(self, mu, filename_ptr, buf_ptr):
        filename = memory_helpers.read_utf8(mu, filename_ptr)

        logger.info("File stat64 '%s'" % filename)

        pathname = self.translate_path(filename)

        if not os.path.exists(pathname):
            logger.warning('> File was not found.')
            return -1

        logger.warning('> File was found.')

        # stat = file_helpers.stat64(path=pathname)
        # stat = os.stat(path=file_path, dir_fd=None, follow_symlinks=False)
        # file_helpers.stat_to_memory(mu, buf_ptr, stat, WRITE_FSTAT_TIMES)

        return 0

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

        stat = file_helpers.stat64(file.name_virt)
        # stat = os.fstat(file.descriptor)
        file_helpers.stat_to_memory(mu, buf_ptr, stat, WRITE_FSTAT_TIMES)

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

    def _handle_fstatat64(self, mu, dirfd, pathname_ptr, buf, flags):
        """
        int fstatat(int dirfd, const char *pathname, struct stat *buf, int flags);

        If the pathname given in pathname is relative, then it is interpreted relative to the directory referred
        to by the file descriptor dirfd (rather than relative to the current working directory of the calling process,
        as is done by stat(2) for a relative pathname).

        If pathname is relative and dirfd is the special value AT_FDCWD,
        then pathname is interpreted relative to the current working directory of the calling process (like stat(2)).

        If pathname is absolute, then dirfd is ignored.

        flags can either be 0, or include one or more of the following flags ..

        On success, fstatat() returns 0. On error, -1 is returned and errno is set to indicate the error.
        """
        pathname = memory_helpers.read_utf8(mu, pathname_ptr)

        if not pathname.startswith('/'):
            raise NotImplementedError("Directory file descriptor has not been implemented yet.")

        if not flags == 0:
            if flags & 0x100:  # AT_SYMLINK_NOFOLLOW
                pass
            if flags & 0x800:  # AT_NO_AUTOMOUNT
                pass
            # raise NotImplementedError("Flags has not been implemented yet.")

        logger.info("File fstatat64 '%s'" % pathname)
        pathname = self.translate_path(pathname)

        if not os.path.exists(pathname):
            logger.warning('> File was not found.')
            return -1

        logger.warning('> File was found.')

        stat = file_helpers.stat64(path=pathname)
        # stat = os.stat(path=file_path, dir_fd=None, follow_symlinks=False)
        file_helpers.stat_to_memory(mu, buf, stat, WRITE_FSTAT_TIMES)

        return 0
