import calendar
import logging
import math
import os
import time
from random import randint

import hexdump
from unicorn import Uc

from androidemu.const.android import *
from androidemu.const.linux import *
from androidemu.cpu.syscall_handlers import SyscallHandlers
from androidemu.data import socket_info
from androidemu.data.fork_info import ForkInfo
from androidemu.data.socket_info import SocketInfo
from androidemu.internal.modules import Modules
from androidemu.utils import memory_helpers

OVERRIDE_TIMEOFDAY = False
OVERRIDE_TIMEOFDAY_SEC = 0
OVERRIDE_TIMEOFDAY_USEC = 0

OVERRIDE_CLOCK = False
OVERRIDE_CLOCK_TIME = 0

logger = logging.getLogger(__name__)


class SyscallHooks:

    """
    :type mu Uc
    :type syscall_handler SyscallHandlers
    """
    def __init__(self, mu, syscall_handler, modules: Modules):
        self._mu = mu
        self._syscall_handler = syscall_handler
        self._syscall_handler.set_handler(0xB, "execve", 3, self._handle_execve)
        self._syscall_handler.set_handler(0x43, "sigaction", 3, self._null)
        self._syscall_handler.set_handler(0x48, "sigsuspend", 3, self._null)
        self._syscall_handler.set_handler(0x14, "getpid", 0, self._getpid)
        self._syscall_handler.set_handler(0x4E, "gettimeofday", 2, self._handle_gettimeofday)
        self._syscall_handler.set_handler(0x72, "wait4", 4, self._handle_wait4)
        self._syscall_handler.set_handler(0xAC, "prctl", 5, self._handle_prctl)
        self._syscall_handler.set_handler(0xE0, "gettid", 0, self._gettid)
        self._syscall_handler.set_handler(0xAF, "sigprocmask", 3, self._null)
        self._syscall_handler.set_handler(0xBE, "vfork", 0, self._handle_vfork)
        self._syscall_handler.set_handler(0xF0, "futex", 6, self._handle_futex)
        self._syscall_handler.set_handler(0xF8, "exit_group", 1, self._exit_group)
        self._syscall_handler.set_handler(0x107, "clock_gettime", 2, self._handle_clock_gettime)
        self._syscall_handler.set_handler(0x119, "socket", 3, self._socket)
        self._syscall_handler.set_handler(0x11a, "bind", 3, self._bind)
        self._syscall_handler.set_handler(0x11b, "connect", 3, self._connect)
        self._syscall_handler.set_handler(0x14e, "faccessat", 4, self._faccessat)
        self._syscall_handler.set_handler(0x159, "getcpu", 3, self._getcpu)
        self._syscall_handler.set_handler(0x14e, "faccessat", 4, self._faccessat)
        self._syscall_handler.set_handler(0x14, "getpid", 0, self._getpid)
        self._syscall_handler.set_handler(0xe0, "gettid", 0, self._gettid)
        # self._syscall_handler.set_handler(0x180,"null1",0, self._null)
        self._syscall_handler.set_handler(0x180, "getrandom", 3, self._getrandom)
        self._modules = modules
        self._clock_start = time.time()
        self._clock_offset = randint(1000, 2000)
        self._socket_id = 0x100000
        self._sockets = dict()
        self._fork = None

    def _getpid(self, mu):
        return 21458

    def _handle_execve(self, mu, pathname_ptr, argv, envp):
        pathname = memory_helpers.read_utf8(mu, pathname_ptr)
        args = []
        while True:
            arg_ptr = int.from_bytes(mu.mem_read(argv, 4), byteorder='little')

            if arg_ptr == 0:
                break

            args.append(memory_helpers.read_utf8(mu, arg_ptr))
            argv = argv + 4

        # Set errno.
        errno_ptr = self._modules.find_symbol_name('__errno')
        mu.mem_write(errno_ptr, int(13).to_bytes(4, byteorder='little'))

        logger.warning('Exec %s %s' % (pathname, args))
        return 0

    def _null(self, mu, *args):
        logger.warning('Skipping syscall, returning 0')
        return 0

    def _gettid(self, mu):
        return 0x2211

    def _faccessat(self, mu, filename, pathname, mode, flag):
        file = memory_helpers.read_utf8(mu, pathname)
        return 0

    def _getcpu(self, mu, _cpu, node, cache):
        if _cpu != 0:
            mu.mem_write(_cpu, int(1).to_bytes(4, byteorder='little'))
        return 0

    def _handle_gettimeofday(self, uc, tv, tz):
        """
        If either tv or tz is NULL, the corresponding structure is not set or returned.
        """

        if tv != 0:
            if OVERRIDE_TIMEOFDAY:
                uc.mem_write(tv + 0, int(OVERRIDE_TIMEOFDAY_SEC).to_bytes(4, byteorder='little'))
                uc.mem_write(tv + 4, int(OVERRIDE_TIMEOFDAY_USEC).to_bytes(4, byteorder='little'))
            else:
                timestamp = time.time()
                (usec, sec) = math.modf(timestamp)
                usec = abs(int(usec * 100000))

                uc.mem_write(tv + 0, int(sec).to_bytes(4, byteorder='little'))
                uc.mem_write(tv + 4, int(usec).to_bytes(4, byteorder='little'))

        if tz != 0:
            uc.mem_write(tz + 0, int(-120).to_bytes(4, byteorder='little'))  # minuteswest -(+GMT_HOURS) * 60
            uc.mem_write(tz + 4, int().to_bytes(4, byteorder='little'))  # dsttime

        return 0

    def _handle_wait4(self, mu, upid, stat_addr, options,  ru):
        """
        on success, returns the process ID of the terminated child; on error, -1 is returned.
        """
        return upid

    def _handle_prctl(self, mu, option, arg2, arg3, arg4, arg5):
        """
        int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
        See:
        - https://linux.die.net/man/2/prctl
        - https://github.com/torvalds/linux/blob/master/include/uapi/linux/prctl.h

        For PR_SET_VMA:
        - https://android.googlesource.com/platform/bionic/+/263325d/libc/include/sys/prctl.h
        - https://sourceforge.net/p/strace/mailman/message/34329772/
        """

        if option == PR_SET_VMA:
            # arg5 contains ptr to a name.
            return 0
        else:
            raise NotImplementedError("Unsupported prctl option %d (0x%x)" % (option, option))

    def _handle_vfork(self, mu):
        """
        Upon successful completion, vfork() shall return 0 to the child process
        and return the process ID of the child process to the parent process.

        Otherwise, -1 shall be returned to the parent, no child process shall be created,
        and errno shall be set to indicate the error.
        """
        if self._fork is not None:
            raise NotImplementedError('Already forked.')

        self._fork = ForkInfo(mu, self._getpid(mu) + 1)

        # Current execution becomes the fork, save all registers so we can return to vfork later for the main process.
        # See exit_group.
        self._fork.save_state()

        return 0

    def _handle_futex(self, mu, uaddr, op, val, timeout, uaddr2, val3):
        """
        See: https://linux.die.net/man/2/futex
        """

        if op & FUTEX_WAIT:
            raise NotImplementedError()
        elif op & FUTEX_WAKE:
            wakes_at_most = val
            return 0
        elif op & FUTEX_FD:
            raise NotImplementedError()
        elif op & FUTEX_REQUEUE:
            raise NotImplementedError()
        elif op & FUTEX_CMP_REQUEUE:
            raise NotImplementedError()

        return 0

    def _exit_group(self, mu, status):
        if self._fork is not None:
            pid = self._fork.pid

            self._fork.load_state()
            self._fork = None

            # We exit the child process, registers were restored to vfork.
            return pid

        raise Exception('Application shutdown all threads, status %u' % status)

    def _handle_clock_gettime(self, mu, clk_id, tp_ptr):
        """
        The functions clock_gettime() retrieve the time of the specified clock clk_id.

        The clk_id argument is the identifier of the particular clock on which to act. A clock may be system-wide and
        hence visible for all processes, or per-process if it measures time only within a single process.

        clock_gettime(), clock_settime() and clock_getres() return 0 for success, or -1 for failure (in which case
        errno is set appropriately).
        """

        if clk_id == CLOCK_REALTIME:
            # Its time represents seconds and nanoseconds since the Epoch.
            clock_real = calendar.timegm(time.gmtime())

            mu.mem_write(tp_ptr + 0, int(clock_real).to_bytes(4, byteorder='little'))
            mu.mem_write(tp_ptr + 4, int(0).to_bytes(4, byteorder='little'))
            return 0
        elif clk_id == CLOCK_MONOTONIC or clk_id == CLOCK_MONOTONIC_COARSE:
            if OVERRIDE_CLOCK:
                mu.mem_write(tp_ptr + 0, int(OVERRIDE_CLOCK_TIME).to_bytes(4, byteorder='little'))
                mu.mem_write(tp_ptr + 4, int(0).to_bytes(4, byteorder='little'))
            else:
                clock_add = time.time() - self._clock_start  # Seconds passed since clock_start was set.

                mu.mem_write(tp_ptr + 0, int(self._clock_start + clock_add).to_bytes(4, byteorder='little'))
                mu.mem_write(tp_ptr + 4, int(0).to_bytes(4, byteorder='little'))
            return 0
        else:
            raise NotImplementedError("Unsupported clk_id: %d (%x)" % (clk_id, clk_id))

    def _socket(self, mu, family, type_in, protocol):
        socket_id = self._socket_id + 1
        socket = SocketInfo()
        socket.domain = family
        socket.type = type_in
        socket.protocol = protocol

        self._sockets[socket_id] = socket
        self._socket_id = self._socket_id + 1

        return socket_id

    def _bind(self, mu, fd, addr, addr_len):
        socket = self._sockets.get(fd, None)

        if socket is None:
            raise Exception('Expected a socket')

        if socket.domain != socket_info.AF_UNIX and socket.type != socket_info.SOCK_STREAM:
            raise Exception('Unexpected socket domain / type.')

        # The struct is confusing..
        socket.addr = mu.mem_read(addr + 3, addr_len - 3).decode(encoding="utf-8")

        logger.info('Binding socket to ://%s' % socket.addr)

        return 0

    def _connect(self, mu, fd, addr, addr_len):
        """
        If the connection or binding succeeds, zero is returned.
        On error, -1 is returned, and errno is set appropriately.
        """
        hexdump.hexdump(mu.mem_read(addr, addr_len))
        
        # return 0
        raise NotImplementedError()

    def _getrandom(self, mu, buf, count, flags):
        mu.mem_write(buf, b"\x01" * count)
        return count
