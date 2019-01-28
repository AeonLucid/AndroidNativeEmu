from unicorn import Uc

from androidemu.const.android import PR_SET_VMA
from androidemu.const.linux import CLOCK_MONOTONIC_COARSE
from androidemu.cpu.syscall_handlers import SyscallHandlers
from androidemu.utils import memory_helpers


class SyscallHooks:

    """
    :type mu Uc
    :type syscall_handler SyscallHandlers
    """
    def __init__(self, mu, syscall_handler):
        self._mu = mu
        self._syscall_handler = syscall_handler
        self._syscall_handler.set_handler(0xAC, "prctl", 5, self._handle_prctl)
        self._syscall_handler.set_handler(0x107, "clock_gettime", 2, self._handle_clock_gettime)

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

    def _handle_clock_gettime(self, mu, clk_id, tp_ptr):
        """
        The functions clock_gettime() retrieve the time of the specified clock clk_id.

        The clk_id argument is the identifier of the particular clock on which to act. A clock may be system-wide and
        hence visible for all processes, or per-process if it measures time only within a single process.

        clock_gettime(), clock_settime() and clock_getres() return 0 for success, or -1 for failure (in which case
        errno is set appropriately).
        """

        if clk_id == CLOCK_MONOTONIC_COARSE:
            # TODO: Actually write time.
            return 0
        else:
            raise NotImplementedError("Unsupported clk_id: %d (%x)" % (clk_id, clk_id))
