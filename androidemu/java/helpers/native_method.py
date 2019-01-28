import inspect
import types

from unicorn import Uc
from unicorn.arm_const import *


def native_method(func):
    def native_method_wrapper(self, mu):
        """
        :type self
        :type mu Uc
        """

        args = inspect.getfullargspec(func).args
        args_count = len(args) - (2 if 'self' in args else 1)

        if args_count < 0:
            raise RuntimeError("NativeMethod accept at least (self, mu) or (mu).")

        native_args = []

        if args_count >= 1:
            native_args.append(mu.reg_read(UC_ARM_REG_R0))

        if args_count >= 2:
            native_args.append(mu.reg_read(UC_ARM_REG_R1))

        if args_count >= 3:
            native_args.append(mu.reg_read(UC_ARM_REG_R2))

        if args_count >= 4:
            native_args.append(mu.reg_read(UC_ARM_REG_R3))

        if args_count >= 5:
            raise NotImplementedError("We don't support more than 4 args yet, read from the stack.")

        try:
            result = func(self, mu, *native_args)
        except:
            # Make sure we catch exceptions inside hooks and stop emulation.
            mu.emu_stop()
            raise

        if result is not None:
            if isinstance(result, int):
                mu.reg_write(UC_ARM_REG_R0, result)
            else:
                raise NotImplementedError("Unable to write response '%s' to emulator." % str(result))

    return native_method_wrapper
