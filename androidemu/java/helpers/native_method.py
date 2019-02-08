import inspect

from unicorn import Uc
from unicorn.arm_const import *

from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.jni_const import JNI_ERR
from androidemu.java.jni_ref import jobject


def native_write_args(mu, *argv):
    amount = len(argv)

    if amount == 0:
        return

    if amount >= 1:
        native_write_arg_register(mu, UC_ARM_REG_R0, argv[0])

    if amount >= 2:
        native_write_arg_register(mu, UC_ARM_REG_R1, argv[1])

    if amount >= 3:
        native_write_arg_register(mu, UC_ARM_REG_R2, argv[2])

    if amount >= 4:
        native_write_arg_register(mu, UC_ARM_REG_R3, argv[3])

    if amount >= 5:
        raise NotImplementedError("We don't support more than 4 args yet, write to the stack.")


def native_write_arg_register(mu, reg, val):
    if isinstance(val, int):
        mu.reg_write(reg, val)
    else:
        raise ValueError('Unsupported val type.')


def native_method(func):
    def native_method_wrapper(*argv):
        """
        :type self
        :type emu androidemu.emulator.Emulator
        :type mu Uc
        """

        emu = argv[1] if len(argv) == 2 else argv[0]
        mu = emu.mu

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

        if len(argv) == 1:
            result = func(mu, *native_args)
        else:
            result = func(argv[0], mu, *native_args)

        if result is not None:
            if isinstance(result, int):
                mu.reg_write(UC_ARM_REG_R0, result)
            elif isinstance(type(result), JavaClassDef):
                # This is a Java class object, so we should probably respond with a local jobject reference.
                ref = emu.java_vm.jni_env.add_local_reference(jobject(result))
                mu.reg_write(UC_ARM_REG_R0, ref)
            else:
                raise NotImplementedError("Unable to write response '%s' to emulator." % str(result))
        else:
            mu.reg_write(UC_ARM_REG_R0, JNI_ERR)

    return native_method_wrapper
