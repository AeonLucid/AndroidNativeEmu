import inspect

from unicorn import Uc
from unicorn.arm_const import *

from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.jni_const import JNI_ERR
from androidemu.java.jni_ref import jobject, jstring, jobjectArray, jbyteArray


def native_write_args(emu, *argv):
    amount = len(argv)

    if amount == 0:
        return

    if amount >= 1:
        native_write_arg_register(emu, UC_ARM_REG_R0, argv[0])

    if amount >= 2:
        native_write_arg_register(emu, UC_ARM_REG_R1, argv[1])

    if amount >= 3:
        native_write_arg_register(emu, UC_ARM_REG_R2, argv[2])

    if amount >= 4:
        native_write_arg_register(emu, UC_ARM_REG_R3, argv[3])

    if amount >= 5:
        # TODO: I have no idea why this dark magic is required but it works (for me)..
        sp_start = emu.mu.reg_read(UC_ARM_REG_SP)
        sp_current = sp_start - 8

        for arg in argv[4:]:
            emu.mu.mem_write(sp_current - 8, native_translate_arg(emu, arg).to_bytes(4, byteorder='little'))
            sp_current = sp_current - 4

        emu.mu.reg_write(UC_ARM_REG_SP, sp_current)


def native_translate_arg(emu, val):
    if isinstance(val, int):
        return val
    elif isinstance(val, str):
        return emu.java_vm.jni_env.add_local_reference(jstring(val))
    elif isinstance(val, list):
        return emu.java_vm.jni_env.add_local_reference(jobjectArray(val))
    elif isinstance(val, bytearray):
        return emu.java_vm.jni_env.add_local_reference(jbyteArray(val))
    elif isinstance(type(val), JavaClassDef):
        return emu.java_vm.jni_env.add_local_reference(jobject(val))
    else:
        raise NotImplementedError("Unable to write response '%s' type '%s' to emulator." % (str(val), type(val)))


def native_write_arg_register(emu, reg, val):
    emu.mu.reg_write(reg, native_translate_arg(emu, val))


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
            native_args.append(mu.reg_read(UC_ARM_REG_R4))

        if args_count >= 6:
            native_args.append(mu.reg_read(UC_ARM_REG_R5))

        if args_count >= 7:
            native_args.append(mu.reg_read(UC_ARM_REG_R6))

        if args_count >= 8:
            native_args.append(mu.reg_read(UC_ARM_REG_R7))

        if args_count >= 9:
            raise NotImplementedError("We don't support more than 8 args yet, read from the stack.")

        if len(argv) == 1:
            result = func(mu, *native_args)
        else:
            result = func(argv[0], mu, *native_args)

        if result is not None:
            native_write_arg_register(emu, UC_ARM_REG_R0, result)
        else:
            mu.reg_write(UC_ARM_REG_R0, JNI_ERR)

    return native_method_wrapper
