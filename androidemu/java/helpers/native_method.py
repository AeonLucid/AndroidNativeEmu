import inspect

from unicorn import Uc
from unicorn.arm_const import *

from androidemu.hooker import STACK_OFFSET
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
        sp_start = emu.mu.reg_read(UC_ARM_REG_SP)
        sp_current = sp_start - STACK_OFFSET  # Need to offset because our hook pushes one register on the stack.

        for arg in argv[4:]:
            emu.mu.mem_write(sp_current - STACK_OFFSET, native_translate_arg(emu, arg).to_bytes(4, byteorder='little'))
            sp_current = sp_current - 4

        emu.mu.reg_write(UC_ARM_REG_SP, sp_current)


def native_read_args(mu, args_count):
    native_args = []

    if args_count >= 1:
        native_args.append(mu.reg_read(UC_ARM_REG_R0))

    if args_count >= 2:
        native_args.append(mu.reg_read(UC_ARM_REG_R1))

    if args_count >= 3:
        native_args.append(mu.reg_read(UC_ARM_REG_R2))

    if args_count >= 4:
        native_args.append(mu.reg_read(UC_ARM_REG_R3))

    sp = mu.reg_read(UC_ARM_REG_SP)
    sp = sp + STACK_OFFSET  # Need to offset by 4 because our hook pushes one register on the stack.

    if args_count >= 5:
        for x in range(0, args_count - 4):
            native_args.append(int.from_bytes(mu.mem_read(sp + (x * 4), 4), byteorder='little'))

    return native_args


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
        # TODO: Look into this, seems wrong..
        return emu.java_vm.jni_env.add_local_reference(jobject(val))
    elif isinstance(val, JavaClassDef):
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

        native_args = native_read_args(mu, args_count)

        if len(argv) == 1:
            result = func(mu, *native_args)
        else:
            result = func(argv[0], mu, *native_args)

        if result is not None:
            native_write_arg_register(emu, UC_ARM_REG_R0, result)
        else:
            mu.reg_write(UC_ARM_REG_R0, JNI_ERR)

    return native_method_wrapper
