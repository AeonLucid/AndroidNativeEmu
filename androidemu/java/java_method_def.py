class JavaMethodDef:

    def __init__(self, func_name, func, name, signature, native, args_list=None, modifier=None, ignore=None):
        self.jvm_id = None  # Assigned by JavaClassDef.
        self.func_name = func_name
        self.func = func
        self.name = name
        self.signature = signature
        self.native = native
        self.native_addr = None
        self.args_list = args_list
        self.modifier = modifier
        self.ignore = ignore


def java_method_def(name, signature, native=False, args_list=None, modifier=None, ignore=False):
    def java_method_def_real(func):
        def native_wrapper(self, emulator, *argv):
            return emulator.call_native(
                native_wrapper.jvm_method.native_addr,
                emulator.java_vm.jni_env.address_ptr,  # JNIEnv*
                0xFA,    # this, TODO: Implement proper "this", a reference to the Java object inside which this native
                         # method has been declared in
                *argv  # Extra args.
            )

        def normal_wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            return result

        wrapper = native_wrapper if native else normal_wrapper
        wrapper.jvm_method = JavaMethodDef(func.__name__, wrapper, name, signature, native,
                                           args_list=args_list,
                                           modifier=modifier,
                                           ignore=ignore)
        return wrapper

    return java_method_def_real
