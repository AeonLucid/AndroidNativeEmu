import logging

from androidemu.hooker import Hooker
from androidemu.java.classes.constructor import Constructor
from androidemu.java.classes.method import Method
from androidemu.java.constant_values import MODIFIER_STATIC
from androidemu.java.helpers.native_method import native_method
from androidemu.java.java_classloader import JavaClassLoader
from androidemu.java.jni_const import *
from androidemu.java.jni_ref import *
from androidemu.java.reference_table import ReferenceTable
from androidemu.utils import memory_helpers

logger = logging.getLogger(__name__)


# This class attempts to mimic the JNINativeInterface table.
class JNIEnv:
    """
    :type class_loader JavaClassLoader
    :type hooker Hooker
    """

    def __init__(self, emu, class_loader, hooker):
        self._emu = emu
        self._class_loader = class_loader
        self._locals = ReferenceTable(start=1, max_entries=2048)
        self._globals = ReferenceTable(start=4096, max_entries=512000)

        (self.address_ptr, self.address) = hooker.write_function_table({
            4: self.get_version,
            5: self.define_class,
            6: self.find_class,
            7: self.from_reflected_method,
            8: self.from_reflected_field,
            9: self.to_reflected_method,
            10: self.get_superclass,
            11: self.is_assignable_from,
            12: self.to_reflected_field,
            13: self.throw,
            14: self.throw_new,
            15: self.exception_occurred,
            16: self.exception_describe,
            17: self.exception_clear,
            18: self.fatal_error,
            19: self.push_local_frame,
            20: self.pop_local_frame,
            21: self.new_global_ref,
            22: self.delete_global_ref,
            23: self.delete_local_ref,
            24: self.is_same_object,
            25: self.new_local_ref,
            26: self.ensure_local_capacity,
            27: self.alloc_object,
            28: self.new_object,
            29: self.new_object_v,
            30: self.new_object_a,
            31: self.get_object_class,
            32: self.is_instance_of,
            33: self.get_method_id,
            34: self.call_object_method,
            35: self.call_object_method_v,
            36: self.call_object_method_a,
            37: self.call_boolean_method,
            38: self.call_boolean_method_v,
            39: self.call_boolean_method_a,
            40: self.call_byte_method,
            41: self.call_byte_method_v,
            42: self.call_byte_method_a,
            43: self.call_char_method,
            44: self.call_char_method_v,
            45: self.call_char_method_a,
            46: self.call_short_method,
            47: self.call_short_method_v,
            48: self.call_short_method_a,
            49: self.call_int_method,
            50: self.call_int_method_v,
            51: self.call_int_method_a,
            52: self.call_long_method,
            53: self.call_long_method_v,
            54: self.call_long_method_a,
            55: self.call_float_method,
            56: self.call_float_method_v,
            57: self.call_float_method_a,
            58: self.call_double_method,
            59: self.call_double_method_v,
            60: self.call_double_method_a,
            61: self.call_void_method,
            62: self.call_void_method_v,
            63: self.call_void_method_a,
            64: self.call_nonvirtual_object_method,
            65: self.call_nonvirtual_object_method_v,
            66: self.call_nonvirtual_object_method_a,
            67: self.call_nonvirtual_boolean_method,
            68: self.call_nonvirtual_boolean_method_v,
            69: self.call_nonvirtual_boolean_method_a,
            70: self.call_nonvirtual_byte_method,
            71: self.call_nonvirtual_byte_method_v,
            72: self.call_nonvirtual_byte_method_a,
            73: self.call_nonvirtual_char_method,
            74: self.call_nonvirtual_char_method_v,
            75: self.call_nonvirtual_char_method_a,
            76: self.call_nonvirtual_short_method,
            77: self.call_nonvirtual_short_method_v,
            78: self.call_nonvirtual_short_method_a,
            79: self.call_nonvirtual_int_method,
            80: self.call_nonvirtual_int_method_v,
            81: self.call_nonvirtual_int_method_a,
            82: self.call_nonvirtual_long_method,
            83: self.call_nonvirtual_long_method_v,
            84: self.call_nonvirtual_long_method_a,
            85: self.call_nonvirtual_float_method,
            86: self.call_nonvirtual_float_method_v,
            87: self.call_nonvirtual_float_method_a,
            88: self.call_nonvirtual_double_method,
            89: self.call_nonvirtual_double_method_v,
            90: self.call_nonvirtual_double_method_a,
            91: self.call_nonvirtual_void_method,
            92: self.call_nonvirtual_void_method_v,
            93: self.call_nonvirtual_void_method_a,
            94: self.get_field_id,
            95: self.get_object_field,
            96: self.get_boolean_field,
            97: self.get_byte_field,
            98: self.get_char_field,
            99: self.get_short_field,
            100: self.get_int_field,
            101: self.get_long_field,
            102: self.get_float_field,
            103: self.get_double_field,
            104: self.set_object_field,
            105: self.set_boolean_field,
            106: self.set_byte_field,
            107: self.set_char_field,
            108: self.set_short_field,
            109: self.set_int_field,
            110: self.set_long_field,
            111: self.set_float_field,
            112: self.set_double_field,
            113: self.get_static_method_id,
            114: self.call_static_object_method,
            115: self.call_static_object_method_v,
            116: self.call_static_object_method_a,
            117: self.call_static_boolean_method,
            118: self.call_static_boolean_method_v,
            119: self.call_static_boolean_method_a,
            120: self.call_static_byte_method,
            121: self.call_static_byte_method_v,
            122: self.call_static_byte_method_a,
            123: self.call_static_char_method,
            124: self.call_static_char_method_v,
            125: self.call_static_char_method_a,
            126: self.call_static_short_method,
            127: self.call_static_short_method_v,
            128: self.call_static_short_method_a,
            129: self.call_static_int_method,
            130: self.call_static_int_method_v,
            131: self.call_static_int_method_a,
            132: self.call_static_long_method,
            133: self.call_static_long_method_v,
            134: self.call_static_long_method_a,
            135: self.call_static_float_method,
            136: self.call_static_float_method_v,
            137: self.call_static_float_method_a,
            138: self.call_static_double_method,
            139: self.call_static_double_method_v,
            140: self.call_static_double_method_a,
            141: self.call_static_void_method,
            142: self.call_static_void_method_v,
            143: self.call_static_void_method_a,
            144: self.get_static_field_id,
            145: self.get_static_object_field,
            146: self.get_static_boolean_field,
            147: self.get_static_byte_field,
            148: self.get_static_char_field,
            149: self.get_static_short_field,
            150: self.get_static_int_field,
            151: self.get_static_long_field,
            152: self.get_static_float_field,
            153: self.get_static_double_field,
            154: self.set_static_object_field,
            155: self.set_static_boolean_field,
            156: self.set_static_byte_field,
            157: self.set_static_char_field,
            158: self.set_static_short_field,
            159: self.set_static_int_field,
            160: self.set_static_long_field,
            161: self.set_static_float_field,
            162: self.set_static_double_field,
            163: self.new_string,
            164: self.get_string_length,
            165: self.get_string_chars,
            166: self.release_string_chars,
            167: self.new_string_utf,
            168: self.get_string_utf_length,
            169: self.get_string_utf_chars,
            170: self.release_string_utf_chars,
            171: self.get_array_length,
            172: self.new_object_array,
            173: self.get_object_array_element,
            174: self.set_object_array_element,
            175: self.new_boolean_array,
            176: self.new_byte_array,
            177: self.new_char_array,
            178: self.new_short_array,
            179: self.new_int_array,
            180: self.new_long_array,
            181: self.new_float_array,
            182: self.new_double_array,
            183: self.get_boolean_array_elements,
            184: self.get_byte_array_elements,
            185: self.get_char_array_elements,
            186: self.get_short_array_elements,
            187: self.get_int_array_elements,
            188: self.get_long_array_elements,
            189: self.get_float_array_elements,
            190: self.get_double_array_elements,
            191: self.release_boolean_array_elements,
            192: self.release_byte_array_elements,
            193: self.release_char_array_elements,
            194: self.release_short_array_elements,
            195: self.release_int_array_elements,
            196: self.release_long_array_elements,
            197: self.release_float_array_elements,
            198: self.release_double_array_elements,
            199: self.get_boolean_array_region,
            200: self.get_byte_array_region,
            201: self.get_char_array_region,
            202: self.get_short_array_region,
            203: self.get_int_array_region,
            204: self.get_long_array_region,
            205: self.get_float_array_region,
            206: self.get_double_array_region,
            207: self.set_boolean_array_region,
            208: self.set_byte_array_region,
            209: self.set_char_array_region,
            210: self.set_short_array_region,
            211: self.set_int_array_region,
            212: self.set_long_array_region,
            213: self.set_float_array_region,
            214: self.set_double_array_region,
            215: self.register_natives,
            216: self.unregister_natives,
            217: self.monitor_enter,
            218: self.monitor_exit,
            219: self.get_java_vm,
            220: self.get_string_region,
            221: self.get_string_utf_region,
            222: self.get_primitive_array_critical,
            223: self.release_primitive_array_critical,
            224: self.get_string_critical,
            225: self.release_string_critical,
            226: self.new_weak_global_ref,
            227: self.delete_weak_global_ref,
            228: self.exception_check,
            229: self.new_direct_byte_buffer,
            230: self.get_direct_buffer_address,
            231: self.get_direct_buffer_capacity,
            232: self.get_object_ref_type
        })

    def get_reference(self, idx):
        if idx == 0:
            return None

        if self._locals.in_range(idx):
            return self._locals.get(idx)

        if self._globals.in_range(idx):
            return self._globals.get(idx)

        raise RuntimeError('Invalid get_reference(%d)' % idx)

    def add_local_reference(self, obj):
        if not isinstance(obj, jobject):
            raise ValueError('Expected a jobject.')

        return self._locals.add(obj)

    def set_local_reference(self, idx, newobj):
        if not isinstance(newobj, jobject):
            raise ValueError('Expected a jobject.')

        self._locals.set(idx, newobj)

    def get_local_reference(self, idx):
        return self._locals.get(idx)

    def delete_local_reference(self, obj):
        if not isinstance(obj, jobject):
            raise ValueError('Expected a jobject.')

        self._locals.remove(obj)

    def clear_locals(self):
        self._locals.clear()

    def add_global_reference(self, obj):
        if not isinstance(obj, jobject):
            raise ValueError('Expected a jobject.')

        return self._globals.add(obj)

    def get_global_reference(self, idx):
        return self._globals.get(idx)

    def delete_global_reference(self, obj):
        if not isinstance(obj, jobject):
            raise ValueError('Expected a jobject.')

        return self._globals.remove(obj)

    def read_args_v(self, mu, args_ptr, args_list):
        if args_list is None:
            return []

        result = []

        for arg_name in args_list:
            if arg_name == 'jint':
                ref = int.from_bytes(mu.mem_read(args_ptr, 4), byteorder='little')
                result.append(ref)
                args_ptr = args_ptr + 4
            elif arg_name == 'jstring':
                ref = int.from_bytes(mu.mem_read(args_ptr, 4), byteorder='little')
                result.append(self.get_reference(ref))
                args_ptr = args_ptr + 4
            elif arg_name == 'jobject':
                ref = int.from_bytes(mu.mem_read(args_ptr, 4), byteorder='little')
                result.append(self.get_reference(ref))
                args_ptr = args_ptr + 4
            else:
                raise NotImplementedError('Unknown arg name %s' % arg_name)

        return result

    @native_method
    def get_version(self, mu, env):
        raise NotImplementedError()

    @native_method
    def define_class(self, mu, env):
        raise NotImplementedError()

    @native_method
    def find_class(self, mu, env, name_ptr):
        """
        Returns a class object from a fully-qualified name, or NULL if the class cannot be found.
        """
        name = memory_helpers.read_utf8(mu, name_ptr)
        logger.debug("JNIEnv->FindClass(%s) was called" % name)

        if name.startswith('['):
            raise NotImplementedError('Array type not implemented.')

        clazz = self._class_loader.find_class_by_name(name)

        if clazz is None:
            # TODO: Proper Java error?
            raise RuntimeError('Could not find class \'%s\' for JNIEnv.' % name)

        if clazz.jvm_ignore:
            return 0

        return self.add_local_reference(jclass(clazz))

    @native_method
    def from_reflected_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def from_reflected_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def to_reflected_method(self, mu, env, class_idx, method_id, is_static):
        """
        Converts a method ID derived from cls to a java.lang.reflect.Method or java.lang.reflect.Constructor object.
        isStatic must be set to JNI_TRUE if the method ID refers to a static field, and JNI_FALSE otherwise.

        Throws OutOfMemoryError and returns 0 if fails.
        """
        clazz = self.get_reference(class_idx)

        if not isinstance(clazz, jclass):
            raise ValueError('Expected a jclass.')

        method = clazz.value.find_method_by_id(method_id)
        if method is None:
            raise RuntimeError("Could not find method ('%u') in class %s." % (method_id, clazz.value.jvm_name))

        if method.modifier & MODIFIER_STATIC:
            mu.mem_write(is_static, int(JNI_TRUE).to_bytes(4, byteorder='little'))
        else:
            mu.mem_write(is_static, int(JNI_FALSE).to_bytes(4, byteorder='little'))

        logger.debug("JNIEnv->ToReflectedMethod(%s, %s, %u) was called" % (clazz.value.jvm_name,
                                                                           method.name,
                                                                           is_static))

        if method.name == '<init>' and method.signature.endswith('V'):
            return Constructor(clazz.value, method)
        else:
            return Method(clazz.value, method)

    @native_method
    def get_superclass(self, mu, env):
        raise NotImplementedError()

    @native_method
    def is_assignable_from(self, mu, env):
        raise NotImplementedError()

    @native_method
    def to_reflected_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def throw(self, mu, env):
        raise NotImplementedError()

    @native_method
    def throw_new(self, mu, env):
        raise NotImplementedError()

    @native_method
    def exception_occurred(self, mu, env):
        raise NotImplementedError()

    @native_method
    def exception_describe(self, mu, env):
        raise NotImplementedError()

    @native_method
    def exception_clear(self, mu, env):
        """
        Clears any exception that is currently being thrown.
        If no exception is currently being thrown, this routine has no effect.
        """
        logger.debug("JNIEnv->ExceptionClear() was called")
        # TODO: Implement
        return None

    @native_method
    def fatal_error(self, mu, env):
        raise NotImplementedError()

    @native_method
    def push_local_frame(self, mu, env):
        raise NotImplementedError()

    @native_method
    def pop_local_frame(self, mu, env):
        raise NotImplementedError()

    @native_method
    def new_global_ref(self, mu, env, obj):
        """
        Creates a new global reference to the object referred to by the obj argument. The obj argument may be a
        global or local reference. Global references must be explicitly disposed of by calling DeleteGlobalRef().
        """
        logger.debug("JNIEnv->NewGlobalRef(%d) was called" % obj)

        if obj == 0:
            return 0

        obj = self.get_local_reference(obj)

        if obj is None:
            # TODO: Implement global > global support (?)
            raise NotImplementedError('Invalid local reference obj.')

        return self.add_global_reference(obj)

    @native_method
    def delete_global_ref(self, mu, env, idx):
        """
        Deletes the global reference pointed to by globalRef.
        """
        logger.debug("JNIEnv->DeleteGlobalRef(%d) was called" % idx)

        if idx == 0:
            return None

        obj = self.get_global_reference(idx)
        self.delete_global_reference(obj)

    @native_method
    def delete_local_ref(self, mu, env, idx):
        """
        Deletes the local reference pointed to by localRef.
        """
        logger.debug("JNIEnv->DeleteLocalRef(%d) was called" % idx)

        if idx == 0:
            return None

        obj = self.get_local_reference(idx)
        self.delete_local_reference(obj)

    @native_method
    def is_same_object(self, mu, env, ref1, ref2):
        """
        Returns JNI_TRUE if ref1 and ref2 refer to the same Java object, or are both NULL; otherwise, returns JNI_FALSE.
        """
        logger.debug("JNIEnv->IsSameObject(%d, %d) was called" % (ref1, ref2))

        if ref1 == 0 and ref2 == 0:
            return JNI_TRUE

        obj1 = self.get_reference(ref1)
        obj2 = self.get_reference(ref2)

        if obj1 is obj2:
            return JNI_TRUE

        return JNI_FALSE

    @native_method
    def new_local_ref(self, mu, env, ref):
        """
        Creates a new local reference that refers to the same object as ref.
        The given ref may be a global or local reference. Returns NULL if ref refers to null.
        """
        logger.debug("JNIEnv->NewLocalRef(%d) was called" % ref)

        obj = self.get_reference(ref)

        if obj is None:
            return 0

        return self.add_local_reference(obj)

    @native_method
    def ensure_local_capacity(self, mu, env):
        raise NotImplementedError()

    @native_method
    def alloc_object(self, mu, env):
        raise NotImplementedError()

    @native_method
    def new_object(self, mu, env):
        raise NotImplementedError()

    @native_method
    def new_object_v(self, mu, env, clazz_idx, method_id, args):
        # Get class reference.
        clazz = self.get_reference(clazz_idx)
        if not isinstance(clazz, jclass):
            raise ValueError('Expected a jclass.')

        # Create class instance.
        obj = clazz.value()

        # Get constructor method.
        method = obj.__class__.find_method_by_id(method_id)
        if method.name != '<init>' or not method.signature.endswith('V'):
            raise ValueError('Class constructor has the wrong name or does not return void.')

        logger.debug("JNIEnv->NewObjectV(%s, %s, 0x%x) was called" % (clazz.value.jvm_name, method.name, args))

        # Parse arguments.
        constructor_args = self.read_args_v(mu, args, method.args_list)

        # Execute function.
        method.func(obj, self._emu, *constructor_args)

        return self.add_local_reference(jobject(obj))

    @native_method
    def new_object_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_object_class(self, mu, env):
        raise NotImplementedError()

    @native_method
    def is_instance_of(self, mu, env, obj_idx, class_idx):
        """
        Tests whether an object is an instance of a class.
        Returns JNI_TRUE if obj can be cast to clazz; otherwise, returns JNI_FALSE. A NULL object can be cast to any class.
        """
        obj = self.get_reference(obj_idx)
        if not isinstance(obj, jobject):
            raise ValueError('Expected a jobject.')

        clazz = self.get_reference(class_idx)
        if not isinstance(clazz, jclass):
            raise ValueError('Expected a jclass.')

        # TODO: Casting check (?)

        return JNI_TRUE if obj.value.jvm_id == clazz.value.jvm_id else JNI_FALSE

    @native_method
    def get_method_id(self, mu, env, clazz_idx, name_ptr, sig_ptr):
        """
        Returns the method ID for an instance (nonstatic) method of a class or interface. The method may be defined
        in one of the clazz’s superclasses and inherited by clazz. The method is determined by its name and signature.
        """
        name = memory_helpers.read_utf8(mu, name_ptr)
        sig = memory_helpers.read_utf8(mu, sig_ptr)
        clazz = self.get_reference(clazz_idx)
        logger.debug("JNIEnv->GetMethodId(%d, %s, %s) was called" % (clazz_idx, name, sig))

        if not isinstance(clazz, jclass):
            raise ValueError('Expected a jclass.')

        method = clazz.value.find_method(name, sig)

        if method is None:
            # TODO: Proper Java error?
            raise RuntimeError("Could not find method ('%s', '%s') in class %s." % (name, sig, clazz.value.jvm_name))

        return method.jvm_id

    @native_method
    def call_object_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_object_method_v(self, mu, env, obj_idx, method_id, args):
        obj = self.get_reference(obj_idx)

        if not isinstance(obj, jobject):
            raise ValueError('Expected a jobject.')

        method = obj.value.__class__.find_method_by_id(method_id)
        if method is None:
            # TODO: Proper Java error?
            raise RuntimeError("Could not find method %d in object %s by id." % (method_id, obj.value.jvm_name))

        logger.debug("JNIEnv->CallObjectMethodV(%s, %s <%s>, 0x%x) was called" % (
            obj.value.jvm_name,
            method.name,
            method.signature, args))

        # Parse arguments.
        constructor_args = self.read_args_v(mu, args, method.args_list)

        return method.func(obj.value, self._emu, *constructor_args)

    @native_method
    def call_object_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_boolean_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_boolean_method_v(self, mu, env, obj_idx, method_id, args):
        obj = self.get_reference(obj_idx)

        if not isinstance(obj, jobject):
            raise ValueError('Expected a jobject.')

        method = obj.value.__class__.find_method_by_id(method_id)

        if method is None:
            # TODO: Proper Java error?
            raise RuntimeError("Could not find method %d in object %s by id." % (method_id, obj.value.jvm_name))

        logger.debug("JNIEnv->CallBooleanMethodV(%s, %s <%s>, 0x%x) was called" % (
            obj.value.jvm_name,
            method.name,
            method.signature, args))

        # Parse arguments.
        constructor_args = self.read_args_v(mu, args, method.args_list)
        result = method.func(obj.value, self._emu, *constructor_args)

        return result

    @native_method
    def call_boolean_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_byte_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_byte_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_byte_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_char_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_char_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_char_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_short_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_short_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_short_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_int_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_int_method_v(self, mu, env,  obj_idx, method_id, args):
        obj = self.get_reference(obj_idx)

        if not isinstance(obj, jobject):
            raise ValueError('Expected a jobject.')

        method = obj.value.__class__.find_method_by_id(method_id)

        if method is None:
            # TODO: Proper Java error?
            raise RuntimeError("Could not find method %d in object %s by id." % (method_id, obj.value.jvm_name))

        logger.debug("JNIEnv->CallIntMethodV(%s, %s <%s>, 0x%x) was called" % (
            obj.value.jvm_name,
            method.name,
            method.signature, args))

        # Parse arguments.
        constructor_args = self.read_args_v(mu, args, method.args_list)
        result = method.func(obj.value, self._emu, *constructor_args)

        return result

    @native_method
    def call_int_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_long_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_long_method_v(self, mu, env, obj_idx, method_id, args):
        obj = self.get_reference(obj_idx)

        if not isinstance(obj, jobject):
            raise ValueError('Expected a jobject.')

        method = obj.value.__class__.find_method_by_id(method_id)

        if method is None:
            # TODO: Proper Java error?
            raise RuntimeError("Could not find method %d in object %s by id." % (method_id, obj.value.jvm_name))

        logger.debug("JNIEnv->CallLongMethodV(%s, %s <%s>, 0x%x) was called" % (
            obj.value.jvm_name,
            method.name,
            method.signature, args))

        # Parse arguments.
        constructor_args = self.read_args_v(mu, args, method.args_list)

        return method.func(obj.value, self._emu, *constructor_args)

    @native_method
    def call_long_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_float_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_float_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_float_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_double_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_double_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_double_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_void_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_void_method_v(self, mu, env, obj_idx, method_id, args):
        obj = self.get_reference(obj_idx)

        if not isinstance(obj, jobject):
            raise ValueError('Expected a jobject.')

        method = obj.value.__class__.find_method_by_id(method_id)

        if method is None:
            # TODO: Proper Java error?
            raise RuntimeError("Could not find method %d in object %s by id." % (method_id, obj.value.jvm_name))

        logger.debug("JNIEnv->CallVoidMethodV(%s, %s <%s>, 0x%x) was called" % (
            obj.value.jvm_name,
            method.name,
            method.signature, args))

        method.func(obj.value, self._emu)

        return None

    @native_method
    def call_void_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_object_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_object_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_object_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_boolean_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_boolean_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_boolean_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_byte_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_byte_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_byte_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_char_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_char_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_char_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_short_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_short_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_short_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_int_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_int_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_int_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_long_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_long_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_long_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_float_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_float_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_float_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_double_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_double_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_double_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_void_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_void_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_nonvirtual_void_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_field_id(self, mu, env, clazz_idx, name_ptr, sig_ptr):
        """
        Returns the field ID for an instance (nonstatic) field of a class. The field is specified by its name and
        signature. The Get<type>Field and Set<type>Field families of accessor functions use field IDs to retrieve
        object fields.
        """
        name = memory_helpers.read_utf8(mu, name_ptr)
        sig = memory_helpers.read_utf8(mu, sig_ptr)
        clazz = self.get_reference(clazz_idx)

        logger.debug("JNIEnv->GetFieldId(%d, %s, %s) was called" % (clazz_idx, name, sig))

        field = clazz.value.find_field(name, sig, False)

        if field is None:
            # TODO: Proper Java error?
            raise RuntimeError("Could not find field ('%s', '%s') in class %s." % (name, sig, clazz.value.jvm_name))

        if field.ignore:
            return 0

        return field.jvm_id

    @native_method
    def get_object_field(self, mu, env, obj_idx, field_id):
        obj = self.get_reference(obj_idx)

        if not isinstance(obj, jobject):
            raise ValueError('Expected a jobject.')

        field = obj.value.__class__.find_field_by_id(field_id)

        if field is None:
            # TODO: Proper Java error?
            raise RuntimeError("Could not find field %d in object %s by id." % (field_id, obj.value.jvm_name))

        logger.debug("JNIEnv->GetObjectField(%s, %s <%s>) was called" % (obj.value.jvm_name,
                                                                         field.name,
                                                                         field.signature))

        return getattr(obj.value, field.name)

    @native_method
    def get_boolean_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_byte_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_char_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_short_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_int_field(self, mu, env, obj_idx, field_id):
        obj = self.get_reference(obj_idx)

        if not isinstance(obj, jobject):
            raise ValueError('Expected a jobject.')

        field = obj.value.__class__.find_field_by_id(field_id)

        if field is None:
            # TODO: Proper Java error?
            raise RuntimeError("Could not find field %d in object %s by id." % (field_id, obj.value.jvm_name))

        logger.debug("JNIEnv->GetIntField(%s, %s <%s>) was called" % (obj.value.jvm_name,
                                                                      field.name,
                                                                      field.signature))

        return getattr(obj.value, field.name)

    @native_method
    def get_long_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_float_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_double_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_object_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_boolean_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_byte_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_char_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_short_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_int_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_long_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_float_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_double_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_static_method_id(self, mu, env, clazz_idx, name_ptr, sig_ptr):
        """
        Returns the method ID for a static method of a class. The method is specified by its name and signature.
        """
        name = memory_helpers.read_utf8(mu, name_ptr)
        sig = memory_helpers.read_utf8(mu, sig_ptr)
        clazz = self.get_reference(clazz_idx)

        logger.debug("JNIEnv->GetStaticMethodId(%d, %s, %s) was called" % (clazz_idx, name, sig))

        if not isinstance(clazz, jclass):
            raise ValueError('Expected a jclass.')

        method = clazz.value.find_method(name, sig)

        if method is None:
            # TODO: Proper Java error?
            raise RuntimeError(
                "Could not find static method ('%s', '%s') in class %s." % (name, sig, clazz.value.jvm_name))

        if method.ignore:
            return 0

        return method.jvm_id

    @native_method
    def call_static_object_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_object_method_v(self, mu, env, clazz_idx, method_id, args):
        clazz = self.get_reference(clazz_idx)

        if not isinstance(clazz, jclass):
            raise ValueError('Expected a jclass.')

        method = clazz.value.find_method_by_id(method_id)

        if method is None:
            # TODO: Proper Java error?
            raise RuntimeError("Could not find method %d in class %s by id." % (method_id, clazz.value.jvm_name))

        logger.debug("JNIEnv->CallStaticObjectMethodV(%s, %s <%s>, 0x%x) was called" % (
            clazz.value.jvm_name,
            method.name,
            method.signature, args))

        # Parse arguments.
        constructor_args = self.read_args_v(mu, args, method.args_list)

        return method.func(self._emu, *constructor_args)

    @native_method
    def call_static_object_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_boolean_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_boolean_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_boolean_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_byte_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_byte_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_byte_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_char_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_char_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_char_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_short_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_short_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_short_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_int_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_int_method_v(self, mu, env, clazz_idx, method_id, args):
        clazz = self.get_reference(clazz_idx)

        if not isinstance(clazz, jclass):
            raise ValueError('Expected a jclass.')

        method = clazz.value.find_method_by_id(method_id)

        if method is None:
            # TODO: Proper Java error?
            raise RuntimeError("Could not find method %d in class %s by id." % (method_id, clazz.value.jvm_name))

        logger.debug("JNIEnv->CallStaticIntMethodV(%s, %s <%s>, 0x%x) was called" % (
            clazz.value.jvm_name,
            method.name,
            method.signature, args))

        # Parse arguments.
        constructor_args = self.read_args_v(mu, args, method.args_list)

        return method.func(self._emu, *constructor_args)

    @native_method
    def call_static_int_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_long_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_long_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_long_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_float_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_float_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_float_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_double_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_double_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_double_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_void_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_void_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_void_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_static_field_id(self, mu, env, clazz_idx, name_ptr, sig_ptr):
        """
        Returns the field ID for a static field of a class. The field is specified by its name and signature. The
        GetStatic<type>Field and SetStatic<type>Field families of accessor functions use field IDs to retrieve static
        fields.
        """
        name = memory_helpers.read_utf8(mu, name_ptr)
        sig = memory_helpers.read_utf8(mu, sig_ptr)
        clazz = self.get_reference(clazz_idx)

        logger.debug("JNIEnv->GetStaticFieldId(%d, %s, %s) was called" % (clazz_idx, name, sig))

        field = clazz.value.find_field(name, sig, True)

        if field is None:
            # TODO: Proper Java error?
            raise RuntimeError(
                "Could not find static field ('%s', '%s') in class %s." % (name, sig, clazz.value.jvm_name))

        return field.jvm_id

    @native_method
    def get_static_object_field(self, mu, env, clazz_idx, field_id):
        logger.debug("JNIEnv->GetStaticObjectField(%d, %d) was called" % (clazz_idx, field_id))

        clazz = self.get_reference(clazz_idx)
        field = clazz.value.find_field_by_id(field_id)

        return field.static_value

    @native_method
    def get_static_boolean_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_static_byte_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_static_char_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_static_short_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_static_int_field(self, mu, env, clazz_idx, field_id):
        logger.debug("JNIEnv->GetStaticIntField(%d, %d) was called" % (clazz_idx, field_id))

        clazz = self.get_reference(clazz_idx)
        field = clazz.value.find_field_by_id(field_id)

        return field.static_value

    @native_method
    def get_static_long_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_static_float_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_static_double_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_static_object_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_static_boolean_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_static_byte_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_static_char_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_static_short_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_static_int_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_static_long_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_static_float_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_static_double_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def new_string(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_string_length(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_string_chars(self, mu, env):
        raise NotImplementedError()

    @native_method
    def release_string_chars(self, mu, env):
        raise NotImplementedError()

    @native_method
    def new_string_utf(self, mu, env, bytes_ptr):
        string = memory_helpers.read_utf8(mu, bytes_ptr)
        logger.debug("JNIEnv->NewStringUtf(%s) was called" % string)

        return self.add_local_reference(jstring(string))

    @native_method
    def get_string_utf_length(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_string_utf_chars(self, mu, env, string, is_copy_ptr):
        logger.debug("JNIEnv->GetStringUtfChars(%u, %x) was called" % (string, is_copy_ptr))

        if is_copy_ptr != 0:
            raise NotImplementedError()

        str_ref = self.get_reference(string)
        str_val = str_ref.value
        str_ptr = self._emu.native_memory.allocate(len(str_val) + 1)

        logger.debug("=> %s" % str_val)

        memory_helpers.write_utf8(mu, str_ptr, str_val)

        return str_ptr

    @native_method
    def release_string_utf_chars(self, mu, env, string, utf_ptr):
        pass

    @native_method
    def get_array_length(self, mu, env, array):
        logger.debug("JNIEnv->GetArrayLength(%u) was called" % array)

        obj = self.get_reference(array)

        if not isinstance(obj, jarray):
            raise ValueError('Expected a jarray.')

        return len(obj.value)

    @native_method
    def new_object_array(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_object_array_element(self, mu, env, array_idx, item_idx):
        logger.debug("JNIEnv->GetObjectArrayElement(%u, %u) was called" % (array_idx, item_idx))

        obj = self.get_reference(array_idx)

        if not isinstance(obj, jarray):
            raise ValueError('Expected a jarray.')

        return obj.value[item_idx]

    @native_method
    def set_object_array_element(self, mu, env):
        raise NotImplementedError()

    @native_method
    def new_boolean_array(self, mu, env):
        raise NotImplementedError()

    @native_method
    def new_byte_array(self, mu, env, bytelen):
        logger.debug("JNIEnv->NewByteArray(%u) was called" % bytelen)
        return self.add_local_reference(jbyteArray(bytelen))
        #raise NotImplementedError()

    @native_method
    def new_char_array(self, mu, env):
        raise NotImplementedError()

    @native_method
    def new_short_array(self, mu, env):
        raise NotImplementedError()

    @native_method
    def new_int_array(self, mu, env):
        raise NotImplementedError()

    @native_method
    def new_long_array(self, mu, env):
        raise NotImplementedError()

    @native_method
    def new_float_array(self, mu, env):
        raise NotImplementedError()

    @native_method
    def new_double_array(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_boolean_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_byte_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_char_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_short_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_int_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_long_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_float_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_double_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def release_boolean_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def release_byte_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def release_char_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def release_short_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def release_int_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def release_long_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def release_float_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def release_double_array_elements(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_boolean_array_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_byte_array_region(self, mu, env, array_idx, start, len_in, buf_ptr):
        logger.debug("JNIEnv->GetByteArrayRegion(%u, %u, %u, 0x%x) was called" % (array_idx, start, len_in, buf_ptr))

        obj = self.get_reference(array_idx)

        if not isinstance(obj, jbyteArray):
            raise ValueError('Expected a jbyteArray.')

        mu.mem_write(buf_ptr, bytes(obj.value[start:start + len_in]))

        return None

    @native_method
    def get_char_array_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_short_array_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_int_array_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_long_array_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_float_array_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_double_array_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_boolean_array_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_byte_array_region(self, mu, env, arrayJREF, startIndex, length, bufAddress):
        string = memory_helpers.read_byte_array(mu, bufAddress, length)
        logger.debug("JNIEnv->SetByteArrayRegion was called")
        self.set_local_reference(arrayJREF, jbyteArray(string))

    @native_method
    def set_char_array_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_short_array_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_int_array_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_long_array_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_float_array_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_double_array_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def register_natives(self, mu, env, clazz_id, methods, methods_count):
        logger.debug("JNIEnv->RegisterNatives(%d, 0x%08x, %d) was called" % (clazz_id, methods, methods_count))

        clazz = self.get_local_reference(clazz_id)

        if not isinstance(clazz, jclass):
            raise ValueError('Expected a jclass.')

        clazz = clazz.value

        for i in range(0, methods_count):
            ptr_name = memory_helpers.read_ptr(mu, (i * 12) + methods)
            ptr_sign = memory_helpers.read_ptr(mu, (i * 12) + methods + 4)
            ptr_func = memory_helpers.read_ptr(mu, (i * 12) + methods + 8)

            name = memory_helpers.read_utf8(mu, ptr_name)
            signature = memory_helpers.read_utf8(mu, ptr_sign)

            clazz.register_native(name, signature, ptr_func)

        return JNI_OK

    @native_method
    def unregister_natives(self, mu, env):
        raise NotImplementedError()

    @native_method
    def monitor_enter(self, mu, env):
        raise NotImplementedError()

    @native_method
    def monitor_exit(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_java_vm(self, mu, env, vm):
        logger.debug("JNIEnv->GetJavaVM(0x%08x) was called" % vm)

        mu.mem_write(vm, self._emu.java_vm.address_ptr.to_bytes(4, byteorder='little'))

        return JNI_OK

    @native_method
    def get_string_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_string_utf_region(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_primitive_array_critical(self, mu, env):
        raise NotImplementedError()

    @native_method
    def release_primitive_array_critical(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_string_critical(self, mu, env):
        raise NotImplementedError()

    @native_method
    def release_string_critical(self, mu, env):
        raise NotImplementedError()

    @native_method
    def new_weak_global_ref(self, mu, env):
        raise NotImplementedError()

    @native_method
    def delete_weak_global_ref(self, mu, env):
        raise NotImplementedError()

    @native_method
    def exception_check(self, mu, env):
        """
        Returns JNI_TRUE when there is a pending exception; otherwise, returns JNI_FALSE.
        """
        logger.debug("JNIEnv->ExceptionCheck() was called")
        # TODO: Implement
        return JNI_FALSE

    @native_method
    def new_direct_byte_buffer(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_direct_buffer_address(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_direct_buffer_capacity(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_object_ref_type(self, mu, env):
        raise NotImplementedError()
