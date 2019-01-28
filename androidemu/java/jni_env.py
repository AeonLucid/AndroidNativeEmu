import logging

from androidemu.hooker import Hooker
from androidemu.java.helpers.native_method import native_method
from androidemu.java.jni_const import *
from androidemu.utils import memory_helpers

logger = logging.getLogger(__name__)


# This class attempts to mimic the JNINativeInterface table.
class JNIEnv:

    """
    :type hooker Hooker
    """
    def __init__(self, hooker):
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

        # TODO: Actually retrieve a class id from a class map.
        name = memory_helpers.read_utf8(mu, name_ptr)
        logger.debug(name)
        return 0xFF

    @native_method
    def from_reflected_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def from_reflected_field(self, mu, env):
        raise NotImplementedError()

    @native_method
    def to_reflected_method(self, mu, env):
        raise NotImplementedError()

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
        raise NotImplementedError()

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
    def new_global_ref(self, mu, env):
        raise NotImplementedError()

    @native_method
    def delete_global_ref(self, mu, env):
        raise NotImplementedError()

    @native_method
    def delete_local_ref(self, mu, env):
        raise NotImplementedError()

    @native_method
    def is_same_object(self, mu, env):
        raise NotImplementedError()

    @native_method
    def new_local_ref(self, mu, env):
        raise NotImplementedError()

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
    def new_object_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def new_object_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_object_class(self, mu, env):
        raise NotImplementedError()

    @native_method
    def is_instance_of(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_method_id(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_object_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_object_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_object_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_boolean_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_boolean_method_v(self, mu, env):
        raise NotImplementedError()

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
    def call_int_method_v(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_int_method_a(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_long_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_long_method_v(self, mu, env):
        raise NotImplementedError()

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
    def call_void_method_v(self, mu, env):
        raise NotImplementedError()

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
    def get_field_id(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_object_field(self, mu, env):
        raise NotImplementedError()

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
    def get_int_field(self, mu, env):
        raise NotImplementedError()

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
    def get_static_method_id(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_object_method(self, mu, env):
        raise NotImplementedError()

    @native_method
    def call_static_object_method_v(self, mu, env):
        raise NotImplementedError()

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
    def call_static_int_method_v(self, mu, env):
        raise NotImplementedError()

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
    def get_static_field_id(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_static_object_field(self, mu, env):
        raise NotImplementedError()

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
    def get_static_int_field(self, mu, env):
        raise NotImplementedError()

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
    def new_string_utf(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_string_utf_length(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_string_utf_chars(self, mu, env):
        raise NotImplementedError()

    @native_method
    def release_string_utf_chars(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_array_length(self, mu, env):
        raise NotImplementedError()

    @native_method
    def new_object_array(self, mu, env):
        raise NotImplementedError()

    @native_method
    def get_object_array_element(self, mu, env):
        raise NotImplementedError()

    @native_method
    def set_object_array_element(self, mu, env):
        raise NotImplementedError()

    @native_method
    def new_boolean_array(self, mu, env):
        raise NotImplementedError()

    @native_method
    def new_byte_array(self, mu, env):
        raise NotImplementedError()

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
    def get_byte_array_region(self, mu, env):
        raise NotImplementedError()

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
    def set_byte_array_region(self, mu, env):
        raise NotImplementedError()

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
    def register_natives(self, mu, env, clazz, methods, methods_count):
        for i in range(0, methods_count):
            ptr_name = memory_helpers.read_ptr(mu, (i * 12) + methods)
            ptr_sign = memory_helpers.read_ptr(mu, (i * 12) + methods + 4)
            ptr_func = memory_helpers.read_ptr(mu, (i * 12) + methods + 8)

            name = memory_helpers.read_utf8(mu, ptr_name)
            signature = memory_helpers.read_utf8(mu, ptr_sign)

            print(name, signature, "%x" % ptr_func)

        # TODO: Store these so we can call them.

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
    def get_java_vm(self, mu, env):
        raise NotImplementedError()

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
        raise NotImplementedError()

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
