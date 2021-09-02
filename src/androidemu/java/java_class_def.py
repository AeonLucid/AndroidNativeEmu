import inspect
import itertools
import logging

logger = logging.getLogger(__name__)


class JavaClassDef(type):
    next_jvm_id = itertools.count(start=1)
    next_jvm_method_id = itertools.count(start=0xd2000000, step=4)
    next_jvm_field_id = itertools.count(start=0xe2000000, step=4)

    def __init__(cls, name, base, ns, jvm_name=None, jvm_fields=None, jvm_ignore=False, jvm_super=None):
        cls.jvm_id = next(JavaClassDef.next_jvm_id)
        cls.jvm_name = jvm_name
        cls.jvm_methods = dict()
        cls.jvm_fields = dict()
        cls.jvm_ignore = jvm_ignore
        cls.jvm_super = jvm_super

        # Register all defined Java methods.
        for func in inspect.getmembers(cls, predicate=inspect.isfunction):
            if hasattr(func[1], 'jvm_method'):
                method = func[1].jvm_method
                method.jvm_id = next(JavaClassDef.next_jvm_method_id)
                cls.jvm_methods[method.jvm_id] = method

        # Register all defined Java fields.
        if jvm_fields is not None:
            for jvm_field in jvm_fields:
                jvm_field.jvm_id = next(JavaClassDef.next_jvm_field_id)
                cls.jvm_fields[jvm_field.jvm_id] = jvm_field

        type.__init__(cls, name, base, ns)

    def __new__(mcs, name, base, ns, **kargs):
        return type.__new__(mcs, name, base, ns)

    def register_native(self, name, signature, ptr_func):
        found = False
        found_method = None

        # Search for a defined jvm method.
        for method in self.jvm_methods.values():
            if method.name == name and method.signature == signature:
                method.native_addr = ptr_func
                found = True
                found_method = method
                break

        if not found:
            x = "Register native ('%s', '%s') failed on class %s." % (name, signature, self.__name__)
            logger.warning(x)
            return
            # raise RuntimeError("Register native ('%s', '%s') failed on class %s." % (name, signature, self.__name__))
        logger.debug("Registered native function ('%s', '%s') to %s.%s" % (name, signature,
                                                                           self.__name__, found_method.func_name))

    def find_method(cls, name, signature):
        for method in cls.jvm_methods.values():
            if method.name == name and method.signature == signature:
                return method

        return None

    def find_method_by_id(cls, jvm_id):
        return cls.jvm_methods[jvm_id]

    def find_field(cls, name, signature, is_static):
        for field in cls.jvm_fields.values():
            if field.name == name and field.signature == signature and field.is_static == is_static:
                return field

        return None

    def find_field_by_id(cls, jvm_id):
        try:
            if cls.jvm_super is not None:
                return cls.jvm_super.find_field_by_id(jvm_id)
        except KeyError:
            pass

        return cls.jvm_fields[jvm_id]
