import inspect
import itertools
import logging

logger = logging.getLogger(__name__)


class JavaClassDef(type):
    next_jvm_id = itertools.count(start=1)
    next_jvm_method_id = itertools.count(start=0xd2000000, step=4)

    def __init__(cls, name, base, ns, jvm_name=None):
        cls.jvm_id = next(JavaClassDef.next_jvm_id)
        cls.jvm_name = jvm_name
        cls.jvm_methods = dict()

        # Register all defined Java methods.
        for func in inspect.getmembers(cls, predicate=inspect.isfunction):
            if hasattr(func[1], 'jvm_method'):
                method = func[1].jvm_method
                method.jvm_id = next(JavaClassDef.next_jvm_method_id)
                cls.jvm_methods[method] = method

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
            raise RuntimeError("Register native ('%s', '%s') failed on class %s." % (name, signature, self.__name__))

        logger.debug("Registered native function ('%s', '%s') to %s.%s" % (name, signature,
                                                                           self.__name__, found_method.func_name))

    def find_method(cls, name, signature):
        for method in cls.jvm_methods.values():
            if method.name == name and method.signature == signature:
                return method

        return None
