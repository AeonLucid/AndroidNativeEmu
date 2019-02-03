import inspect
import itertools
import logging

logger = logging.getLogger(__name__)


class JavaClassDef(type):
    next_jvm_id = itertools.count(start=1)

    def __init__(cls, name, base, ns, jvm_name=None):
        cls.jvm_id = next(JavaClassDef.next_jvm_id)
        cls.jvm_name = jvm_name
        cls.jvm_methods = list()

        # Register all defined Java methods.
        for func in inspect.getmembers(cls, predicate=inspect.isfunction):
            if hasattr(func[1], 'jvm_method'):
                cls.jvm_methods.append(func[1].jvm_method)

        type.__init__(cls, name, base, ns)

    def __new__(mcs, name, base, ns, **kargs):
        return type.__new__(mcs, name, base, ns)

    def register_native(self, name, signature, ptr_func):
        found = False
        found_method = None

        # Search for a defined jvm method.
        for method in self.jvm_methods:
            if method.name == name and method.signature == signature:
                method.native_addr = ptr_func
                found = True
                found_method = method
                break

        if not found:
            raise RuntimeError("Register native ('%s', '%s') failed on class %s." % (name, signature, self.__name__))

        logger.debug("Registered native function ('%s', '%s') to %s.%s" % (name, signature,
                                                                           self.__name__, found_method.func_name))
