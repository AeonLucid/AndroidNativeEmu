import itertools


class JavaClassDef(type):
    next_jvm_id = itertools.count(start=1)

    def __init__(cls, name, base, ns, jvm_name=None):
        cls.jvm_id = next(JavaClassDef.next_jvm_id)
        cls.jvm_name = jvm_name
        cls.jvm_natives = list()
        type.__init__(cls, name, base, ns)

    def __new__(mcs, name, base, ns, **kargs):
        return type.__new__(mcs, name, base, ns)

    def register_native(self, name, signature, ptr_func):
        self.jvm_natives.append((name, signature, ptr_func))
