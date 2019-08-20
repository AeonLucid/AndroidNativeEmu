from androidemu.java.classes.executable import Executable
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import JavaMethodDef

class Constructor(metaclass=JavaClassDef,
                  jvm_name = 'java/lang/reflect/Constructor',
                  jvm_fields=[
                      JavaFieldDef('slot', 'I', False, ignore=True),
                      JavaFieldDef('declaringClass', 'Ljava/lang/Class;', False)],
                  jvm_super=Executable):

    def __init__(self, clazz: JavaClassDef, method: JavaMethodDef):
        self._clazz = clazz
        self._method = method
        self.slot = method.jvm_id
        self.declaringClass = self._clazz
        self.accessFlags = method.modifier
