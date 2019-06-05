import logging

from androidemu.emulator_error import EmulatorError
from androidemu.java.classes.executable import Executable
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def, JavaMethodDef

logger = logging.getLogger(__name__)


class Method(metaclass=JavaClassDef,
             jvm_name='java/lang/reflect/Method',
             jvm_fields=[
                 JavaFieldDef('slot', 'I', False, ignore=True),
                 JavaFieldDef('declaringClass', 'Ljava/lang/Class;', False),
             ],
             jvm_super=Executable):

    def __init__(self, clazz: JavaClassDef, method: JavaMethodDef):
        super().__init__()
        self._clazz = clazz
        self._method = method
        self.slot = method.jvm_id
        self.declaringClass = self._clazz
        self.accessFlags = method.modifier

    @staticmethod
    @java_method_def(
        name="getMethodModifiers",
        signature="(Ljava/lang/Class;I)I",
        args_list=['jobject', 'jint'],
        ignore=True
    )
    def get_method_modifiers(emu, clazz_obj, jvm_method_id):
        clazz = clazz_obj.value
        method = clazz.find_method_by_id(jvm_method_id)

        logger.debug('get_method_modifiers(%s, %s)' % (clazz.jvm_name, method.name))

        if method.modifier is None:
            raise EmulatorError('No modifier was given to class %s method %s' % (clazz.jvm_name, method.name))

        return method.modifier
