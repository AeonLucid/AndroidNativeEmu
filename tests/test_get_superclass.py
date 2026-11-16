"""GetSuperclass should use jvm_super, not Python __mro__."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.jni_env import JNIEnv


class Animal(metaclass=JavaClassDef, jvm_name='demo/Animal'):
    pass


class Dog(metaclass=JavaClassDef, jvm_name='demo/Dog', jvm_super=Animal):
    pass


class TestGetSuperclass(unittest.TestCase):
    def test_jvm_super_not_mro(self):
        # Python MRO parent is object; Java parent is Animal
        self.assertIs(Dog.__mro__[1], object)
        self.assertIs(Dog.jvm_super, Animal)

        self.assertIs(JNIEnv._java_superclass(Dog), Animal)
        self.assertIsNone(JNIEnv._java_superclass(Animal))

    def test_old_mro_path_would_be_wrong(self):
        # What the old get_superclass returned via __mro__[1]
        self.assertIs(Dog.__mro__[1], object)
        self.assertIsNot(Dog.__mro__[1], Animal)

    def test_invalid_jvm_super_treated_as_none(self):
        class Broken(metaclass=JavaClassDef, jvm_name='demo/Broken'):
            pass

        Broken.jvm_super = 'not-a-class'
        self.assertIsNone(JNIEnv._java_superclass(Broken))


if __name__ == '__main__':
    unittest.main()
