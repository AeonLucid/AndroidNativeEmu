import logging

from androidemu.hooker import Hooker
from androidemu.java.helpers.native_method import native_method
from androidemu.java.java_classloader import JavaClassLoader
from androidemu.java.jni_const import *
from androidemu.java.jni_env import JNIEnv

logger = logging.getLogger(__name__)


# https://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/invocation.html
# This class attempts to mimic the JNIInvokeInterface table.
class JavaVM:

    """
    :type class_loader JavaClassLoader
    :type hooker Hooker
    """
    def __init__(self, emu, class_loader, hooker):
        (self.address_ptr, self.address) = hooker.write_function_table({
            3: self.destroy_java_vm,
            4: self.attach_current_thread,
            5: self.detach_current_thread,
            6: self.get_env,
            7: self.attach_current_thread
        })

        self.jni_env = JNIEnv(emu, class_loader, hooker)

    @native_method
    def destroy_java_vm(self, mu):
        raise NotImplementedError()

    @native_method
    def attach_current_thread(self, mu):
        raise NotImplementedError()

    @native_method
    def detach_current_thread(self, mu):
        # TODO: NooOO idea.
        pass

    @native_method
    def get_env(self, mu, java_vm, env, version):
        logger.debug("java_vm: 0x%08x" % java_vm)
        logger.debug("env: 0x%08x" % env)
        logger.debug("version: 0x%08x" % version)

        mu.mem_write(env, self.jni_env.address_ptr.to_bytes(4, byteorder='little'))

        logger.debug("JavaVM->GetENV() was called!")

        return JNI_OK

    @native_method
    def attach_current_thread_as_daemon(self, mu):
        raise NotImplementedError()
