import logging

from androidemu.hooker import Hooker
from androidemu.java.helpers.native_method import native_method
from androidemu.java.jni_const import *

logger = logging.getLogger(__name__)


# https://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/invocation.html
# This class attempts to mimic the JNIInvokeInterface table.
class JavaVM:

    """
    :type hooker Hooker
    """
    def __init__(self, hooker):
        (self.address_ptr, self.address) = hooker.write_function_table({
            3: self.destroy_java_vm,
            4: self.attach_current_thread,
            5: self.detach_current_thread,
            6: self.get_env,
            7: self.attach_current_thread
        })

    @native_method
    def destroy_java_vm(self, mu):
        pass

    @native_method
    def attach_current_thread(self, mu):
        pass

    @native_method
    def detach_current_thread(self, mu):
        pass

    @native_method
    def get_env(self, mu, java_vm, env, version):
        logger.debug("java_vm: 0x%08x" % java_vm)
        logger.debug("env: 0x%08x" % env)
        logger.debug("version: 0x%08x" % version)

        mu.mem_write(env, b"\x01")

        logger.debug("JavaVM->GetENV() was called!")

        return JNI_ERR

    @native_method
    def attach_current_thread_as_daemon(self, mu):
        pass
