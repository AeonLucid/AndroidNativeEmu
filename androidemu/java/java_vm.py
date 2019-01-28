import logging

from unicorn import Uc
from unicorn.arm_const import *
from androidemu.hooker import Hooker
from androidemu.java.jni_const import JNI_ERR

logger = logging.getLogger(__name__)


# https://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/invocation.html
# This class attempts to mimic the Invocation API function table.
class JavaVM:

    """
    :type mu Uc
    :type hooker Hooker
    """
    def __init__(self, mu, hooker):
        self._mu = mu
        (self.address_ptr, self.address) = hooker.write_function_table({
            3: self.destroy_java_vm,
            4: self.attach_current_thread,
            5: self.detach_current_thread,
            6: self.get_env,
            7: self.attach_current_thread
        })

    def destroy_java_vm(self):
        pass

    def attach_current_thread(self):
        pass

    def detach_current_thread(self):
        pass

    def get_env(self):
        self._mu.mem_write(self._mu.reg_read(UC_ARM_REG_R1), b"\x01")   # Write address of the JEnv
        self._mu.reg_write(UC_ARM_REG_R0, JNI_ERR)                      # Write 0 to respond succes

        logger.debug("JavaVM->GetENV() was called!")

    def attach_current_thread_as_daemon(self):
        pass
