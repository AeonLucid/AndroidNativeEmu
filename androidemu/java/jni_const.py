JNI_FALSE = 0
JNI_TRUE = 1

JNI_VERSION_1_1 = 0x00010001
JNI_VERSION_1_2 = 0x00010002
JNI_VERSION_1_4 = 0x00010004
JNI_VERSION_1_6 = 0x00010006

JNI_OK = 0  # no error
JNI_ERR = -1  # generic error
JNI_EDETACHED = -2  # thread detached from the VM
JNI_EVERSION = -3  # JNI version error
JNI_ENOMEM = -4  # Out of memory
JNI_EEXIST = -5  # VM already created
JNI_EINVAL = -6  # Invalid argument

JNI_COMMIT = 1  # copy content, do not free buffer
JNI_ABORT = 2  # free buffer w/o copying back
