class jvalue:

    def __init__(self, value=None):
        self.value = value


class jobject:

    def __init__(self, value=None):
        self.value = value


class jclass(jobject):

    def __init__(self, value=None):
        super().__init__(value)


class jstring(jobject):

    def __init__(self, value=None):
        super().__init__(value)


class jarray(jobject):

    def __init__(self, value=None):
        super().__init__(value)


class jobjectArray(jarray):

    def __init__(self, value=None):
        super().__init__(value)


class jbooleanArray(jarray):

    def __init__(self, value=None):
        super().__init__(value)


class jbyteArray(jarray):

    def __init__(self, value=None):
        super().__init__(value)


class jcharArray(jarray):

    def __init__(self, value=None):
        super().__init__(value)


class jshortArray(jarray):

    def __init__(self, value=None):
        super().__init__(value)


class jintArray(jarray):

    def __init__(self, value=None):
        super().__init__(value)


class jlongArray(jarray):

    def __init__(self, value=None):
        super().__init__(value)


class jfloatArray(jarray):

    def __init__(self, value=None):
        super().__init__(value)


class jdoubleArray(jarray):

    def __init__(self, value=None):
        super().__init__(value)


class jthrowable(jobject):

    def __init__(self, value=None):
        super().__init__(value)


