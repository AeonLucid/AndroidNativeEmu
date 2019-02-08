class JavaFieldDef:

    def __init__(self, name, signature, is_static):
        self.jvm_id = None  # Assigned by JavaClassDef.
        self.name = name
        self.signature = signature
        self.is_static = is_static
