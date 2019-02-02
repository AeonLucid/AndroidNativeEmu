class Module:

    """
    :type filename str
    :type base int
    :type size int
    """
    def __init__(self, filename, address, size, symbols_resolved):
        self.filename = filename
        self.base = address
        self.size = size
        self.symbols = symbols_resolved

    def find_symbol(self, name):
        if name in self.symbols:
            return self.symbols[name]

        return None
