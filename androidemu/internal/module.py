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
        self.symbol_lookup = dict()

        # Create fast lookup.
        for symbol_name, symbol in self.symbols.items():
            if symbol.address != 0:
                self.symbol_lookup[symbol.address] = (symbol_name, symbol)

    def find_symbol(self, name):
        if name in self.symbols:
            return self.symbols[name]

        return None
