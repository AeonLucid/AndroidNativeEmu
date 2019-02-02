class Module:

    """
    :type filename str
    :type base_addr int
    :type size int
    """
    def __init__(self, filename, address, size, symbols_resolved):
        self.filename = filename
        self.base_addr = address
        self.size = size
        self.symbols = symbols_resolved
