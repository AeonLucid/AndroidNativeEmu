from collections import defaultdict

from elftools.elf.elffile import SymbolTableSection


class Module:

    """
    :type filename str
    :type base_addr int
    :type size int
    :type dynsym SymbolTableSection
    """
    def __init__(self, filename, address, size, dynsym):
        self.filename = filename
        self.base_addr = address
        self.size = size
        self.symbols = ModuleSymbols(dynsym)


# Thanks to
# https://github.com/eliben/pyelftools/blob/82299758cc0c0ca788de094ee2d83f6f490a8ef4/elftools/elf/sections.py#L143
class ModuleSymbols:

    def __init__(self, dynsym):
        self._symbols = list(dynsym.iter_symbols())
        self._symbol_name_map = None

    def get_symbol_by_name(self, name):
        if self._symbol_name_map is None:
            self._symbol_name_map = defaultdict(list)
            for i, sym in enumerate(self.iter_symbols()):
                self._symbol_name_map[sym.name].append(i)

        symnums = self._symbol_name_map.get(name)

        return [self.get_symbol(i) for i in symnums] if symnums else None

    def num_symbols(self):
        return len(self._symbols)

    def get_symbol(self, n):
        return self._symbols[n]

    def iter_symbols(self):
        for i in range(self.num_symbols()):
            yield self.get_symbol(i)
