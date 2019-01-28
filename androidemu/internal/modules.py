import logging

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from unicorn import UC_PROT_ALL

from androidemu.internal import get_segment_protection, arm
from androidemu.internal.module import Module

logger = logging.getLogger(__name__)


class Modules:

    """
    :type emu androidemu.emulator.Emulator
    :type modules list[Module]
    """
    def __init__(self, emu):
        self.emu = emu
        self.modules = list()

    def load_module(self, filename):
        logger.debug("Loading module '%s'." % filename)

        with open(filename, 'rb') as fstream:
            elf = ELFFile(fstream)

            dynamic = elf.header.e_type == 'ET_DYN'

            if not dynamic:
                raise NotImplementedError("Only ET_DYN is supported at the moment.")

            # Parse program header (Execution view).

            # - LOAD (determinate what parts of the ELF file get mapped into memory)
            load_segments = [x for x in elf.iter_segments() if x.header.p_type == 'PT_LOAD']

            # Find bounds of the load segments.
            bound_low = 0
            bound_high = 0

            for segment in load_segments:
                if segment.header.p_memsz == 0:
                    continue

                if bound_low > segment.header.p_vaddr:
                    bound_low = segment.header.p_vaddr

                high = segment.header.p_vaddr + segment.header.p_memsz

                if bound_high < high:
                    bound_high = high

            # Retrieve a base address for this module.
            load_base = self.emu.memory.mem_reserve(bound_high - bound_low)

            for segment in load_segments:
                prot = get_segment_protection(segment.header.p_flags)
                prot = prot if prot is not 0 else UC_PROT_ALL

                self.emu.memory.mem_map(load_base + segment.header.p_vaddr, segment.header.p_memsz, prot)
                self.emu.memory.mem_write(load_base + segment.header.p_vaddr, segment.data())

            # Parse section header (Linking view).
            dynsym = elf.get_section_by_name(".dynsym")
            dynstr = elf.get_section_by_name(".dynstr")

            # Relocate.
            for section in elf.iter_sections():
                if not isinstance(section, RelocationSection):
                    continue

                for rel in section.iter_relocations():
                    sym = dynsym.get_symbol(rel['r_info_sym'])
                    sym_value = sym['st_value']

                    rel_addr = load_base + rel['r_offset']  # Location where relocation should happen
                    rel_info_type = rel['r_info_type']

                    # Relocation table for ARM
                    if rel_info_type == arm.R_ARM_ABS32:
                        # Create the new value.
                        value = load_base + sym_value

                        # Write the new value
                        self.emu.mu.mem_write(rel_addr, value.to_bytes(4, byteorder='little'))
                    elif rel_info_type == arm.R_ARM_GLOB_DAT or rel_info_type == arm.R_ARM_JUMP_SLOT:
                        # Resolve the symbol.
                        (sym_base, resolved_symbol) = self._resolv_symbol(load_base, dynsym, sym)

                        if resolved_symbol is None:
                            logger.debug("=> Unable to resolve symbol: %s" % sym.name)
                            continue

                        # Create the new value.
                        value = sym_base + resolved_symbol['st_value']

                        # Write the new value
                        self.emu.mu.mem_write(rel_addr, value.to_bytes(4, byteorder='little'))
                    elif rel_info_type == arm.R_ARM_RELATIVE:
                        if sym_value == 0:
                            # Load address at which it was linked originally.
                            value_orig_bytes = self.emu.mu.mem_read(rel_addr, 4)
                            value_orig = int.from_bytes(value_orig_bytes, byteorder='little')

                            # Create the new value
                            value = load_base + value_orig

                            # Write the new value
                            self.emu.mu.mem_write(rel_addr, value.to_bytes(4, byteorder='little'))
                        else:
                            raise NotImplementedError()
                    else:
                        logger.error("Unhandled relocation type %i." % rel_info_type)

            # Store information about loaded module.
            self.modules.append(Module(filename, load_base, bound_high - bound_low, dynsym))

            return load_base

    def _resolv_symbol(self, load_base, symbol_table, symbol):
        # First we check our own symbol table.
        symbols = symbol_table.get_symbol_by_name(symbol.name)
        symbol = symbols[0]

        if symbol['st_shndx'] != 'SHN_UNDEF':
            return load_base, symbol

        # Next we check previously discovered symbol tables.
        for module in self.modules:
            symbols = module.symbols.get_symbol_by_name(symbol.name)

            if symbols is None:
                continue

            for symbol in symbols:
                if symbol['st_shndx'] != 'SHN_UNDEF':
                    return module.base_addr, symbol

        return None, None

    def __iter__(self):
        for x in self.modules:
            yield x
