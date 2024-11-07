import logging

import elftools
import elftools.elf
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from elftools.elf.sections import StringTableSection
import elftools.elf.sections
from unicorn import UC_PROT_ALL

from androidemu.internal import get_segment_protection, arm
from androidemu.internal.module import Module
from androidemu.internal.symbol_resolved import SymbolResolved

import struct

from androidemu.memory import align

logger = logging.getLogger(__name__)


class Modules:
    """
    :type emu androidemu.emulator.Emulator
    :type modules list[Module]
    """
    def __init__(self, emu):
        self.emu = emu
        self.modules = list()
        self.symbol_hooks = dict()

    def add_symbol_hook(self, symbol_name, addr):
        self.symbol_hooks[symbol_name] = addr

    def find_symbol(self, addr):
        for module in self.modules:
            if addr in module.symbol_lookup:
                return module.symbol_lookup[addr]
        return None, None

    def find_symbol_name(self, name):
        return self._elf_lookup_symbol(name)

    def find_module(self, addr):
        for module in self.modules:
            if module.base == addr:
                return module
        return None

    def find_section_index(self, elf, addr):
        for idx, section in enumerate(elf.iter_sections()):
            if section.header['sh_addr'] <= addr < (section.header['sh_addr'] + section.header['sh_size']):
                return idx
        return 0

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
            (load_base, _) = self.emu.memory_manager.reserve_module(bound_high - bound_low)

            logger.debug('=> Base address: 0x%x' % load_base)

            for segment in load_segments:
                prot = get_segment_protection(segment.header.p_flags)
                prot = prot if prot != 0 else UC_PROT_ALL

                (seg_addr, seg_size) = align(load_base + segment.header.p_vaddr, segment.header.p_memsz, True)

                self.emu.uc.mem_map(seg_addr, seg_size, prot)
                self.emu.uc.mem_write(load_base + segment.header.p_vaddr, segment.data())

            rel_section = None
            for section in elf.iter_sections():
                if not isinstance(section, RelocationSection):
                    continue
                rel_section = section
                break

            # Parse section header (Linking view).
            dynsym = elf.get_section_by_name(".dynsym")
            dynstr = elf.get_section_by_name(".dynstr")

            # Find rel section if not found.
            if rel_section is None or dynsym is None or dynstr is None:
                rel_info = {
                    'rel': {'addr': None, 'size': None, 'entsize': None, 'count': None},
                    'rela': {'addr': None, 'size': None, 'entsize': None, 'count': None},
                    'sym': None,
                    'type': None
                }
                
                sym_info = {
                    'dynsym': {'addr': None, 'size': None, 'entsize': None},
                    'dynstr': {'addr': None, 'size': None}
                }

                # get information from dynamic segment
                for segment in elf.iter_segments():
                    if segment.header.p_type == 'PT_DYNAMIC':
                        for tag in segment.iter_tags():
                            # find relocation table
                            if tag.entry.d_tag == 'DT_REL':
                                rel_info['rel']['addr'] = tag.entry.d_val
                            elif tag.entry.d_tag == 'DT_RELSZ':
                                rel_info['rel']['size'] = tag.entry.d_val
                            elif tag.entry.d_tag == 'DT_RELENT':
                                rel_info['rel']['entsize'] = tag.entry.d_val
                            elif tag.entry.d_tag == 'DT_RELCOUNT':
                                rel_info['rel']['count'] = tag.entry.d_val
                            
                            # find relocation table with addend
                            elif tag.entry.d_tag == 'DT_RELA':
                                rel_info['rela']['addr'] = tag.entry.d_val
                            elif tag.entry.d_tag == 'DT_RELASZ':
                                rel_info['rela']['size'] = tag.entry.d_val
                            elif tag.entry.d_tag == 'DT_RELAENT':
                                rel_info['rela']['entsize'] = tag.entry.d_val
                            elif tag.entry.d_tag == 'DT_RELACOUNT':
                                rel_info['rela']['count'] = tag.entry.d_val
                            
                            # find symbol table
                            elif tag.entry.d_tag == 'DT_SYMTAB':
                                rel_info['sym'] = self.find_section_index(elf, tag.entry.d_val)
                                sym_info['dynsym']['addr'] = tag.entry.d_val
                            elif tag.entry.d_tag == 'DT_STRTAB':
                                sym_info['dynstr']['addr'] = tag.entry.d_val
                            elif tag.entry.d_tag == 'DT_STRSZ':
                                sym_info['dynstr']['size'] = tag.entry.d_val
                            elif tag.entry.d_tag == 'DT_SYMENT':
                                sym_info['dynsym']['entsize'] = tag.entry.d_val

                if rel_section is None:
                    if rel_info['rel']['addr'] and rel_info['rel']['size']:
                        rel_info['type'] = 'REL'
                        active_rel = rel_info['rel']
                        has_reloc_info = True
                    elif rel_info['rela']['addr'] and rel_info['rela']['size']:
                        rel_info['type'] = 'RELA'
                        active_rel = rel_info['rela']
                        has_reloc_info = True
                    else:
                        has_reloc_info = False

                    if has_reloc_info and active_rel['addr'] and active_rel['size'] and active_rel['entsize']:
                        is_rela = rel_info['type'] == 'RELA'
                        fake_rel_header = {
                            'sh_name': 0, # we don't know the name
                            'sh_type': 'SHT_RELA' if is_rela else 'SHT_REL',
                            'sh_flags': 2,
                            'sh_addr': active_rel['addr'],
                            'sh_offset': active_rel['addr'],
                            'sh_size': active_rel['size'],
                            'sh_link': rel_info['sym'], # link to dynsym
                            'sh_info': 0,
                            'sh_addralign': 8 if elf.elfclass == 64 else 4,
                            'sh_entsize': active_rel['entsize']
                        }
                        rel_section = RelocationSection(fake_rel_header, 
                                                    '.rela.dyn' if is_rela else '.rel.dyn',
                                                    elf)

                # create dynsym and dynstr if not found
                if dynstr is None or dynsym is None:
                    # calculate dynsym size
                    if sym_info['dynsym']['addr'] and sym_info['dynstr']['addr']:
                        sym_info['dynsym']['size'] = sym_info['dynstr']['addr'] - sym_info['dynsym']['addr']

                    if dynstr is None and sym_info['dynstr']['addr'] and sym_info['dynstr']['size']:
                        fake_str_header = {
                            'sh_name': 0,
                            'sh_type': 'SHT_STRTAB',
                            'sh_flags': 2,
                            'sh_addr': sym_info['dynstr']['addr'],
                            'sh_offset': sym_info['dynstr']['addr'],
                            'sh_size': sym_info['dynstr']['size'],
                            'sh_link': 0,
                            'sh_info': 0,
                            'sh_addralign': 1,
                            'sh_entsize': 0
                        }
                        dynstr = StringTableSection(fake_str_header, '.dynstr', elf)

                    if dynsym is None and dynstr is not None and \
                    sym_info['dynsym']['addr'] and sym_info['dynsym']['size']:
                        fake_sym_header = {
                            'sh_name': 0,
                            'sh_type': 'SHT_DYNSYM',
                            'sh_flags': 2,
                            'sh_addr': sym_info['dynsym']['addr'],
                            'sh_offset': sym_info['dynsym']['addr'],
                            'sh_size': sym_info['dynsym']['size'],
                            'sh_link': self.find_section_index(elf, sym_info['dynstr']['addr']), # link to dynstr
                            'sh_info': 0, # we don't know the index of the first non-local symbol
                            'sh_addralign': 8 if elf.elfclass == 64 else 4,
                            'sh_entsize': sym_info['dynsym']['entsize']
                        }
                        dynsym = SymbolTableSection(fake_sym_header, '.dynsym', elf, dynstr)

            # Find init array.
            init_array_size = 0
            init_array_offset = 0
            init_array = []
            for x in elf.iter_segments():
                if x.header.p_type == "PT_DYNAMIC":
                    for tag in x.iter_tags():
                        if tag.entry.d_tag == "DT_INIT_ARRAYSZ":
                            init_array_size = tag.entry.d_val
                        elif tag.entry.d_tag == "DT_INIT_ARRAY":
                            init_array_offset = tag.entry.d_val

            for _ in range(int(init_array_size / 4)):
                # covert va to file offset
                for seg in load_segments:
                    if seg.header.p_vaddr <= init_array_offset < seg.header.p_vaddr + seg.header.p_memsz:
                        init_array_foffset = init_array_offset - seg.header.p_vaddr + seg.header.p_offset
                fstream.seek(init_array_foffset)
                data = fstream.read(4)
                fun_ptr = struct.unpack('I', data)[0]
                if fun_ptr != 0:
                    # fun_ptr += load_base
                    init_array.append(fun_ptr + load_base)
                    # print ("find init array for :%s %x" % (filename, fun_ptr))
                else:
                    # search in reloc
                    for rel in rel_section.iter_relocations():
                        rel_info_type = rel['r_info_type']
                        rel_addr = rel['r_offset']
                        if rel_info_type == arm.R_ARM_ABS32 and rel_addr == init_array_offset:
                            sym = dynsym.get_symbol(rel['r_info_sym'])
                            sym_value = sym['st_value']
                            init_array.append(load_base + sym_value)
                            # print ("find init array for :%s %x" % (filename, sym_value))
                            break
                init_array_offset += 4

            # Resolve all symbols.
            symbols_resolved = dict()

            # for section in elf.iter_sections():
            #     if not isinstance(section, SymbolTableSection):
            #         continue
            if dynsym:
                itersymbols = dynsym.iter_symbols()
                next(itersymbols)  # Skip first symbol which is always NULL.
                for symbol in itersymbols:
                    symbol_address = self._elf_get_symval(elf, load_base, symbol)
                    if symbol_address is not None:
                        # TODO: Maybe we need to do something with uname symbols？
                        symbols_resolved[symbol.name] = SymbolResolved(symbol_address, symbol)

            # Relocate.
            # for section in elf.iter_sections():
            #     if not isinstance(section, RelocationSection): 
            #         continue
            if rel_section:
                for rel in rel_section.iter_relocations():
                    sym = dynsym.get_symbol(rel['r_info_sym'])
                    sym_value = sym['st_value']

                    rel_addr = load_base + rel['r_offset']  # Location where relocation should happen
                    rel_info_type = rel['r_info_type']

                    # https://static.docs.arm.com/ihi0044/e/IHI0044E_aaelf.pdf
                    # Relocation table for ARM
                    if rel_info_type == arm.R_ARM_ABS32:
                        # Read value.
                        offset = int.from_bytes(self.emu.uc.mem_read(rel_addr, 4), byteorder='little')
                        # Create the new value.
                        value = load_base + sym_value + offset
                        # Check thumb.
                        if sym['st_info']['type'] == 'STT_FUNC':
                            value = value | 1
                        # Write the new value
                        self.emu.uc.mem_write(rel_addr, value.to_bytes(4, byteorder='little'))
                    elif rel_info_type == arm.R_ARM_GLOB_DAT or \
                            rel_info_type == arm.R_ARM_JUMP_SLOT:
                        # Resolve the symbol.
                        if sym.name in symbols_resolved:
                            value = symbols_resolved[sym.name].address

                            # Write the new value
                            self.emu.uc.mem_write(rel_addr, value.to_bytes(4, byteorder='little'))
                    elif rel_info_type == arm.R_ARM_RELATIVE:
                        if sym_value == 0:
                            # Load address at which it was linked originally.
                            value_orig_bytes = self.emu.uc.mem_read(rel_addr, 4)
                            value_orig = int.from_bytes(value_orig_bytes, byteorder='little')

                            # Create the new value
                            value = load_base + value_orig

                            # Write the new value
                            self.emu.uc.mem_write(rel_addr, value.to_bytes(4, byteorder='little'))
                        else:
                            raise NotImplementedError()
                    else:
                        logger.error("Unhandled relocation type %i." % rel_info_type)

            # Store information about loaded module.
            module = Module(filename, load_base, bound_high - bound_low, symbols_resolved, init_array)
            self.modules.append(module)

            return module

    def _elf_get_symval(self, elf, elf_base, symbol):
        if symbol.name in self.symbol_hooks:
            return self.symbol_hooks[symbol.name]

        if symbol['st_shndx'] == 'SHN_UNDEF':
            # External symbol, lookup value.
            target = self._elf_lookup_symbol(symbol.name)
            if target is None:
                # Extern symbol not found
                if symbol['st_info']['bind'] == 'STB_WEAK':
                    # Weak symbol initialized as 0
                    return 0
                else:
                    logger.error('=> Undefined external symbol: %s' % symbol.name)
                    return None
            else:
                return target
        elif symbol['st_shndx'] == 'SHN_ABS':
            # Absolute symbol.
            return elf_base + symbol['st_value']
        else:
            # Internally defined symbol.
            return elf_base + symbol['st_value']

    def _elf_lookup_symbol(self, name):
        for module in self.modules:
            if name in module.symbols:
                symbol = module.symbols[name]

                if symbol.address != 0:
                    return symbol.address

        return None

    def __iter__(self):
        for x in self.modules:
            yield x
