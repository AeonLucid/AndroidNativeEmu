import logging

import elftools.elf
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from elftools.elf.sections import StringTableSection
from elftools.elf.constants import SH_FLAGS
from elftools.construct import Container
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
    
    @staticmethod
    def find_section_index(elf, addr):
        for idx, section in enumerate(elf.iter_sections()):
            if section.header['sh_addr'] <= addr < (section.header['sh_addr'] + section.header['sh_size']):
                return idx
        return 0

    @staticmethod
    def calculate_sh_offset(elf, vaddr):
        for segment in elf.iter_segments():
            if segment.header.p_type == 'PT_LOAD':
                p_vaddr = segment.header.p_vaddr
                p_offset = segment.header.p_offset
                p_filesz = segment.header.p_filesz
                if p_vaddr <= vaddr < (p_vaddr + p_filesz):
                    return p_offset + (vaddr - p_vaddr)
        raise Exception(f"Cannot find segment containing address {vaddr:#x}")
    
    @staticmethod
    def create_reloc_section(elf,name, is_rela, addr, size, entsize, sym_idx):
        if not addr or not size:
            return None
        if elf.elfclass == 32:
            entsize = entsize or (12 if is_rela else 8)
        else:  # 64 bit
            entsize = entsize or (24 if is_rela else 16)
        fake_rel_header = Container(
            sh_name=0, # we don't know the name,but it's not important
            sh_type='SHT_RELA' if is_rela else 'SHT_REL',
            sh_flags=SH_FLAGS.SHF_ALLOC,
            sh_addr=addr,
            sh_offset=Modules.calculate_sh_offset(elf, addr),
            sh_size=size,
            sh_link=sym_idx,
            sh_info=0,
            sh_addralign=8 if elf.elfclass == 64 else 4,
            sh_entsize=entsize
            
        )
        return RelocationSection(fake_rel_header, name, elf)

    def load_module(self, filename):
        logger.debug("Loading module '%s'." % filename)

        with open(filename, 'rb') as fstream:
            elf = ELFFile(fstream)

            dynamic = elf.header.e_type == 'ET_DYN'

            if not dynamic:
                raise NotImplementedError("Only ET_DYN is supported at the moment.")
  
            # support 32bit and 64bit
            is_64bit = elf.elfclass == 64
            ptr_size = 8 if is_64bit else 4

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

            rel_sections = []

            # Parse section header (Linking view).
            dynsym = elf.get_section_by_name(".dynsym")
            dynstr = elf.get_section_by_name(".dynstr")

            # Find relocation table and symbol table by dynamic segment
            rel_info = {
                'rel': {'addr': None, 'size': None, 'entsize': None, 'count': None},
                'rela': {'addr': None, 'size': None, 'entsize': None, 'count': None},
                'jmprel': {'addr': None, 'size': None, 'entsize': None},
                'android_rela': {'addr': None, 'size': None, 'entsize': None},
                'relr': {'addr': None, 'size': None, 'entsize': None},
                'pltrel': None,  # DT_PLTREL
                'textrel': False,  # DT_TEXTREL
                'sym': None,
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

                        # other Relocation information
                        elif tag.entry.d_tag == 'DT_TEXTREL':
                            rel_info['textrel'] = True
                        elif tag.entry.d_tag == 'DT_PLTREL':
                            rel_info['pltrel'] = 'RELA' if tag.entry.d_val == 7 else 'REL'
                        elif tag.entry.d_tag == 'DT_JMPREL':
                            rel_info['jmprel']['addr'] = tag.entry.d_val
                        elif tag.entry.d_tag == 'DT_PLTRELSZ':
                            rel_info['jmprel']['size'] = tag.entry.d_val
                        elif tag.entry.d_tag == 'DT_ANDROID_RELA':
                            rel_info['android_rela']['addr'] = tag.entry.d_val
                        elif tag.entry.d_tag == 'DT_ANDROID_RELASZ':
                            rel_info['android_rela']['size'] = tag.entry.d_val
                        elif tag.entry.d_tag == 'DT_ANDROID_RELR':
                            rel_info['relr']['addr'] = tag.entry.d_val
                        elif tag.entry.d_tag == 'DT_ANDROID_RELRSZ':
                            rel_info['relr']['size'] = tag.entry.d_val

            if rel_info['rel']['addr'] and rel_info['rel']['size']:
                rel_info['type'] = 'REL'

            elif rel_info['rela']['addr'] and rel_info['rela']['size']:
                rel_info['type'] = 'RELA'

            # create dynsym and dynstr if not found
            if dynstr is None or dynsym is None:
                # calculate dynsym size
                if sym_info['dynsym']['addr'] and sym_info['dynstr']['addr']:
                    sym_info['dynsym']['size'] = sym_info['dynstr']['addr'] - sym_info['dynsym']['addr']

                if dynstr is None and sym_info['dynstr']['addr'] and sym_info['dynstr']['size']:
                    fake_str_header = Container(
                        sh_name=0,
                        sh_type='SHT_STRTAB',
                        sh_flags=SH_FLAGS.SHF_ALLOC,
                        sh_addr=sym_info['dynstr']['addr'],
                        sh_offset=self.calculate_sh_offset(elf, sym_info['dynstr']['addr']),
                        sh_size=sym_info['dynstr']['size'],
                        sh_link=0,
                        sh_info = 0,
                        sh_addralign=1,
                        sh_entsize=0
                    )
                    dynstr = StringTableSection(fake_str_header, '.dynstr', elf)

                if dynsym is None and dynstr is not None and \
                sym_info['dynsym']['addr'] and sym_info['dynsym']['size']:
                    fake_sym_header = Container(
                        sh_name=0,
                        sh_type='SHT_DYNSYM',
                        sh_flags = SH_FLAGS.SHF_ALLOC,
                        sh_addr=sym_info['dynsym']['addr'],
                        sh_offset=self.calculate_sh_offset(elf, sym_info['dynsym']['addr']),
                        sh_size=sym_info['dynsym']['size'],
                        sh_link=self.find_section_index(elf, sym_info['dynstr']['addr']), # link to dynstr
                        sh_info=0, # we don't know the index of the first non-local symbol
                        sh_addralign=8 if elf.elfclass == 64 else 4,
                        sh_entsize=sym_info['dynsym']['entsize']
                    )
                    dynsym = SymbolTableSection(fake_sym_header, '.dynsym', elf, dynstr)

            # create all fake relocation section
            if rel_info['rel']['addr']:
                rel = self.create_reloc_section(elf,'.rel.dyn', False, 
                                            rel_info['rel']['addr'],
                                            rel_info['rel']['size'],
                                            rel_info['rel']['entsize'],
                                            rel_info['sym'])
                if rel:
                    rel_sections.append(rel)

            if rel_info['rela']['addr']:
                rela = self.create_reloc_section(elf,'.rela.dyn', True,
                                            rel_info['rela']['addr'],
                                            rel_info['rela']['size'],
                                            rel_info['rela']['entsize'],
                                            rel_info['sym'])
                if rela:
                    rel_sections.append(rela)

            if rel_info['jmprel']['addr']:
                is_rela = rel_info['pltrel'] == 'RELA'
                jmprel = self.create_reloc_section(elf,'.rela.plt' if is_rela else '.rel.plt',
                                            is_rela,
                                            rel_info['jmprel']['addr'],
                                            rel_info['jmprel']['size'],
                                            rel_info['jmprel']['entsize'],
                                            rel_info['sym'])
                if jmprel:
                    rel_sections.append(jmprel)

            if rel_info['android_rela']['addr']:
                android_rela = self.create_reloc_section(elf,'.rela.android', True,
                                                    rel_info['android_rela']['addr'],
                                                    rel_info['android_rela']['size'],
                                                    rel_info['android_rela']['entsize'],
                                                    rel_info['sym'])
                if android_rela:
                    rel_sections.append(android_rela)

            # Resolve all symbols.
            symbols_resolved = dict()

            if dynsym:
                itersymbols = dynsym.iter_symbols()
                next(itersymbols)  # Skip first symbol which is always NULL.
                for symbol in itersymbols:
                    symbol_address = self._elf_get_symval(elf, load_base, symbol)
                    if symbol_address is not None:
                        # TODO: Maybe we need to do something with uname symbols？
                        symbols_resolved[symbol.name] = SymbolResolved(symbol_address, symbol)
            
            # only for debug and call local function by symbol name directly, not by address.
            for section in elf.iter_sections():
                if not isinstance(section, SymbolTableSection):
                    continue
                for symbol in itersymbols:
                    symbol_address = self._elf_get_symval(elf, load_base, symbol)
                    if symbol_address is not None and symbol.name not in symbols_resolved:
                        symbols_resolved[symbol.name] = SymbolResolved(symbol_address, symbol)

            # Relocate.
            processed_relocs = set()  # Keep track of processed relocations to avoid double processing.
            # process relocation in DT_DYNAMIC first
            for section in rel_sections:
                processed_relocs.add(section.header.sh_addr)
                self._process_relocations(load_base, section, symbols_resolved, dynsym,is_64bit)

            # then process relocation in Section Header(in fact, it's not necessary most of the time)
            for section in elf.iter_sections():
                if isinstance(section, RelocationSection):
                    if section.header.sh_addr in processed_relocs:
                        continue
                    self._process_relocations(load_base, section, symbols_resolved, dynsym,is_64bit)

            # Find init array.
            init_array_size = 0
            init_array_offset = 0
            init_array = []
            init = None
            for x in elf.iter_segments():
                if x.header.p_type == "PT_DYNAMIC":
                    for tag in x.iter_tags():
                        if tag.entry.d_tag == "DT_INIT_ARRAYSZ":
                            init_array_size = tag.entry.d_val
                        elif tag.entry.d_tag == "DT_INIT_ARRAY":
                            init_array_offset = tag.entry.d_val
                        elif tag.entry.d_tag == "DT_INIT":
                            init = tag.entry.d_val

            # DT_INIT should be called before DT_INIT_ARRAY if both are present
            if init:
                init = load_base + init

            # Read init_array after relocations have been applied
            init_array_va = load_base + init_array_offset
            for i in range(int(init_array_size / ptr_size)):
                fun_ptr_bytes = self.emu.uc.mem_read(init_array_va + i * ptr_size, ptr_size)
                fun_ptr = int.from_bytes(fun_ptr_bytes, byteorder='little')
                init_array.append(fun_ptr)

            # Store information about loaded module.
            module = Module(filename, load_base, bound_high - bound_low, symbols_resolved, init_array, init)
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
    
    def _process_relocations(self, load_base, section, symbols_resolved, dynsym, is_64bit=False):
        """Process relocations in a section."""
        ptr_size = 8 if is_64bit else 4

        for rel in section.iter_relocations():
            sym = dynsym.get_symbol(rel['r_info_sym'])
            sym_value = sym['st_value']
            rel_addr = load_base + rel['r_offset']
            rel_info_type = rel['r_info_type']
            
            # Get addend - for RELA sections it's in r_addend, for REL it's at the relocation address
            if section["sh_type"] == "SHT_RELA":
                addend = rel["r_addend"] 
            else:
                addend = int.from_bytes(self.emu.uc.mem_read(rel_addr, ptr_size), byteorder='little')
            if is_64bit:
                # https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst#relocation
                if rel_info_type == arm.R_AARCH64_NONE:
                    continue
                elif rel_info_type == arm.R_AARCH64_ABS64:
                    # S + A
                    value = load_base + sym_value + addend
                elif rel_info_type == arm.R_AARCH64_RELATIVE:
                    # Delta(S) + A
                    if sym_value == 0:
                        value = load_base + addend
                    else:
                        raise NotImplementedError()
                elif rel_info_type in (arm.R_AARCH64_GLOB_DAT, arm.R_AARCH64_JUMP_SLOT):
                    # S + A
                    if sym.name not in symbols_resolved:
                        continue
                    value = symbols_resolved[sym.name].address + addend

                elif rel_info_type in (arm.R_AARCH64_TLS_DTPREL, arm.R_AARCH64_TLS_TPREL):
                    # TLS relocations currently not supported
                    continue
                    
                elif rel_info_type == arm.R_AARCH64_IRELATIVE:
                    # Indirect functions not supported yet
                    continue
                    
                else:
                    logger.error("Unhandled AArch64 relocation type %i." % rel_info_type)
                    continue

                # Write relocated value
                self.emu.uc.mem_write(rel_addr, value.to_bytes(8, byteorder='little'))

            else:
                # https://static.docs.arm.com/ihi0044/e/IHI0044E_aaelf.pdf
                # Relocation table for ARM
                if rel_info_type == arm.R_ARM_ABS32:
                    # Create the new value.
                    value = load_base + sym_value + addend
                    # Check thumb.
                    if sym['st_info']['type'] == 'STT_FUNC':
                        value = value | 1
                        
                elif rel_info_type in (arm.R_ARM_GLOB_DAT, arm.R_ARM_JUMP_SLOT):
                    # Resolve the symbol.
                    if sym.name not in symbols_resolved:
                        continue
                    value = symbols_resolved[sym.name].address
                    
                elif rel_info_type == arm.R_ARM_RELATIVE:
                    if sym_value == 0:
                        value = load_base + addend
                    else:
                        raise NotImplementedError()
                
                else:
                    logger.error("Unhandled ARM32 relocation type %i." % rel_info_type)
                    continue

                # Write the new value
                self.emu.uc.mem_write(rel_addr, value.to_bytes(4, byteorder='little'))

    def __iter__(self):
        for x in self.modules:
            yield x
