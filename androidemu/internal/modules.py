from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from unicorn import UC_PROT_ALL

from androidemu.internal import get_segment_protection, arm


class Module:

    """
    :type filename str
    :type address int
    :type size int
    """
    def __init__(self, filename, address, size):
        self.filename = filename
        self.address = address
        self.size = size


class Modules:

    """
    :type emu androidemu.emulator.Emulator
    :type module_main Module
    :type modules list[Module]
    """
    def __init__(self, emu):
        self.emu = emu
        self.module_main = None
        self.modules = list()

    def load_module(self, filename, main=True):
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

            # Store information about loaded module.
            module = Module(filename, load_base, bound_high - bound_low)

            if main:
                self.module_main = module
            else:
                self.modules.append(module)

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

                    # Relocation table for ARM
                    if rel.entry.r_info_type == arm.R_ARM_ABS32:  # Static | Data | Op: (S + A) | T
                        # Create the new value.
                        value = load_base + sym_value

                        # Write the new value
                        self.emu.mu.mem_write(rel_addr, value.to_bytes(4, byteorder='little'))
                    elif rel.entry.r_info_type == arm.R_ARM_GLOB_DAT:  # Dyn | Data | Op: (S + A) | T
                        pass
                    elif rel.entry.r_info_type == arm.R_ARM_JUMP_SLOT:  # Dyn | Data | Op: (S + A) | T
                        pass
                    elif rel.entry.r_info_type == arm.R_ARM_RELATIVE:  # Dyn | Data | Op: B(S) + A[Note: see Table 4-18]
                        pass
                    else:
                        print("Unhandled relocation type %i." % rel.entry.r_info_type)
