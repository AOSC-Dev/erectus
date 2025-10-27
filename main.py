#!/bin/env python3
# libLoL-aot: recompiles LoongArch ABI v0 (old world) binaries to v1 (new world) binaries


import lief
import dataclasses

from typing import Callable

LOONGARCH_ABI_OBJ_V1 = 0x40
NEW_GLIBC_VERSION = "GLIBC_2.36"


def load_elf(path: str) -> lief.ELF.Binary:
    binary = lief.parse(path)
    assert isinstance(binary, lief.ELF.Binary), "Not an ELF binary"
    return binary


def patch_glibc_symbols(obj: lief.ELF.Binary) -> list[tuple[int, int]]:
    delayed_patches = []  # workaround another bug in lief
    needs_patching = dict()
    for sym in obj.dynamic_symbols:
        if not sym.has_version:
            continue
        # handle symbol renames
        if sym.name == "___brk_addr":
            sym.name = "__curbrk"
        sym_name = ""
        if isinstance(sym.name, str):
            sym_name = sym.name
        elif isinstance(sym.name, bytes):
            sym_name = sym.name.decode("utf-8")
        elif isinstance(sym.name, memoryview):
            sym_name = sym.name.tobytes().decode("utf-8")

        if sym_name in interesting_symbols:
            pass
        elif f"{sym_name}_wrapper" in interesting_symbols:
            sym_name = f"{sym_name}_wrapper"
        else:
            sym_name = ""
        if sym_name:
            needs_patching[sym_name] = find_plt_entry_by_name(obj, sym.name)
        # replace GLIBC version in auxiliary version
        if sym.symbol_version.has_auxiliary_version:
            ver = sym.symbol_version.symbol_version_auxiliary
            if isinstance(ver.name, str) and ver.name.startswith("GLIBC_"):
                ver.name = NEW_GLIBC_VERSION

    for name, plt_data in needs_patching.items():
        if plt_data:
            renames_to = attach_shim_symbol_with_relocs(
                obj, name, delayed_patches, plt_data
            )
            if renames_to:
                print(f"Renaming {name} to {renames_to}")
                for sym in obj.dynamic_symbols:
                    if sym.name == name.removesuffix("_wrapper"):
                        sym.name = renames_to
    # restore plt
    return delayed_patches


def add_section_for_new_function(
    obj: lief.ELF.Binary, name: str, size: int
) -> lief.ELF.Section:
    end_addr = 0
    for section in obj.sections:
        section_end = section.virtual_address + section.size
        if section_end > end_addr:
            end_addr = section_end
    new_section = lief.ELF.Section(f".text.{name}")
    end_addr = (end_addr + 0xF) & ~0xF  # align to 16 bytes
    new_section.virtual_address = end_addr
    new_section.size = size
    new_section.flags_list.append(lief.ELF.Section.FLAGS.EXECINSTR)
    new_section.flags_list.append(lief.ELF.Section.FLAGS.ALLOC)
    return obj.add(new_section)


shims = load_elf("shims.o")
interesting_symbols = dict([(s.name, s) for s in shims.symbols if s.size > 0])


def attach_shim_symbol(
    obj: lief.ELF.Binary, name: str, padding: int = 0
) -> lief.ELF.Segment | None:
    """
    Attach a shim symbol from shims.o to the target binary as a new LOAD segment.

    If padding > 0, add padding instructions at the end of the segment.
    For functions, padding instructions are `break 0` instructions.
    For data, padding bytes are zero bytes.

    Padding size is in number of instructions/words (4 bytes each).
    """
    if name not in interesting_symbols:
        return
    sym = interesting_symbols[name]
    print(f"Attaching shim for {name} at {hex(sym.value)} size {sym.size}")
    assert sym.section
    segment = lief.ELF.Segment()
    segment.type = lief.ELF.Segment.TYPE.LOAD
    segment.flags = lief.ELF.Segment.FLAGS.R
    if sym.is_function:
        segment.flags |= lief.ELF.Segment.FLAGS.X
    elif lief.ELF.Section.FLAGS.WRITE in sym.section.flags_list:
        segment.flags |= lief.ELF.Segment.FLAGS.W
    segment.content = sym.section.content
    if padding > 0:
        padding_content = get_break_inst() if sym.is_function else b"\x00\x00\x00\x00"
        segment.content = memoryview(
            segment.content.tobytes() + padding_content * padding
        )
    return obj.add(segment)


def encode_pcala_pair(from_addr: int, to_addr: int) -> tuple[int, int]:
    jump_dist = to_addr - from_addr
    hi20 = (jump_dist >> 12) + 1
    lo12 = to_addr - ((from_addr + (hi20 << 12)) & 0xFFFFF000)
    return hi20 & 0xFFFFF, lo12 & 0xFFF


def find_plt_entry_by_name(obj, name):
    for r in obj.relocations:
        if r.symbol.name == name:
            end_va, result = get_plt_entry_by_target_va(obj, r.address) or (
                0,
                LoongPLTEntryData(),
            )
            print(
                f"Found PLT entry for {name} at {hex(result.start_va)} to {hex(end_va)}"
            )
            if result.start_va != 0:
                plt_data = result
                print(plt_data.saved_pc_reg, hex(plt_data.saved_pc_value))
                return plt_data


def sanity_check(obj: lief.ELF.Binary):
    known_symbols = set()
    with open("libc.abilist", "r") as f:
        for line in f.readlines():
            _, name, _ = line.split(maxsplit=2)
            known_symbols.add(name)
    for sym in obj.dynamic_symbols:
        if not sym.has_version:
            continue
        if sym.symbol_version.has_auxiliary_version:
            ver = sym.symbol_version.symbol_version_auxiliary
            if isinstance(ver.name, str) and ver.name.startswith("GLIBC_"):
                if sym.name not in known_symbols:
                    print(f"Warning: unknown symbol {sym.name} not handled")
    if search_syscall_usages(obj):
        print("Warning: syscall usages found, not handled")


def attach_shim_symbol_with_relocs(
    obj: lief.ELF.Binary,
    name: str,
    delayed_patches: list[tuple[int, int]],
    old_plt_data,
):
    sym = interesting_symbols[name]
    assert sym.section
    relocs: list[lief.ELF.Relocation] = []
    for reloc in shims.relocations:
        if reloc.section != sym.section:
            continue
        relocs.append(reloc)
    if not relocs:
        return
    deps: dict[str, lief.ELF.Relocation] = dict()
    for reloc in relocs:
        if reloc.symbol.name:
            sym_name = reloc.symbol.name
            assert isinstance(sym_name, str)
            deps[sym_name] = reloc
        elif reloc.symbol.section:
            section_name = reloc.symbol.section.name
            assert isinstance(section_name, str)
            deps[section_name.split(".", 2)[2]] = reloc
    relocs_addr = dict()
    for d in deps.keys():
        relocs_addr[d] = attach_shim_symbol(obj, d)
    segment = attach_shim_symbol(obj, name, 4)
    assert segment
    reloc_mem = dict()  # temp storage for hi-lo pairs
    renames_to = None
    for reloc in relocs:
        reloc_name = ""
        if reloc.symbol.name:
            sym_name = reloc.symbol.name
            assert isinstance(sym_name, str)
            reloc_name = sym_name
        elif reloc.symbol.section:
            section_name = reloc.symbol.section.name
            assert isinstance(section_name, str)
            reloc_name = section_name.split(".", 2)[2]
        else:
            raise RuntimeError("Relocation without symbol name or section")
        target_segment = relocs_addr[reloc_name]
        if target_segment:
            jump_out_addr = segment.virtual_address + reloc.address
            jump_dist = target_segment.virtual_address - jump_out_addr
            new_inst = 0
            print(jump_dist, hex(target_segment.virtual_address), hex(jump_out_addr))
            jump_out_content = segment.content[reloc.address : reloc.address + 4]
            if reloc.type == lief.ELF.Relocation.TYPE.LARCH_PCALA_HI20:
                hi20, lo12 = encode_pcala_pair(
                    jump_out_addr, target_segment.virtual_address
                )
                orig = int.from_bytes(jump_out_content, "little")
                new_inst = orig | ((hi20 & 0xFFFFF) << 5)
                reloc_mem[target_segment.virtual_address] = lo12
            elif reloc.type == lief.ELF.Relocation.TYPE.LARCH_PCALA_LO12:
                lo12 = reloc_mem[target_segment.virtual_address]
                orig = int.from_bytes(jump_out_content, "little")
                new_inst = orig | (lo12 << 10)
            elif reloc.type == lief.ELF.Relocation.TYPE.LARCH_B26:
                orig = int.from_bytes(jump_out_content, "little")
                jump_offset = (jump_dist >> 2) & 0x3FFFFFF
                new_inst = orig | (jump_offset >> 16) | ((jump_offset & 0xFFFF) << 10)
            else:
                raise RuntimeError(f"Unsupported relocation type {reloc.type}")
            print(hex(new_inst))
            obj.patch_address(jump_out_addr, new_inst, size=4)
        else:
            # handle PLT redirections
            assert old_plt_data
            # restore saved pc, load original got, jump into original function
            jump_back_seq: list[int] = [0] * 5
            jump_out_addr = segment.virtual_address + reloc.address
            # check how many break 0 instructions we have
            nop_count = 0
            while (
                obj.get_int_from_virtual_address(jump_out_addr + 4 + nop_count * 4, 4)
                == 0x002A0000
            ):
                nop_count += 1
            print(nop_count, "padding instructions before PLT jump")
            if nop_count < 4:
                # this means the relocation is in the middle of our shim function
                # let's try to do the sequence at the end of the function
                # and create a jump to there
                offset = 4
                while (
                    obj.get_int_from_virtual_address(jump_out_addr + offset, 4)
                    != 0x002A0000
                ):
                    offset += 4
                    if offset > 0x100:
                        raise RuntimeError("Cannot find padding area for PLT jump")
                b_offset = offset >> 2
                orig_inst = (
                    obj.get_int_from_virtual_address(jump_out_addr, 4) or 0x50000000
                )
                b_inst = orig_inst | (b_offset >> 16) | ((b_offset & 0xFFFF) << 10)
                obj.patch_address(jump_out_addr, b_inst, size=4)
                jump_out_addr += offset
            # due to a implicit design in LIEF, we need to adjust the virtual address of .plt
            # after LIEF patched the ELF header (PLT rewrite)
            new_plt_offset = (
                obj.get_section(".plt").virtual_address - old_plt_data.plt_start
            )
            hi20, lo12 = encode_pcala_pair(
                jump_out_addr, old_plt_data.saved_pc_value + new_plt_offset
            )
            print(f"restore saved pc: 0x{hi20:02x} 0x{lo12:02x}")
            # generate:
            # pcalau12i <saved_pc_reg>, <hi20>
            # addi.d <saved_pc_reg>, <saved_pc_reg>, <lo12>
            # pcalau12i <jump_reg>, <hi20>
            # ld.d <jump_reg>, <lo12>, 0
            # jirl zero, <jump_reg>, 0
            jump_back_seq[0] = 0x1A000000 | hi20 << 5 | old_plt_data.saved_pc_reg
            jump_back_seq[1] = (
                0x2C00000
                | lo12 << 10
                | old_plt_data.saved_pc_reg << 5
                | old_plt_data.saved_pc_reg
            )
            hi20, lo12 = encode_pcala_pair(
                jump_out_addr + 8,
                old_plt_data.target_va + new_plt_offset,
            )
            jump_back_seq[2] = 0x1A000000 | hi20 << 5 | old_plt_data.jump_reg
            jump_back_seq[3] = (
                0x28C00000
                | lo12 << 10
                | old_plt_data.jump_reg << 5
                | old_plt_data.jump_reg
            )
            jump_back_seq[4] = 0x4C000000 | old_plt_data.jump_reg << 5
            for idx, inst in enumerate(jump_back_seq):
                obj.patch_address(jump_out_addr + idx * 4, inst, size=4)
            # finally replace the original PLT entry with our shim function
            jump_to_seq = encode_jump(
                old_plt_data.start_va + new_plt_offset,
                segment.virtual_address,
                old_plt_data.jump_reg,
            )
            print(f"new_plt_offset = {new_plt_offset:x}")
            new_start_va = old_plt_data.start_va + new_plt_offset
            print(
                "old_plt_data.start_va",
                obj.get_int_from_virtual_address(new_start_va, 4),
            )
            for idx, inst in enumerate(jump_to_seq):
                # obj.patch_address(new_start_va + idx * 4, inst, size=4)
                delayed_patches.append((new_start_va + idx * 4, inst))
            # obj.get_section(".plt").virtual_address = old_plt_data.plt_start
            renames_to = reloc_name
    return renames_to


def search_syscall_usages(obj: lief.ELF.Binary) -> list[int]:
    text_section = obj.get_section(".text")
    if text_section is None:
        raise ValueError("No .text section found")

    return text_section.search_all(0x2B000000, 4)  # SYSCALL instruction


def finalize_new_elf(
    obj: lief.ELF.Binary, path: str, delayed_patches: list[tuple[int, int]]
) -> None:
    new_flags = obj.header.processor_flag | LOONGARCH_ABI_OBJ_V1
    obj.interpreter = "/lib64/ld-linux-loongarch-lp64d.so.1"

    # re-open the ELF file for applying delayed patches
    for addr, inst in delayed_patches:
        obj.patch_address(addr, inst, size=4)
    obj.write(path)

    with open(path, "rb+") as f:
        f.seek(0x30)  # e_flags offset
        f.write(new_flags.to_bytes(4, byteorder="little"))
    print(f"Recompiled binary written to {path}")


def get_break_inst() -> bytes:
    return b"\x00\x00\x2a\x00"  # break instruction (0x002A0000)


def encode_jump(from_va: int, to_va: int, tmp_reg: int = 20) -> list[int]:
    offset = to_va - from_va
    if offset & 0x3 != 0:
        raise ValueError("Jump target is not aligned to 4 bytes")
    offset >>= 2
    # LoongArch B/BL instruction has a 26-bit signed immediate
    if offset >= -0x2000000 and offset < 0x2000000:
        inst = 0x50000000  # B instruction opcode
        offset_26b = offset & 0x3FFFFFF
        inst |= (offset_26b >> 16) | ((offset_26b & 0xFFFF) << 10)
        return [inst]
    else:
        # encode far jump using jirl (kind of rare)
        # strategy: use pcalau12i (set hi 20-bit) + jirl (set lo 12-bit)
        offset += 1  # account for one additional instruction we added
        hi20, lo12 = encode_pcala_pair(from_va, to_va)
        inst1 = 0x1A000000  # PCALAU12I opcode
        inst1 |= ((hi20 & 0xFFFFF) << 5) | tmp_reg
        offset_lo = lo12 & ~0xFFF if lo12 & 0x800 else lo12 & 0xFFF
        inst2 = 0x4C000000  # JIRL opcode
        inst2 |= ((offset_lo & 0xFFFF) << 10) | (tmp_reg << 5) | 0  # rd = r0
        return [inst1, inst2]


@dataclasses.dataclass
class LoongPLTEntryData:
    saved_pc_reg: int = -1
    saved_pc_value: int = -1
    start_va: int = 0
    target_va: int = 0
    jump_reg: int = -1
    plt_start: int = 0


class LoongArchInstruction:
    def __init__(self, raw: int):
        self.raw = raw
        self.regs: list[int] = []
        self.imms: list[int] = []
        self.opcode: int = 0
        self.__decode()

    def __decode(self) -> None:
        tmp = self.raw >> 10
        if tmp >= 4 and tmp <= 0x1B:
            self.opcode = tmp
            regs_int = self.raw & 0x3FF
            # [rj, rd]
            self.regs = [regs_int >> 5 & 0x1F, regs_int & 0x1F]
            return
        tmp = self.raw >> 15
        if tmp >= 0x2 and tmp <= 0x4F:
            self.opcode = tmp
            regs_int = (self.raw >> 5) & 0x3FFFF
            # [rk, rj, rd]
            self.regs = [regs_int >> 10 & 0x1F, regs_int >> 5 & 0x1F, regs_int & 0x1F]
            # handle immediate
            opcode_hi = self.opcode & 0x1C
            # alsl.w[u], bytepick.w
            if opcode_hi >= 2 and opcode_hi <= 4:
                self.imms = [self.opcode & 0x3]
            # bytepick.d
            elif opcode_hi == 6 or opcode_hi == 7:
                self.imms = [self.opcode & 0x7]
            return
        if tmp in (0x54, 0x55, 0x56):
            self.opcode = tmp
            self.imms = [self.raw & 0x7FFF]
            return
        if tmp == 0x58:
            self.opcode = tmp
            regs_int = (self.raw >> 5) & 0x3FFFF
            # [rk, rj, rd]
            self.regs = [regs_int >> 10 & 0x1F, regs_int >> 5 & 0x1F, regs_int & 0x1F]
            self.imms = [self.opcode & 0x3]
            return
        if tmp >= 0x81 and tmp <= 0x9B:
            self.opcode = tmp
            regs_int = self.raw & 0x3FF
            # [rj, rd]
            self.regs = [regs_int >> 5 & 0x1F, regs_int & 0x1F]
            if self.opcode & 2 == 2:
                self.imms = [(self.raw >> 10) & 0x3F]
            else:
                self.imms = [(self.raw >> 10) & 0x1F]
            return
        tmp = self.raw >> 22
        if tmp >= 0xA0 and tmp <= 0xAF:
            self.opcode = tmp
            regs_int = self.raw & 0x3FF
            self.imms = [(self.raw >> 10) & 0xFFF]
            # [rj, rd]
            self.regs = [regs_int >> 5 & 0x1F, regs_int & 0x1F]
            return
        if tmp >= 0x8 and tmp <= 0xC:
            self.opcode = tmp
            imm = (self.raw >> 10) & 0xFFF
            if imm & 0x800:
                imm |= ~0xFFF  # sign extend
            self.imms = [imm]
            self.regs = [(self.raw >> 5) & 0x1F, self.raw & 0x1F]  # [rj, rd]
            return
        tmp = self.raw >> 25
        if tmp >= 0x8 and tmp <= 0xF:
            self.opcode = tmp
            if self.opcode in (0x8, 0x9):
                self.imms = [(self.raw >> 10) & 0xFFFF]
                self.regs = [(self.raw >> 5) & 0x1F, self.raw & 0x1F]  # [rj, rd]
                return
            self.imms = [(self.raw >> 5) & 0xFFFFF]
            self.regs = [self.raw & 0x1F]  # [rd]
            return
        tmp = self.raw >> 26
        if tmp in (0x10, 0x11):
            self.opcode = tmp
            self.imms = [(self.raw >> 10) & 0xFFFF, self.raw & 0x1F]
            return
        if tmp == 0x13 or (tmp >= 0x16 and tmp <= 0x1B):
            self.opcode = tmp
            self.imms = [(self.raw >> 10) & 0xFFFF]
            self.regs = [(self.raw >> 5) & 0x1F, self.raw & 0x1F]  # [rj, rd]
            return
        if tmp in (0x14, 0x15):  # b/bl
            self.opcode = tmp
            self.imms = [(self.raw >> 10) & 0xFFFF, self.raw & 0x3FF]
            return
        # we only care about a subset of integer instructions for now
        raise NotImplementedError(f"Unsupported instruction: {self.raw:08x}")

    def const_prop(
        self,
        ctx: list[int],
        pc: int,
        mem_func: Callable[[list[int], int, bool], int] | None = None,
    ) -> tuple[int, bool]:
        ctx[0] = 0  # r0 is always 0
        # const prop for a few instructions
        if self.opcode in (0x20, 0x21):  # add
            # rd = rj + rk
            ctx[self.regs[2]] = ctx[self.regs[0]] + ctx[self.regs[1]]
        elif self.opcode in (0xA, 0xB):  # addi
            # rd = rj + imm
            imm = self.imms[0]
            if imm & 0x8000:
                imm |= ~0xFFFF  # sign extend
            ctx[self.regs[1]] = ctx[self.regs[0]] + imm
        elif self.opcode in (0x22, 0x23):  # sub
            # rd = rj - rk
            ctx[self.regs[2]] = ctx[self.regs[0]] - ctx[self.regs[1]]
        elif self.opcode == 0x29:  # and
            # rd = rj & rk
            ctx[self.regs[2]] = ctx[self.regs[0]] & ctx[self.regs[1]]
        elif self.opcode == 0x82 or self.opcode == 0x83:  # srli.d
            # rd = rj >> imm
            imm = self.imms[0]
            ctx[self.regs[1]] = ctx[self.regs[0]] >> imm
        elif self.opcode == 0xE:  # PCADDU12I
            # rd = pc + (imm << 12)
            imm = self.imms[0]
            if imm & 0x80000:
                imm |= ~0xFFFFF  # sign extend
            ctx[self.regs[0]] = (pc + (imm << 12)) & 0xFFFFFFFFFFFFFFFF
        elif self.opcode == 0x13:  # jirl
            ctx[self.regs[1]] = pc + 4
            imm = self.imms[0] << 2
            if imm & 0x8000:
                imm |= ~0xFFFF  # sign extend
            pc = ctx[self.regs[0]] + imm
            ctx[0] = 0
            return pc, True
        elif self.opcode in (0x8A, 0x8B):  # srli.d
            # rd = rj >> imm
            imm = self.imms[0]
            ctx[self.regs[1]] = ctx[self.regs[0]] >> imm
        elif self.opcode >= 0xA0 and self.opcode <= 0xAF:
            # skip load/store instructions
            if callable(mem_func):
                addr = 0
                if self.opcode == 0xA3:  # ld.d
                    imm = self.imms[0]
                    if imm & 0x800:
                        imm |= ~0xFFF  # sign extend
                    addr = ctx[self.regs[0]] + imm
                    # print(f"addr = {ctx[self.regs[0]]:x} + {imm:x} = {addr:x}")
                else:
                    raise NotImplementedError(
                        f"Unsupported load/store instruction for const prop: {self.raw:08x} @ {pc:x}"
                    )
                result = mem_func(ctx, addr, True)
                ctx[self.regs[1]] = result
                # print(f"Const prop load from {addr:x} = {result:x}")
        else:
            raise NotImplementedError(
                f"Unsupported instruction for const prop: {self.raw:08x} @ {pc:x}"
            )
        ctx[0] = 0
        return pc + 4, False

    def to_bytes(self) -> bytes:
        return self.raw.to_bytes(4, byteorder="little")


jump_table: dict[int, LoongPLTEntryData] = {}


def get_plt_entry_by_target_va(obj: lief.ELF.Binary, va: int):
    plt_va = obj.get_section(".plt").virtual_address
    plt_va_end = plt_va + obj.get_section(".plt").size
    if not jump_table:
        ctx = [0] * 32
        start_va = 0
        for entry_va in range(plt_va, plt_va_end, 4):
            inst_bin = obj.get_int_from_virtual_address(entry_va, 4)
            assert inst_bin is not None
            inst = LoongArchInstruction(inst_bin)
            pc, jump = inst.const_prop(ctx, entry_va, lambda ctx, addr, load: addr)
            if jump:
                saved_pc_reg = -1
                saved_pc_value = -1
                for idx, r in enumerate(ctx):
                    if r != 0 and r >= start_va and r < entry_va:
                        saved_pc_reg = idx
                        saved_pc_value = r
                        break
                ctx = [0] * 32
                jump_table[entry_va] = LoongPLTEntryData(
                    saved_pc_reg,
                    saved_pc_value,
                    start_va,
                    pc,
                    inst.regs[0] if inst.regs else -1,
                    plt_va,
                )
                start_va = entry_va + 4
                # print(f"PLT jump at vma:{entry_va:x} to vma:{pc:x}")
    for k, v in jump_table.items():
        start_va, target_va = v.start_va, v.target_va
        # skip nop sequences
        while obj.get_int_from_virtual_address(start_va, 4) == 0x03400000:
            start_va += 4
        jump_table[k].start_va = start_va
        if target_va == va:
            return k, v
    return None


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input-elf> <output-elf>")
        sys.exit(1)
    input_path = sys.argv[1]
    output_path = sys.argv[2]
    data = load_elf(input_path)
    delayed_patches = patch_glibc_symbols(data)
    sanity_check(data)
    lief.logging.set_level(lief.logging.LEVEL.DEBUG)
    finalize_new_elf(data, output_path, delayed_patches)
