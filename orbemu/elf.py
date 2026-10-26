"""Minimal ELF64 parser: loadable segments plus the dynamic section (imports and relocations).

Understands ordinary ELF files and the PlayStation variant (file types 0xFE10 / 0xFE18), where
the symbol table, string table and relocations live in a special SCE_DYNLIBDATA segment and the
dynamic tags (0x61000000 and up) hold offsets into it.
"""
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

PT_LOAD, PT_DYNAMIC, PT_PHDR, PT_TLS = 1, 2, 6, 7
PT_SCE_DYNLIBDATA, PT_SCE_PROCPARAM, PT_SCE_RELRO = 0x61000000, 0x61000001, 0x61000010
PF_X, PF_W, PF_R = 1, 2, 4
EM_X86_64 = 0x3E
ET_EXEC, ET_DYN, ET_SCE_DYNEXEC, ET_SCE_DYNAMIC = 2, 3, 0xFE10, 0xFE18
SONY_TYPES = (ET_SCE_DYNEXEC, ET_SCE_DYNAMIC)
DT_NULL, DT_NEEDED, DT_PLTRELSZ, DT_STRTAB, DT_SYMTAB, DT_RELA, DT_RELASZ, DT_JMPREL = 0, 1, 2, 5, 6, 7, 8, 23
DT_INIT, DT_INIT_ARRAY, DT_INIT_ARRAYSZ = 12, 25, 27
STB_WEAK = 2

# Sony dynamic tags. Values were cross-checked against a real OpenOrbis build (the table sizes and
# offsets line up exactly); MODULE_ATTR, EXPORT_LIB and EXPORT_LIB_ATTR come from public notes only.
DT_SCE = dict(
    FINGERPRINT=0x61000007, ORIGINAL_FILENAME=0x61000009, MODULE_INFO=0x6100000D,
    NEEDED_MODULE=0x6100000F, MODULE_ATTR=0x61000011, EXPORT_LIB=0x61000013,
    IMPORT_LIB=0x61000015, EXPORT_LIB_ATTR=0x61000017, IMPORT_LIB_ATTR=0x61000019,
    HASH=0x61000025, PLTGOT=0x61000027, JMPREL=0x61000029, PLTREL=0x6100002B,
    PLTRELSZ=0x6100002D, RELA=0x6100002F, RELASZ=0x61000031, RELAENT=0x61000033,
    STRTAB=0x61000035, STRSIZE=0x61000037, SYMTAB=0x61000039, SYMENT=0x6100003B,
    HASHSZ=0x6100003D, SYMTABSZ=0x6100003F)
SONY_DT_NAMES = {v: "SCE_" + k for k, v in DT_SCE.items()}


class ElfError(Exception):
    pass


@dataclass
class Segment:
    vaddr: int
    offset: int
    filesz: int
    memsz: int
    flags: int  # ELF PF_* bits


@dataclass
class Reloc:
    offset: int          # where to patch, relative to the load base
    rtype: int           # R_X86_64_* type
    sym: Optional[str]   # symbol name, or None if the relocation has no symbol
    sym_defined: bool    # False means "imported from another library"
    sym_value: int       # for defined symbols: address relative to the load base
    weak: bool
    addend: int


@dataclass
class DynamicInfo:
    needed: List[str] = field(default_factory=list)   # libraries/modules this file depends on
    relocs: List[Reloc] = field(default_factory=list)


@dataclass
class ElfImage:
    entry: int
    segments: List[Segment] = field(default_factory=list)
    phdr_addr: int = 0  # virtual address of the program header table (AT_PHDR)
    phent: int = 56
    phnum: int = 0
    e_type: int = ET_EXEC
    dynamic: Optional[DynamicInfo] = None
    tls: Optional[Tuple[int, int, int, int]] = None  # (vaddr, filesz, memsz, align) of PT_TLS
    sony: bool = False                               # PlayStation-style dynamic data
    module_name: Optional[str] = None
    init: int = 0                                    # DT_INIT (not run yet)
    init_array: Optional[Tuple[int, int]] = None     # (vaddr, size) of DT_INIT_ARRAY (not run yet)

    @property
    def position_independent(self):
        return self.e_type in (ET_DYN, ET_SCE_DYNEXEC, ET_SCE_DYNAMIC)


def vaddr_to_offset(image, vaddr):
    for seg in image.segments:
        if seg.vaddr <= vaddr < seg.vaddr + seg.filesz:
            return seg.offset + (vaddr - seg.vaddr)
    raise ElfError(f"address {vaddr:#x} is not backed by file data")


def _read_dynamic_entries(data, dyn_offset, dyn_size):
    entries = []
    for i in range(dyn_size // 16):
        tag, val = struct.unpack_from("<QQ", data, dyn_offset + 16 * i)
        if tag == DT_NULL:
            break
        entries.append((tag, val))
    return entries


def _collect_relocs(data, tables, read_sym):
    relocs, seen = [], set()
    for table, size in tables:
        if table + size > len(data):
            raise ElfError("relocation table runs past end of file")
        for j in range(size // 24):
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, table + 24 * j)
            rtype, sym_index = r_info & 0xFFFFFFFF, r_info >> 32
            if (r_offset, rtype) in seen:
                continue  # some linkers list PLT relocations in both tables
            seen.add((r_offset, rtype))
            name, defined, value, weak = read_sym(sym_index) if sym_index else (None, False, 0, False)
            relocs.append(Reloc(r_offset, rtype, name, defined, value, weak, r_addend))
    return relocs


def _record_init(image, tags):
    image.init = tags.get(DT_INIT, 0)
    if DT_INIT_ARRAY in tags:
        image.init_array = (tags[DT_INIT_ARRAY], tags.get(DT_INIT_ARRAYSZ, 0))


def _parse_dynamic(data, image, dyn_offset, dyn_size):
    needed_offsets, tags = [], {}
    for tag, val in _read_dynamic_entries(data, dyn_offset, dyn_size):
        if tag == DT_NEEDED:
            needed_offsets.append(val)
        else:
            tags[tag] = val
    _record_init(image, tags)

    strtab, symtab = tags.get(DT_STRTAB), tags.get(DT_SYMTAB)

    def string(off):
        start = vaddr_to_offset(image, strtab) + off
        return data[start:data.index(b"\x00", start)].decode("utf-8", errors="replace")

    def read_sym(index):
        if symtab is None or strtab is None:
            return None, False, 0, False
        try:
            st_name, st_info, _other, st_shndx, st_value, _size = struct.unpack_from(
                "<IBBHQQ", data, vaddr_to_offset(image, symtab) + 24 * index)
        except struct.error:
            raise ElfError(f"symbol {index} is outside the file")
        return string(st_name), st_shndx != 0, st_value, (st_info >> 4) == STB_WEAK

    info = DynamicInfo()
    if strtab is not None:
        info.needed = [string(o) for o in needed_offsets]
    tables = []
    for addr_tag, size_tag in ((DT_RELA, DT_RELASZ), (DT_JMPREL, DT_PLTRELSZ)):
        addr, size = tags.get(addr_tag), tags.get(size_tag, 0)
        if addr is not None and size:
            tables.append((vaddr_to_offset(image, addr), size))
    info.relocs = _collect_relocs(data, tables, read_sym)
    return info


def _parse_sony_dynamic(data, image, dyn_offset, dyn_size, lib_off, lib_size):
    """PlayStation layout: tag values are offsets into the SCE_DYNLIBDATA segment (at file offset
    lib_off). Module/library entries pack a string offset into the low 32 bits."""
    tags, modules, libs = {}, [], []
    for tag, val in _read_dynamic_entries(data, dyn_offset, dyn_size):
        if tag == DT_SCE["NEEDED_MODULE"]:
            modules.append(val)
        elif tag == DT_SCE["IMPORT_LIB"]:
            libs.append(val)
        else:
            tags[tag] = val
    _record_init(image, tags)
    if lib_off + lib_size > len(data):
        raise ElfError("SCE_DYNLIBDATA segment runs past end of file")
    strtab, symtab = tags.get(DT_SCE["STRTAB"]), tags.get(DT_SCE["SYMTAB"])
    if strtab is None:
        raise ElfError("no string table in the PlayStation dynamic section")

    def string(off):
        start = lib_off + strtab + off
        try:
            return data[start:data.index(b"\x00", start)].decode("utf-8", errors="replace")
        except ValueError:
            raise ElfError("unterminated string in SCE_DYNLIBDATA")

    def read_sym(index):
        if symtab is None:
            return None, False, 0, False
        try:
            st_name, st_info, _other, st_shndx, st_value, _size = struct.unpack_from(
                "<IBBHQQ", data, lib_off + symtab + 24 * index)
        except struct.error:
            raise ElfError(f"symbol {index} is outside the file")
        return string(st_name), st_shndx != 0, st_value, (st_info >> 4) == STB_WEAK

    info = DynamicInfo()
    names = [string(v & 0xFFFFFFFF) for v in (modules or libs)]
    info.needed = list(dict.fromkeys(names))
    if DT_SCE["MODULE_INFO"] in tags:
        image.module_name = string(tags[DT_SCE["MODULE_INFO"]] & 0xFFFFFFFF)
    tables = []
    for addr_tag, size_tag in ((DT_SCE["RELA"], DT_SCE["RELASZ"]), (DT_SCE["JMPREL"], DT_SCE["PLTRELSZ"])):
        addr, size = tags.get(addr_tag), tags.get(size_tag, 0)
        if addr is not None and size:
            tables.append((lib_off + addr, size))
    info.relocs = _collect_relocs(data, tables, read_sym)
    return info


def parse_elf(data: bytes) -> ElfImage:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ElfError("not an ELF file (bad magic)")
    if data[4] != 2 or data[5] != 1:
        raise ElfError("only 64-bit little-endian ELF is supported")

    (e_type, e_machine, _ver, e_entry, e_phoff, _shoff, _flags,
     _ehsize, e_phentsize, e_phnum) = struct.unpack_from("<HHIQQQIHHH", data, 16)

    if e_machine != EM_X86_64:
        raise ElfError(f"not x86-64 (e_machine={e_machine:#x})")
    if e_type not in (ET_EXEC, ET_DYN) + SONY_TYPES:
        raise ElfError(f"unsupported ELF type {e_type:#x} (need executable or position-independent)")
    if e_phentsize != 56:
        raise ElfError(f"unexpected program header size {e_phentsize}")

    image = ElfImage(entry=e_entry, phent=e_phentsize, phnum=e_phnum, e_type=e_type)
    dyn_offset = dyn_size = dynlib = None
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + 56 > len(data):
            raise ElfError("program header table runs past end of file")
        (p_type, p_flags, p_offset, p_vaddr, _paddr,
         p_filesz, p_memsz, _align) = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == PT_PHDR:
            image.phdr_addr = p_vaddr
        if p_type == PT_DYNAMIC:
            dyn_offset, dyn_size = p_offset, p_filesz
        if p_type == PT_TLS:
            image.tls = (p_vaddr, p_filesz, p_memsz, _align)
        if p_type == PT_SCE_DYNLIBDATA:
            dynlib = (p_offset, p_filesz)  # tables live here; it is never mapped into memory
        if p_type == PT_SCE_RELRO:
            p_flags |= PF_W  # holds the GOT; a real system remaps it read-only after linking
        if p_type not in (PT_LOAD, PT_SCE_RELRO):
            continue
        if p_offset + p_filesz > len(data):
            raise ElfError(f"segment {i} data runs past end of file")
        if p_filesz > p_memsz:
            raise ElfError(f"segment {i}: filesz > memsz")
        image.segments.append(Segment(p_vaddr, p_offset, p_filesz, p_memsz, p_flags))

    if not image.segments:
        raise ElfError("no PT_LOAD segments")
    if not image.phdr_addr:  # no PT_PHDR: find the segment that contains the table
        for seg in image.segments:
            if seg.offset <= e_phoff < seg.offset + seg.filesz:
                image.phdr_addr = seg.vaddr + (e_phoff - seg.offset)
                break
    if dyn_offset is not None:
        if e_type in SONY_TYPES and dynlib is not None:
            image.sony = True
            image.dynamic = _parse_sony_dynamic(data, image, dyn_offset, dyn_size, *dynlib)
        else:
            image.dynamic = _parse_dynamic(data, image, dyn_offset, dyn_size)
    return image
