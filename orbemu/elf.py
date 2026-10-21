"""Minimal ELF64 parser: just enough to find the loadable segments."""
import struct
from dataclasses import dataclass, field
from typing import List

PT_LOAD = 1
PT_PHDR = 6
PF_X, PF_W, PF_R = 1, 2, 4
EM_X86_64 = 0x3E
ET_EXEC = 2


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
class ElfImage:
    entry: int
    segments: List[Segment] = field(default_factory=list)
    phdr_addr: int = 0  # virtual address of the program header table (AT_PHDR)
    phent: int = 56
    phnum: int = 0


def parse_elf(data: bytes) -> ElfImage:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ElfError("not an ELF file (bad magic)")
    if data[4] != 2 or data[5] != 1:
        raise ElfError("only 64-bit little-endian ELF is supported")

    (e_type, e_machine, _ver, e_entry, e_phoff, _shoff, _flags,
     _ehsize, e_phentsize, e_phnum) = struct.unpack_from("<HHIQQQIHHH", data, 16)

    if e_machine != EM_X86_64:
        raise ElfError(f"not x86-64 (e_machine={e_machine:#x})")
    if e_type != ET_EXEC:
        raise ElfError(f"only fixed-address ET_EXEC is supported for now (e_type={e_type})")
    if e_phentsize != 56:
        raise ElfError(f"unexpected program header size {e_phentsize}")

    image = ElfImage(entry=e_entry, phent=e_phentsize, phnum=e_phnum)
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + 56 > len(data):
            raise ElfError("program header table runs past end of file")
        (p_type, p_flags, p_offset, p_vaddr, _paddr,
         p_filesz, p_memsz, _align) = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == PT_PHDR:
            image.phdr_addr = p_vaddr
        if p_type != PT_LOAD:
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
    return image
