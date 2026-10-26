"""Describe an ELF or PS4-style SELF file without changing anything.

    python -m orbemu.describe FILE                 # header, segments, dynamic tags, hex samples
    python -m orbemu.describe FILE --extract OUT   # write the plain ELF out of a SELF wrapper

Used to look at real PlayStation-style programs before teaching orbemu to load them: it prints
raw numbers next to the names it knows, so anything unfamiliar shows up as a number you can
report. It never decrypts anything. A SELF whose segments are encrypted or compressed is
reported as such and left alone.

NOTE: the SELF layout below follows public documentation as the author remembers it and has
not yet been checked against a real file; treat the output as a hypothesis until it has been.
"""
import struct
import sys

from .elf import SONY_DT_NAMES, ElfError, parse_elf
from .names import name_for
from .nid import split_import_name

SELF_MAGIC = b"\x4f\x15\x3d\x1d"

ET_NAMES = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 0xFE00: "SCE_EXEC (Sony)",
            0xFE01: "SCE_REPLAY_EXEC (Sony)", 0xFE04: "SCE_RELEXEC (Sony)",
            0xFE10: "SCE_DYNEXEC (Sony)", 0xFE18: "SCE_DYNAMIC (Sony)"}
PT_NAMES = {0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE", 6: "PHDR", 7: "TLS",
            0x6474E550: "GNU_EH_FRAME", 0x6474E551: "GNU_STACK", 0x6474E552: "GNU_RELRO", 0x6474E553: "GNU_PROPERTY",
            0x61000000: "SCE_DYNLIBDATA (Sony)", 0x61000001: "SCE_PROCPARAM (Sony)",
            0x61000002: "SCE_MODULE_PARAM (Sony)", 0x61000010: "SCE_RELRO (Sony)",
            0x6FFFFF00: "SCE_COMMENT (Sony)", 0x6FFFFF01: "SCE_LIBVERSION (Sony)"}
DT_NAMES = {0: "NULL", 1: "NEEDED", 2: "PLTRELSZ", 3: "PLTGOT", 4: "HASH", 5: "STRTAB",
            6: "SYMTAB", 7: "RELA", 8: "RELASZ", 9: "RELAENT", 10: "STRSZ", 11: "SYMENT",
            12: "INIT", 13: "FINI", 14: "SONAME", 15: "RPATH", 16: "SYMBOLIC", 29: "RUNPATH", 20: "PLTREL",
            21: "DEBUG", 23: "JMPREL", 24: "BIND_NOW", 25: "INIT_ARRAY", 26: "FINI_ARRAY",
            27: "INIT_ARRAYSZ", 28: "FINI_ARRAYSZ", 30: "FLAGS", 0x6FFFFEF5: "GNU_HASH",
            0x6FFFFFFB: "FLAGS_1"}
DT_NAMES.update(SONY_DT_NAMES)
PT_DYNAMIC = 2


def is_sony_segment(ptype):
    """Sony's own segment types: 0x6100xxxx and 0x6FFFFFxx (not the GNU ones at 0x6474e5xx)."""
    return 0x61000000 <= ptype <= 0x6100FFFF or 0x6FFFFF00 <= ptype <= 0x6FFFFFFF


class DescribeError(Exception):
    pass


def hexdump(data, count=64):
    lines = []
    for i in range(0, min(len(data), count), 16):
        chunk = data[i:i + 16]
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"    {i:04x}  {chunk.hex(' '):<47}  {text}")
    return lines


def parse_self(data):
    """Returns (header dict, entries) for a SELF file."""
    if len(data) < 0x20 or data[:4] != SELF_MAGIC:
        raise DescribeError("not a SELF file")
    version, mode, endian, attribs = struct.unpack_from("<BBBB", data, 4)
    key_type, header_size, meta_size, file_size, num_entries, flags = struct.unpack_from("<IHHQHH", data, 8)
    if 0x20 + 0x20 * num_entries > len(data):
        raise DescribeError("SELF entry table runs past the end of the file")
    entries = []
    for i in range(num_entries):
        props, offset, filesize, memsize = struct.unpack_from("<QQQQ", data, 0x20 + 0x20 * i)
        entries.append({
            "props": props, "offset": offset, "filesize": filesize, "memsize": memsize,
            "id": props >> 20, "encrypted": bool(props & 0x2), "compressed": bool(props & 0x8),
            "blocked": bool(props & 0x800)})
    header = dict(version=version, mode=mode, endian=endian, attribs=attribs, key_type=key_type,
                  header_size=header_size, meta_size=meta_size, file_size=file_size,
                  num_entries=num_entries, flags=flags, elf_offset=0x20 + 0x20 * num_entries)
    return header, entries


def read_phdrs(elf, base=0):
    """Program headers of the ELF that starts at offset `base` of `elf`."""
    if elf[base:base + 4] != b"\x7fELF":
        raise DescribeError("no ELF header where one was expected")
    e_type, e_machine, _v, e_entry, e_phoff, _shoff, _fl, _eh, e_phentsize, e_phnum = struct.unpack_from(
        "<HHIQQQIHHH", elf, base + 16)
    phdrs = []
    for i in range(e_phnum):
        p_type, p_flags, p_offset, p_vaddr, _pa, p_filesz, p_memsz, p_align = struct.unpack_from(
            "<IIQQQQQQ", elf, base + e_phoff + i * e_phentsize)
        phdrs.append(dict(index=i, type=p_type, flags=p_flags, offset=p_offset, vaddr=p_vaddr,
                          filesz=p_filesz, memsz=p_memsz, align=p_align))
    return dict(e_type=e_type, e_machine=e_machine, entry=e_entry, phoff=e_phoff,
                phentsize=e_phentsize, phnum=e_phnum), phdrs


def unwrap_self(data):
    """Rebuild a plain ELF from a SELF whose segments are stored unencrypted and uncompressed.
    Returns (elf_bytes, notes). Raises DescribeError if that is not possible.

    Layout seen in a real OpenOrbis eboot.bin: entries alternate between small metadata blocks and
    the segment data; the data entries carry the "blocked" flag and an id equal to the program
    header index. Segments that sit inside a bigger one (DYNAMIC inside SCE_DYNLIBDATA, INTERP
    inside the code segment, ...) have no entry of their own."""
    header, entries = parse_self(data)
    elf_base = header["elf_offset"]
    ehdr, phdrs = read_phdrs(data, elf_base)
    size = ehdr["phoff"] + ehdr["phnum"] * ehdr["phentsize"]
    for ph in phdrs:
        size = max(size, ph["offset"] + ph["filesz"])
    out = bytearray(size)
    head_len = ehdr["phoff"] + ehdr["phnum"] * ehdr["phentsize"]
    out[:head_len] = data[elf_base:elf_base + head_len]
    data_entries = [e for e in entries if e["blocked"]] or entries  # metadata entries are not "blocked"
    notes, placed, pending = [], [], []
    for ph in phdrs:
        if not ph["filesz"]:
            continue
        candidates = [e for e in data_entries if e["id"] == ph["index"]]
        exact = [e for e in candidates if e["filesize"] == ph["filesz"]]
        choice = (exact or candidates or [None])[0]
        if choice is None:
            pending.append(ph)
            continue
        if choice["encrypted"] or choice["compressed"]:
            raise DescribeError(f"segment {ph['index']} is "
                                f"{'encrypted' if choice['encrypted'] else 'compressed'}; "
                                "this tool does not decrypt or decompress anything")
        if choice["filesize"] < ph["filesz"]:
            raise DescribeError(f"segment {ph['index']}: SELF entry is smaller than the segment")
        out[ph["offset"]:ph["offset"] + ph["filesz"]] = data[choice["offset"]:choice["offset"] + ph["filesz"]]
        placed.append(ph)
        if choice["filesize"] != ph["filesz"]:
            notes.append(f"segment {ph['index']}: entry size {choice['filesize']:#x} != segment size {ph['filesz']:#x}")
    for ph in pending:  # fine if another segment's data already covers it
        end = ph["offset"] + ph["filesz"]
        if not any(o["offset"] <= ph["offset"] and end <= o["offset"] + o["filesz"] for o in placed):
            raise DescribeError(f"no SELF entry found for segment {ph['index']}")
        notes.append(f"segment {ph['index']} has no entry of its own: it lies inside another segment")
    return bytes(out), notes


def _flags(f):
    return ("R" if f & 4 else "-") + ("W" if f & 2 else "-") + ("X" if f & 1 else "-")


def _import_lines(elf):
    """Imports of an ELF that orbemu's loader can parse, marked with whether Python answers them."""
    from .hle_libc import make_default_registry
    try:
        image = parse_elf(elf)
    except ElfError as e:
        return [f"(orbemu's loader cannot read this file's dynamic data: {e})"]
    lines = []
    if image.sony:
        lines.append("PlayStation-style dynamic data: yes"
                     f"   module={image.module_name!r}   needs={image.dynamic.needed}")
    if image.dynamic is None:
        return lines + ["(no dynamic section: nothing is imported)"]
    registry = make_default_registry()
    imports = list(dict.fromkeys(r.sym for r in image.dynamic.relocs if r.sym and not r.sym_defined))
    kinds = {}
    for r in image.dynamic.relocs:
        kinds[r.rtype] = kinds.get(r.rtype, 0) + 1
    lines.append(f"relocations: {len(image.dynamic.relocs)} " +
                 "(by type: " + ", ".join(f"{t}: {n}" for t, n in sorted(kinds.items())) + ")")
    lines.append(f"imports: {len(imports)}")
    for name in imports:
        plain = name_for(name, registry)
        label = f"{plain}   ({name})" if plain and plain != name else name
        lines.append(f"  {'[python]' if registry.has(name) else '[ MISSING ]'} {label}")
    if image.tls:
        lines.append(f"TLS segment: vaddr={image.tls[0]:#x} filesz={image.tls[1]:#x} "
                     f"memsz={image.tls[2]:#x} align={image.tls[3]:#x}")
    if image.init or image.init_array:
        lines.append(f"init: DT_INIT={image.init:#x} INIT_ARRAY={image.init_array}")
    return lines


def describe(data):
    lines = []
    elf, base, readable = data, 0, True
    if data[:4] == SELF_MAGIC:
        header, entries = parse_self(data)
        lines.append("SELF container")
        lines.append(f"  version={header['version']} mode={header['mode']} endian={header['endian']} "
                     f"attribs={header['attribs']:#x} key_type={header['key_type']:#x}")
        lines.append(f"  header_size={header['header_size']:#x} meta_size={header['meta_size']:#x} "
                     f"file_size={header['file_size']:#x} (actual {len(data):#x}) "
                     f"entries={header['num_entries']} flags={header['flags']:#x}")
        for i, e in enumerate(entries):
            tags = [n for n, on in (("encrypted", e["encrypted"]), ("compressed", e["compressed"]),
                                    ("blocked", e["blocked"])) if on]
            lines.append(f"  entry {i:2d}: props={e['props']:#012x} id={e['id']} offset={e['offset']:#x} "
                         f"filesize={e['filesize']:#x} memsize={e['memsize']:#x} {' '.join(tags)}")
        base = header["elf_offset"]
        lines.append(f"  embedded ELF header expected at {base:#x}")
        try:
            elf, notes = unwrap_self(data)
            lines.append("  all segments are plain: can be unwrapped (use --extract)" +
                         ("".join(f"\n  note: {n}" for n in notes)))
            base = 0
        except DescribeError as e:
            lines.append(f"  cannot unwrap: {e}")
            readable = False  # segment data is not where the ELF headers say it is
        lines.append("")

    ehdr, phdrs = read_phdrs(elf, base)
    lines.append("ELF header")
    lines.append(f"  type={ehdr['e_type']:#x} {ET_NAMES.get(ehdr['e_type'], '?')}   "
                 f"machine={ehdr['e_machine']:#x}   entry={ehdr['entry']:#x}")
    lines.append(f"  program headers: {ehdr['phnum']} at offset {ehdr['phoff']:#x}")
    lines.append("Segments")
    for ph in phdrs:
        name = PT_NAMES.get(ph["type"], "?")
        lines.append(f"  {ph['index']:2d} {ph['type']:#010x} {name:<24} {_flags(ph['flags'])} "
                     f"off={ph['offset']:#08x} vaddr={ph['vaddr']:#010x} "
                     f"filesz={ph['filesz']:#08x} memsz={ph['memsz']:#08x} align={ph['align']:#x}")
    if not readable:
        lines.append("")
        lines.append("(segment contents are not shown: they could not be unwrapped from the SELF)")
        return lines

    for ph in phdrs:
        if ph["type"] == PT_DYNAMIC and ph["filesz"]:
            lines.append("")
            lines.append(f"Dynamic entries (segment {ph['index']}), raw tag and value:")
            for i in range(ph["filesz"] // 16):
                at = base + ph["offset"] + 16 * i
                if at + 16 > len(elf):
                    lines.append("  (runs past the end of the file)")
                    break
                tag, val = struct.unpack_from("<QQ", elf, at)
                lines.append(f"  {tag:#018x}  {DT_NAMES.get(tag, '?'):<20} {val:#x}")
                if tag == 0:
                    break
    lines.append("")
    lines.append("Imports as orbemu's loader sees them:")
    lines.extend("  " + l for l in _import_lines(elf))
    lines.append("")
    lines.append("Hex samples of Sony-specific segments (first 64 bytes):")
    shown = False
    for ph in phdrs:
        if is_sony_segment(ph["type"]) and ph["filesz"]:
            shown = True
            lines.append(f"  segment {ph['index']} {PT_NAMES.get(ph['type'], '?')}:")
            lines.extend(hexdump(elf[base + ph["offset"]:base + ph["offset"] + 64]))
    if not shown:
        lines.append("  (none: this does not look like a PlayStation-style file)")
    return lines


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    extract = None
    if "--extract" in argv:
        i = argv.index("--extract")
        extract = argv[i + 1] if i + 1 < len(argv) else None
        del argv[i:i + 2]
    if len(argv) != 1 or (extract is None and "--extract" in sys.argv):
        print(__doc__)
        return 2
    with open(argv[0], "rb") as f:
        data = f.read()
    try:
        if extract:
            elf, notes = unwrap_self(data)
            with open(extract, "wb") as f:
                f.write(elf)
            print(f"wrote {extract} ({len(elf)} bytes)" + "".join(f"\n  note: {n}" for n in notes))
        else:
            print("\n".join(describe(data)))
    except DescribeError as e:
        print(f"describe: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
