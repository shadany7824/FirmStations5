"""Dynamic linking: patch a loaded image's relocations, answering imports with HLE stubs.

No shared library is ever loaded. Where a real dynamic linker would find `puts` in libc,
orbemu points the program at a stub that runs a Python function instead.
"""
import struct
import sys
from dataclasses import dataclass, field

R_X86_64_NONE, R_X86_64_64, R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT, R_X86_64_RELATIVE = 0, 1, 6, 7, 8
MASK = 0xFFFFFFFFFFFFFFFF


@dataclass
class LinkReport:
    resolved: list = field(default_factory=list)      # imports answered by a Python function
    missing: list = field(default_factory=list)       # imports with no Python function yet
    unsupported: list = field(default_factory=list)   # relocation types we do not handle


def apply_relocations(image, base, mem, stubs):
    report = LinkReport()
    if image.dynamic is None:
        return report
    for r in image.dynamic.relocs:
        t = r.rtype
        if t == R_X86_64_NONE:
            continue
        if t == R_X86_64_RELATIVE:
            value = base + r.addend
        elif t in (R_X86_64_64, R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT):
            if r.sym is None:
                symbol = 0
            elif r.sym_defined:
                symbol = base + r.sym_value
            elif r.weak and not stubs.registry.has(r.sym):
                symbol = 0  # an optional import nobody provides: resolves to NULL, like a real linker
            else:
                symbol = stubs.address_for(r.sym)
                bucket = report.resolved if stubs.registry.has(r.sym) else report.missing
                if r.sym not in bucket:
                    bucket.append(r.sym)
            value = symbol + (r.addend if t == R_X86_64_64 else 0)
        else:
            if t not in report.unsupported:
                report.unsupported.append(t)
            continue
        mem.write(base + r.offset, struct.pack("<Q", value & MASK))
    return report
