"""Builds the initial process stack the way a Unix kernel does:

    rsp -> argc | argv[0..n-1] | NULL | envp (just NULL) | auxv pairs ... AT_NULL

C runtimes (glibc, musl) read the auxiliary vector at startup: AT_PHDR lets them find the
TLS template, AT_RANDOM seeds stack-protector canaries, and so on. Without it, a normal
libc program crashes before main().
"""
import os
import struct

from .loader import PERM_R, PERM_W

STACK_TOP = 0x7FFF0000
STACK_SIZE = 0x100000

AT_NULL, AT_PHDR, AT_PHENT, AT_PHNUM, AT_PAGESZ, AT_ENTRY = 0, 3, 4, 5, 6, 9
AT_UID, AT_EUID, AT_GID, AT_EGID, AT_SECURE, AT_RANDOM = 11, 12, 13, 14, 23, 25


def build_initial_stack(cpu, image, argv, random_bytes=None, base=0):
    """Map the stack, fill it in, and return the initial rsp (16-byte aligned)."""
    cpu.map(STACK_TOP - STACK_SIZE, STACK_SIZE, PERM_R | PERM_W)
    top = STACK_TOP

    top -= 16
    rnd_addr = top
    cpu.write(rnd_addr, random_bytes if random_bytes is not None else os.urandom(16))

    argv_addrs = []
    for arg in argv:
        raw = arg.encode() + b"\x00"
        top -= len(raw)
        cpu.write(top, raw)
        argv_addrs.append(top)

    auxv = [
        (AT_PHDR, base + image.phdr_addr), (AT_PHENT, image.phent), (AT_PHNUM, image.phnum),
        (AT_PAGESZ, 0x1000), (AT_ENTRY, base + image.entry),
        (AT_UID, 0), (AT_EUID, 0), (AT_GID, 0), (AT_EGID, 0),
        (AT_SECURE, 0), (AT_RANDOM, rnd_addr), (AT_NULL, 0),
    ]
    words = [len(argv)] + argv_addrs + [0]   # argc, argv[], NULL
    words += [0]                             # envp: empty, just the NULL terminator
    words += [v for pair in auxv for v in pair]

    sp = (top - 8 * len(words)) & ~0xF
    cpu.write(sp, struct.pack(f"<{len(words)}Q", *words))
    return sp
