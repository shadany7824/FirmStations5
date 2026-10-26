"""Thread-local storage for the main thread of a position-independent program.

On x86-64 the thread pointer (the fs base) points at a small control block; the program's
thread-local variables sit just *below* it. The first word of the control block points to
itself, which is how code finds its own thread pointer (%fs:0). We also fill the word at
offset 0x10, where Linux's C library keeps the same pointer.
"""
import struct

TLS_REGION = 0x3C000000
TLS_REGION_SIZE = 0x10000


def setup_tls(cpu, image, base):
    """Create the main thread's TLS block and point fs at it. Returns the thread pointer,
    or None if the program has no TLS segment."""
    if image.tls is None:
        return None
    vaddr, filesz, memsz, align = image.tls
    align = max(align, 16)
    block = (memsz + align - 1) // align * align
    cpu.map(TLS_REGION, TLS_REGION_SIZE, 3)  # read + write
    tp = TLS_REGION + 0x1000 + block         # variables occupy [tp - block, tp)
    if filesz:
        cpu.write(tp - block, cpu.read(base + vaddr, filesz))  # the initial values
    cpu.write(tp, struct.pack("<Q", tp))
    cpu.write(tp + 0x10, struct.pack("<Q", tp))
    cpu.set_reg("fs_base", tp)
    return tp
