"""Helpers shared by the Python-implemented libraries (libc, POSIX, PlayStation)."""
import struct
import sys

HEAP_BASE = 0x38000000
HEAP_SIZE = 16 << 20
ENOSYS_LINUX, ENOSYS_BSD = 38, 78  # the one errno number that differs between Linux and FreeBSD here


def read_cstr(cpu, addr, limit=1 << 16):
    out = bytearray()
    for i in range(limit):
        b = cpu.read(addr + i, 1)
        if b == b"\x00":
            break
        out += b
    return bytes(out)


def stdout_write(k, data):
    stream = k.streams.get(1)
    if stream is not None:
        stream.write(data)
        if hasattr(stream, "flush"):
            stream.flush()


def alloc(k, n, align=16):
    """Bump-allocate n bytes of zeroed guest memory (0 if the arena is exhausted)."""
    st = k.hle_state
    if "heap_next" not in st:
        k.cpu.map(HEAP_BASE, HEAP_SIZE, 3)  # read + write
        st["heap_next"] = HEAP_BASE
    n = (max(n, 1) + align - 1) & ~(align - 1)
    if st["heap_next"] + n > HEAP_BASE + HEAP_SIZE:
        return 0
    addr = st["heap_next"]
    st["heap_next"] += n
    return addr


def errno_address(k):
    """Where this program's `errno` lives (what __error() returns a pointer to)."""
    st = k.hle_state
    if "errno" not in st:
        st["errno"] = alloc(k, 16)
    return st["errno"]


def set_errno(k, value):
    k.cpu.write(errno_address(k), struct.pack("<I", value))


def fail(k, errno):
    """The C library convention for a failed call: set errno and return -1."""
    set_errno(k, errno)
    return -1


def posix_result(k, ret):
    """Turn the kernel layer's negative-errno result into the C convention (-1 plus errno)."""
    if ret < 0:
        return fail(k, ENOSYS_BSD if ret == -ENOSYS_LINUX else -ret)
    return ret


def stack_arg(k, n):
    """The n-th argument beyond the sixth (n=0 is the 7th). Those travel on the stack, and our stubs
    do not touch it, so at the call the return address is at rsp and the 7th argument just above it."""
    rsp = k.cpu.get_reg("rsp")
    return struct.unpack("<Q", k.cpu.read(rsp + 8 + 8 * n, 8))[0]
