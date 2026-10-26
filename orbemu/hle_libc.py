"""A small C library written in Python: the default answers for a program's imports."""
import time as _time

from . import hle_posix, hle_ps4, hle_video
from .hle import HleRegistry
from .hle_util import HEAP_BASE, HEAP_SIZE, alloc, read_cstr, stdout_write as _stdout  # noqa: F401


def format_printf(cpu, fmt, args):
    """printf-style formatting. Supports %d %i %u %x %X %c %s %p %%, flags - 0 + #,
    a width, and the l/ll/z length modifiers. `args` are the integer arguments from the
    registers (at most 5 after the format string)."""
    out, i, argi = bytearray(), 0, 0

    def next_arg():
        nonlocal argi
        argi += 1
        return args[argi - 1] if argi <= len(args) else 0  # missing arguments read as 0

    while i < len(fmt):
        if fmt[i] != 0x25:  # '%'
            out.append(fmt[i])
            i += 1
            continue
        i += 1
        flags = ""
        while i < len(fmt) and chr(fmt[i]) in "-0+ #":
            flags += chr(fmt[i])
            i += 1
        width = 0
        while i < len(fmt) and 0x30 <= fmt[i] <= 0x39:
            width = width * 10 + fmt[i] - 0x30
            i += 1
        long_ = False
        while i < len(fmt) and chr(fmt[i]) in "lzhjt":
            long_ = long_ or chr(fmt[i]) in "lzjt"
            i += 1
        if i >= len(fmt):
            break
        conv = chr(fmt[i])
        i += 1
        bits = 64 if long_ else 32
        numeric = conv in "diuxXp"
        if conv == "%":
            text = b"%"
        elif conv in "di":
            v = next_arg() & ((1 << bits) - 1)
            v -= (1 << bits) if v >= 1 << (bits - 1) else 0
            text = (b"+" if "+" in flags and v >= 0 else b"") + str(v).encode()
        elif conv == "u":
            text = str(next_arg() & ((1 << bits) - 1)).encode()
        elif conv in "xX":
            v = next_arg() & ((1 << bits) - 1)
            text = format(v, "x" if conv == "x" else "X").encode()
            if "#" in flags and v:
                text = (b"0x" if conv == "x" else b"0X") + text
        elif conv == "p":
            text = b"0x" + format(next_arg() & (2**64 - 1), "x").encode()
        elif conv == "c":
            text = bytes([next_arg() & 0xFF])
        elif conv == "s":
            addr = next_arg()
            text = b"(null)" if addr == 0 else read_cstr(cpu, addr)
        else:
            text = b"%" + conv.encode()
        if len(text) < width:
            if "-" in flags:
                text = text.ljust(width)
            elif "0" in flags and numeric:
                sign, digits = (text[:1], text[1:]) if text[:1] in (b"-", b"+") else (b"", text)
                text = sign + digits.rjust(width - len(sign), b"0")
            else:
                text = text.rjust(width)
        out += text
    return bytes(out)


def make_default_registry():
    r = HleRegistry()

    @r.function("puts")
    def puts(k, s, *_):
        data = read_cstr(k.cpu, s) + b"\n"
        _stdout(k, data)
        return len(data)

    @r.function("putchar")
    def putchar(k, c, *_):
        _stdout(k, bytes([c & 0xFF]))
        return c & 0xFF

    @r.function("printf")
    def printf(k, fmt, *args):
        data = format_printf(k.cpu, read_cstr(k.cpu, fmt), args[:5])
        _stdout(k, data)
        return len(data)

    @r.function("strlen")
    def strlen(k, s, *_):
        return len(read_cstr(k.cpu, s))

    @r.function("memset")
    def memset(k, dst, c, n, *_):
        k.cpu.write(dst, bytes([c & 0xFF]) * n)
        return dst

    @r.function("memcpy")
    def memcpy(k, dst, src, n, *_):
        k.cpu.write(dst, k.cpu.read(src, n))
        return dst

    r.function("memmove")(memcpy)

    @r.function("malloc")
    def malloc(k, n, *_):
        return alloc(k, n)  # fresh memory is already zeroed

    @r.function("calloc")
    def calloc(k, count, size, *_):
        return malloc(k, count * size)

    @r.function("free")
    def free(k, p, *_):
        return 0  # a bump allocator never reuses memory (fine for small programs)

    @r.function("exit")
    def exit_(k, code, *_):
        return k.sys_exit(code)

    # --- a few PS4 kernel functions (programs import them by NID; see nid.py) ---
    @r.function("sceKernelUsleep")
    def sceKernelUsleep(k, microseconds, *_):
        _time.sleep(min(microseconds / 1e6, 5.0))
        return 0

    @r.function("sceKernelSleep")
    def sceKernelSleep(k, seconds, *_):
        _time.sleep(min(seconds, 5))
        return 0

    @r.function("sceKernelGetProcessTime")
    def sceKernelGetProcessTime(k, *_):
        return int((_time.monotonic() - k._started) * 1e6)  # microseconds since start

    @r.function("sceKernelGetProcessTimeCounter")
    def sceKernelGetProcessTimeCounter(k, *_):
        return _time.perf_counter_ns()

    @r.function("sceKernelGetProcessTimeCounterFrequency")
    def sceKernelGetProcessTimeCounterFrequency(k, *_):
        return 1_000_000_000  # the counter above counts nanoseconds

    @r.function("orb_add")
    def orb_add(k, a, b, *_):
        v = (a + b) & 0xFFFFFFFF
        return v - (1 << 32) if v >= 1 << 31 else v

    hle_posix.register(r)
    hle_ps4.register(r)
    hle_video.register(r)
    return r
