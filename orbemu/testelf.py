"""Builds a tiny static x86-64 ELF that prints a message and exits.

    python -m orbemu.testelf hello.elf [--abi linux|freebsd]
"""
import argparse
import struct

BASE = 0x400000
HEADERS = 64 + 56
SYSCALLS = {"linux": (1, 60), "freebsd": (4, 1)}  # (write, exit)


def build_test_elf(abi="linux", message=b"Hello from orbemu!\n"):
    nr_write, nr_exit = SYSCALLS[abi]
    entry = BASE + HEADERS

    def code(msg_va):
        c = b""
        c += b"\xb8" + struct.pack("<I", nr_write)        # mov eax, write
        c += b"\xbf" + struct.pack("<I", 1)               # mov edi, 1 (stdout)
        lea_next = entry + len(c) + 7                     # lea is 7 bytes
        c += b"\x48\x8d\x35" + struct.pack("<i", msg_va - lea_next)  # lea rsi,[rip+rel]
        c += b"\xba" + struct.pack("<I", len(message))    # mov edx, len
        c += b"\x0f\x05"                                  # syscall
        c += b"\xb8" + struct.pack("<I", nr_exit)         # mov eax, exit
        c += b"\x31\xff"                                  # xor edi, edi
        c += b"\x0f\x05"                                  # syscall
        return c

    code_len = len(code(0))
    body = code(entry + code_len) + message
    total = HEADERS + len(body)

    ehdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    ehdr += struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, entry, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, BASE, BASE, total, total, 0x1000)
    return ehdr + phdr + body


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--abi", choices=list(SYSCALLS), default="linux")
    a = ap.parse_args()
    with open(a.out, "wb") as f:
        f.write(build_test_elf(a.abi))
    print(f"wrote {a.out} ({a.abi} syscalls)")
