"""High-level emulation of libraries: guest imports are answered by Python functions.

Each imported function gets a stub in guest memory. The usual stub is 16 bytes:

    mov r10, rcx        ; syscall passes argument 4 in r10, C passes it in rcx
    mov eax, 0x2000+N   ; our own syscall number for "call HLE function N"
    syscall             ; the Kernel catches this and runs the Python function
    ret

So the guest simply calls the stub like any function; the first six integer arguments
arrive in the Python function, and its return value comes back in rax.

A few functions must call back into guest code (pthread_once runs the program's init routine).
Python cannot do that from inside a syscall, so those are registered as "native" stubs: plain
machine code that runs on the emulated CPU instead.
"""
import collections
import inspect
import struct
import sys

from .loader import PAGE, PERM_R, PERM_X
from .names import name_for
from .nid import nid_for, split_import_name

HLE_SYSCALL_BASE = 0x2000
STUB_BASE = 0x0F000000
STUB_SIZE = 16
STUB_PAGES = 16  # 64 KB of stubs


def make_stub(index):
    code = b"\x49\x89\xca" + b"\xb8" + struct.pack("<I", HLE_SYSCALL_BASE + index) + b"\x0f\x05\xc3"
    return code.ljust(STUB_SIZE, b"\xcc")


class HleRegistry:
    """Maps import names (like "puts") to Python functions fn(kernel, a0..a5) -> int."""

    def __init__(self):
        self.functions = {}
        self.native = {}      # name -> machine code bytes
        self._nid_count = -1
        self._by_nid = {}

    def function(self, name):
        def decorator(fn):
            self.functions[name] = fn
            return fn
        return decorator

    def native_function(self, name, code):
        self.native[name] = bytes(code)

    def canonical(self, symbol):
        """The plain name we know for an import (a name, a NID, or "NID#lib#module"), or None."""
        if symbol in self.functions or symbol in self.native:
            return symbol
        key = split_import_name(symbol)[0]
        if key in self.functions or key in self.native:
            return key
        count = len(self.functions) + len(self.native)
        if self._nid_count != count:  # (re)build after new functions were added
            self._by_nid = {nid_for(n): n for n in list(self.functions) + list(self.native)}
            self._nid_count = count
        return self._by_nid.get(key)

    def lookup(self, symbol):
        return self.functions.get(self.canonical(symbol))

    def native_code(self, symbol):
        return self.native.get(self.canonical(symbol))

    def has(self, symbol):
        return self.canonical(symbol) is not None


class StubTable:
    def __init__(self, mem, registry):
        self.mem, self.registry = mem, registry
        self.names, self.by_name, self.reported = [], {}, set()
        self.used = 0
        self._mapped = False
        self.recent = collections.deque(maxlen=16)  # the last imports called, for crash reports
        self.trace = False
        self.failures = {}       # (function, error) -> how many times it failed
        self._arity_cache = {}

    def _alloc(self, size):
        size = (size + STUB_SIZE - 1) & ~(STUB_SIZE - 1)
        if self.used + size > STUB_PAGES * PAGE:
            raise RuntimeError("too many imports")
        if not self._mapped:
            self.mem.map(STUB_BASE, STUB_PAGES * PAGE, PERM_R | PERM_X)
            self._mapped = True
        addr = STUB_BASE + self.used
        self.used += size
        return addr

    def address_for(self, name):
        """Guest address of the stub for `name` (created on first use)."""
        if name in self.by_name:
            return self.by_name[name]
        code = self.registry.native_code(name)
        if code is not None:
            addr = self._alloc(len(code))
            self.mem.write(addr, code)
        else:
            addr = self._alloc(STUB_SIZE)
            self.mem.write(addr, make_stub(len(self.names)))
            self.names.append(name)
        self.by_name[name] = addr
        return addr

    def _arity(self, fn):
        """How many of the six register arguments `fn` wants (all six if it takes *args)."""
        n = self._arity_cache.get(fn)
        if n is None:
            params = list(inspect.signature(fn).parameters.values())[1:]   # skip the kernel argument
            if any(p.kind is p.VAR_POSITIONAL for p in params):
                n = 6
            else:
                n = sum(1 for p in params if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD))
            self._arity_cache[fn] = n
        return n

    def report_failures(self):
        """Print a summary of functions that failed more than once (each is only printed once live)."""
        for (shown, message), count in self.failures.items():
            if count > 1:
                print(f"[hle] {shown}() failed {count} times in total: {message}", file=sys.stderr)

    def dispatch(self, kernel, index, args):
        if index >= len(self.names):
            print(f"[hle] call to unknown stub {index}", file=sys.stderr)
            return -38
        name = self.names[index]
        shown = name_for(name, self.registry) or name
        self.recent.append(shown)
        if self.trace:
            print(f"[hle] {shown}({', '.join(hex(a) for a in args[:4])})", file=sys.stderr)
        fn = self.registry.lookup(name)
        if fn is None:
            if name not in self.reported:
                self.reported.add(name)
                print(f"[hle] unimplemented import {shown}() was called", file=sys.stderr)
            return 0
        try:
            return int(fn(kernel, *args[:self._arity(fn)]) or 0)
        except Exception as e:  # a bug in an HLE function must not crash the emulator
            key = (shown, repr(e))
            self.failures[key] = self.failures.get(key, 0) + 1
            if self.failures[key] == 1:   # say it once; report_failures() adds the total at the end
                print(f"[hle] {shown}() failed: {e!r}", file=sys.stderr)
            return -1
