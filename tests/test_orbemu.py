import contextlib
import ctypes
import inspect
import io
import mmap
import os
import struct
import sys
import tempfile
import unittest
from types import SimpleNamespace

from orbemu.__main__ import build_parser, make_display_factory, make_pad_factory
from orbemu import pad as padmod
from orbemu.dynlink import apply_relocations
from orbemu.elf import ET_DYN
from orbemu.hle import HLE_SYSCALL_BASE, HleRegistry, StubTable, make_stub
from orbemu.hle_libc import format_printf, make_default_registry
from orbemu.describe import (DescribeError, describe, hexdump, is_sony_segment, parse_self,
                             read_phdrs, unwrap_self)
from orbemu.nid import nid_for, split_import_name
from orbemu.elf import DT_SCE, ElfImage
from orbemu.tls import setup_tls
from orbemu import hle_ps4
from orbemu.diag import format_fault, format_registers
from orbemu.hle_posix import PTHREAD_ONCE
from orbemu.hle_util import errno_address
from orbemu.names import name_for, pretty
from orbemu.runloop import run_sliced
from orbemu import hle_video
from orbemu.display import shrink_pixels
from orbemu.hle_util import stack_arg
from unittest import mock
import itertools
from orbemu.display import (KEY_ACTION, KEY_DOWN, KEY_ESCAPE, KEY_LEFT, KEY_RIGHT, KEY_UP,
                            KeyState, PpmDisplay, bgrx_to_rgb)
from orbemu.elf import ElfError, parse_elf
from orbemu.kernel import Kernel
from orbemu.loader import load_image
from orbemu.stack import STACK_TOP, build_initial_stack
from orbemu.testelf import build_test_elf


class FakeCpu:
    """Stand-in for the Unicorn backend so the logic can be tested without it."""
    def __init__(self):
        self.maps, self.mem, self.regs, self.stopped = [], {}, {}, False
        self.protects, self.unmaps = [], []

    def map(self, addr, size, perms):
        self.maps.append((addr, size, perms))

    def unmap(self, addr, size):
        self.unmaps.append((addr, size))

    def protect(self, addr, size, perms):
        self.protects.append((addr, size, perms))

    def write(self, addr, data):
        for i, b in enumerate(data):
            self.mem[addr + i] = b

    def read(self, addr, size):
        return bytes(self.mem[addr + i] for i in range(size))

    def get_reg(self, name):
        return self.regs.get(name, 0)

    def set_reg(self, name, value):
        self.regs[name] = value

    def stop(self):
        self.stopped = True


class ElfTests(unittest.TestCase):
    def test_parse_and_load(self):
        data = build_test_elf("linux")
        image = parse_elf(data)
        self.assertEqual(image.entry, 0x400078)
        cpu = FakeCpu()
        entry = load_image(image, data, cpu)
        self.assertEqual(entry, 0x400078)
        self.assertEqual(cpu.maps, [(0x400000, 0x1000, 5)])  # R+X
        self.assertEqual(cpu.read(0x400078, 1), b"\xb8")     # first opcode: mov eax, imm32

    def test_rejects_garbage(self):
        with self.assertRaises(ElfError):
            parse_elf(b"not an elf" * 20)


class KernelTests(unittest.TestCase):
    def run_syscall(self, abi, num, args):
        cpu = FakeCpu()
        out = io.BytesIO()
        k = Kernel(cpu, abi=abi, streams={1: out})
        cpu.regs["rax"] = num
        for reg, val in zip(("rdi", "rsi", "rdx", "r10", "r8", "r9"), args):
            cpu.regs[reg] = val
        return cpu, k, out

    def test_write_linux(self):
        cpu, k, out = self.run_syscall("linux", 1, [1, 0x1000, 5])
        cpu.write(0x1000, b"hello")
        k.handle_syscall(cpu)
        self.assertEqual(out.getvalue(), b"hello")
        self.assertEqual(cpu.regs["rax"], 5)

    def test_write_freebsd_number(self):
        cpu, k, out = self.run_syscall("freebsd", 4, [1, 0x1000, 2])
        cpu.write(0x1000, b"hi")
        k.handle_syscall(cpu)
        self.assertEqual(out.getvalue(), b"hi")

    def test_exit(self):
        cpu, k, _ = self.run_syscall("linux", 60, [3])
        k.handle_syscall(cpu)
        self.assertEqual(k.exit_code, 3)
        self.assertTrue(cpu.stopped)

    def test_unknown_syscall_returns_enosys(self):
        cpu, k, _ = self.run_syscall("linux", 9999, [])
        k.handle_syscall(cpu)
        self.assertEqual(cpu.regs["rax"], (-38) & 0xFFFFFFFFFFFFFFFF)

    def test_anonymous_mmap(self):
        cpu, k, _ = self.run_syscall("linux", 9, [0, 100, 3, 0x22, 0xFFFFFFFFFFFFFFFF, 0])
        k.handle_syscall(cpu)
        self.assertEqual(cpu.regs["rax"], 0x10000000)
        self.assertEqual(cpu.maps, [(0x10000000, 0x1000, 3)])


class MoreKernelTests(KernelTests):
    """Reuses the helper from KernelTests (its own tests are skipped via the base-class guard)."""

    def cstr(self, cpu, addr, text):
        cpu.write(addr, text.encode() + b"\x00")

    def test_brk_grows_and_maps(self):
        cpu, k, _ = self.run_syscall("linux", 12, [0])
        k.handle_syscall(cpu)
        base = cpu.regs["rax"]
        self.assertEqual(base, 0x20000000)
        cpu.regs.update(rax=12, rdi=base + 0x2800)
        k.handle_syscall(cpu)
        self.assertEqual(cpu.regs["rax"], base + 0x2800)
        self.assertEqual(cpu.maps, [(base, 0x3000, 3)])  # rounded up to whole pages

    def test_brk_below_base_is_refused(self):
        cpu, k, _ = self.run_syscall("linux", 12, [0x1000])
        k.handle_syscall(cpu)
        self.assertEqual(cpu.regs["rax"], 0x20000000)  # returns current break, maps nothing
        self.assertEqual(cpu.maps, [])

    def test_arch_prctl_set_fs(self):
        cpu, k, _ = self.run_syscall("linux", 158, [0x1002, 0xDEAD000])
        k.handle_syscall(cpu)
        self.assertEqual(cpu.regs["fs_base"], 0xDEAD000)
        self.assertEqual(cpu.regs["rax"], 0)

    def test_open_read_close(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "a.txt"), "wb") as f:
                f.write(b"data!")
            cpu, k, _ = self.run_syscall("linux", 2, [0x1000, 0, 0])
            k.root = root
            self.cstr(cpu, 0x1000, "a.txt")
            k.handle_syscall(cpu)
            fd = cpu.regs["rax"]
            self.assertEqual(fd, 3)
            cpu.regs.update(rax=0, rdi=fd, rsi=0x2000, rdx=100)
            k.handle_syscall(cpu)
            self.assertEqual(cpu.regs["rax"], 5)
            self.assertEqual(cpu.read(0x2000, 5), b"data!")
            cpu.regs.update(rax=3, rdi=fd)
            k.handle_syscall(cpu)
            self.assertEqual(cpu.regs["rax"], 0)
            k.handle_syscall(cpu)  # closing twice -> EBADF
            self.assertEqual(cpu.regs["rax"], (-9) & 0xFFFFFFFFFFFFFFFF)

    def test_open_cannot_escape_root(self):
        with tempfile.TemporaryDirectory() as root:
            cpu, k, _ = self.run_syscall("linux", 2, [0x1000, 0, 0])
            k.root = root
            self.cstr(cpu, 0x1000, "../../../../etc/passwd")
            k.handle_syscall(cpu)
            self.assertEqual(cpu.regs["rax"], (-13) & 0xFFFFFFFFFFFFFFFF)

    def test_open_disabled_without_root(self):
        cpu, k, _ = self.run_syscall("linux", 2, [0x1000, 0, 0])
        self.cstr(cpu, 0x1000, "anything")
        k.handle_syscall(cpu)
        self.assertEqual(cpu.regs["rax"], (-13) & 0xFFFFFFFFFFFFFFFF)


class RealElfTests(unittest.TestCase):
    def test_gcc_built_example_loads(self):
        path = os.path.join(os.path.dirname(__file__), "..", "examples", "syscalls.elf")
        with open(path, "rb") as f:
            data = f.read()
        image = parse_elf(data)
        cpu = FakeCpu()
        entry = load_image(image, data, cpu)
        executable = [m for m in cpu.maps if m[2] & 4 and m[0] <= entry < m[0] + m[1]]
        self.assertTrue(executable, "entry point must lie in an executable mapping")
        self.assertEqual(cpu.read(entry, 1), data[entry - 0x400000:entry - 0x400000 + 1])


# Syscalls a static glibc "hello world" makes, recorded with tools/trace_syscalls.py.
GLIBC_STARTUP_SYSCALLS = {1, 5, 10, 12, 158, 218, 231, 267, 273, 302, 318, 334}


def call(kernel, cpu, num, *args):
    cpu.regs["rax"] = num
    for reg, val in zip(("rdi", "rsi", "rdx", "r10", "r8", "r9"), args):
        cpu.regs[reg] = val
    kernel.handle_syscall(cpu)
    ret = cpu.regs["rax"]
    return ret - (1 << 64) if ret >= 1 << 63 else ret


class LibcStartupTests(unittest.TestCase):
    def setUp(self):
        self.cpu = FakeCpu()
        self.k = Kernel(self.cpu, streams={1: io.BytesIO()})

    def test_every_recorded_syscall_is_implemented(self):
        self.assertLessEqual(GLIBC_STARTUP_SYSCALLS, set(self.k.table))

    def test_fstat_reports_character_device_for_stdout(self):
        self.assertEqual(call(self.k, self.cpu, 5, 1, 0x3000), 0)
        raw = self.cpu.read(0x3000, 144)
        mode = struct.unpack_from("<I", raw, 24)[0]
        self.assertEqual(mode & 0o170000, 0o020000)

    def test_fstat_bad_fd(self):
        self.assertEqual(call(self.k, self.cpu, 5, 99, 0x3000), -9)

    def test_mprotect(self):
        self.assertEqual(call(self.k, self.cpu, 10, 0x4A5000, 0x5000, 1), 0)
        self.assertEqual(self.cpu.protects, [(0x4A5000, 0x5000, 1)])
        self.assertEqual(call(self.k, self.cpu, 10, 0x4A5010, 0x1000, 1), -22)  # unaligned

    def test_prlimit_stack_is_8mb(self):
        self.assertEqual(call(self.k, self.cpu, 302, 0, 3, 0, 0x3000), 0)
        cur, mx = struct.unpack("<QQ", self.cpu.read(0x3000, 16))
        self.assertEqual(cur, 8 << 20)
        self.assertEqual(mx, 0xFFFFFFFFFFFFFFFF)

    def test_getrandom(self):
        self.assertEqual(call(self.k, self.cpu, 318, 0x3000, 8, 1), 8)

    def test_small_stubs(self):
        self.assertEqual(call(self.k, self.cpu, 218, 0x3000), 1)
        self.assertEqual(call(self.k, self.cpu, 273, 0x3000, 24), 0)
        self.assertEqual(call(self.k, self.cpu, 334, 0x3000, 32, 0, 0), -38)
        self.assertEqual(call(self.k, self.cpu, 267, -100 & 0xFFFFFFFFFFFFFFFF, 0, 0, 0), -2)
        self.assertEqual(call(self.k, self.cpu, 16, 1, 0x5401, 0), -25)

    def test_initial_stack_layout(self):
        path = os.path.join(os.path.dirname(__file__), "..", "examples", "hello_libc.elf")
        with open(path, "rb") as f:
            image = parse_elf(f.read())
        rsp = build_initial_stack(self.cpu, image, ["prog", "arg1"], random_bytes=b"R" * 16)
        self.assertEqual(rsp % 16, 0)
        words = struct.unpack("<29Q", self.cpu.read(rsp, 232))  # 5 header words + 12 auxv pairs
        self.assertEqual(words[0], 2)                      # argc
        self.assertEqual(self.cpu.read(words[1], 5), b"prog\x00")
        self.assertEqual(self.cpu.read(words[2], 5), b"arg1\x00")
        self.assertEqual((words[3], words[4]), (0, 0))     # argv NULL, envp NULL
        aux = dict(zip(words[5::2], words[6::2]))
        self.assertEqual(aux[3], image.phdr_addr)          # AT_PHDR
        self.assertEqual(aux[5], image.phnum)              # AT_PHNUM
        self.assertEqual(aux[9], image.entry)              # AT_ENTRY
        self.assertEqual(self.cpu.read(aux[25], 16), b"R" * 16)  # AT_RANDOM
        self.assertLess(rsp, STACK_TOP)

    def test_phdr_address_found(self):
        path = os.path.join(os.path.dirname(__file__), "..", "examples", "hello_libc.elf")
        with open(path, "rb") as f:
            image = parse_elf(f.read())
        self.assertEqual(image.phdr_addr, 0x400040)  # first LOAD starts at file offset 0
        self.assertEqual(image.phnum, 10)


# Syscalls the bigger example (examples/hello_files.c) needs. The time ones are invisible to
# the native tracer because Linux answers them from the vDSO, but orbemu has no vDSO.
FILES_PROGRAM_SYSCALLS = {0, 1, 3, 5, 8, 9, 10, 11, 12, 16, 20, 96, 158, 201, 218, 228,
                          231, 257, 262, 267, 273, 302, 318, 334}


class FilesProgramTests(unittest.TestCase):
    def setUp(self):
        self.cpu = FakeCpu()
        self.out = io.BytesIO()
        self.k = Kernel(self.cpu, streams={1: self.out})

    def test_every_needed_syscall_is_implemented(self):
        self.assertLessEqual(FILES_PROGRAM_SYSCALLS, set(self.k.table))

    def test_openat_lseek_read(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "f.txt"), "wb") as f:
                f.write(b"0123456789")
            self.k.root = root
            self.cpu.write(0x1000, b"f.txt\x00")
            fd = call(self.k, self.cpu, 257, (-100) & 0xFFFFFFFFFFFFFFFF, 0x1000, 0, 0)
            self.assertEqual(fd, 3)
            self.assertEqual(call(self.k, self.cpu, 8, fd, 4, 0), 4)           # SEEK_SET
            self.assertEqual(call(self.k, self.cpu, 8, fd, (-2) & (2**64 - 1), 2), 8)  # SEEK_END-2
            self.assertEqual(call(self.k, self.cpu, 0, fd, 0x2000, 10), 2)
            self.assertEqual(self.cpu.read(0x2000, 2), b"89")
            self.assertEqual(call(self.k, self.cpu, 8, 1, 0, 0), -29)          # stdout: ESPIPE

    def test_newfstatat_empty_path_is_fstat(self):
        self.cpu.write(0x1000, b"\x00")
        self.assertEqual(call(self.k, self.cpu, 262, 1, 0x1000, 0x3000, 0x1000), 0)
        self.assertEqual(struct.unpack_from("<I", self.cpu.read(0x3000, 144), 24)[0] & 0o170000, 0o020000)
        self.assertEqual(call(self.k, self.cpu, 262, 1, 0x1000, 0x3000, 0), -2)

    def test_writev_gathers_buffers(self):
        self.cpu.write(0x1000, b"foo")
        self.cpu.write(0x1100, b"barbaz")
        self.cpu.write(0x2000, struct.pack("<QQQQ", 0x1000, 3, 0x1100, 6))
        self.assertEqual(call(self.k, self.cpu, 20, 1, 0x2000, 2), 9)
        self.assertEqual(self.out.getvalue(), b"foobarbaz")

    def test_munmap(self):
        self.assertEqual(call(self.k, self.cpu, 11, 0x10000000, 5000), 0)
        self.assertEqual(self.cpu.unmaps, [(0x10000000, 0x2000)])
        self.assertEqual(call(self.k, self.cpu, 11, 0x10000123, 4096), -22)

    def test_time_syscalls(self):
        self.assertEqual(call(self.k, self.cpu, 228, 0, 0x3000), 0)
        sec, nsec = struct.unpack("<qq", self.cpu.read(0x3000, 16))
        self.assertGreater(sec, 1700000000)
        self.assertLess(nsec, 10**9)
        self.assertEqual(call(self.k, self.cpu, 228, 1, 0x3000), 0)       # monotonic
        self.assertEqual(call(self.k, self.cpu, 228, 99, 0x3000), -22)    # bad clock id
        self.assertGreater(call(self.k, self.cpu, 201, 0x3100), 1700000000)
        self.assertEqual(struct.unpack("<q", self.cpu.read(0x3100, 8))[0] > 1700000000, True)
        self.assertEqual(call(self.k, self.cpu, 96, 0x3200, 0), 0)


class CommandLineTests(unittest.TestCase):
    def parse(self, *argv):
        return build_parser().parse_intermixed_args(list(argv))

    def test_options_before_program(self):
        a = self.parse("--root", "ex", "prog.elf", "one", "two")
        self.assertEqual((a.root, a.elf, a.guest_args), ("ex", "prog.elf", ["one", "two"]))

    def test_options_between_program_and_guest_args(self):
        a = self.parse("prog.elf", "--root", "ex", "one", "two")
        self.assertEqual((a.root, a.elf, a.guest_args), ("ex", "prog.elf", ["one", "two"]))

    def test_no_guest_args(self):
        a = self.parse("prog.elf")
        self.assertEqual((a.elf, a.guest_args, a.root, a.abi), ("prog.elf", [], None, "linux"))


class RecordingDisplay:
    def __init__(self, closed=False):
        self.frames, self.closed, self.pumps, self.shut = [], closed, 0, False
        self.held = 0

    def present(self, width, height, raw):
        self.frames.append((width, height, raw))
        return self.closed

    def pump(self):
        self.pumps += 1

    def keys(self):
        return self.held

    def close(self):
        self.shut = True


class GraphicsTests(unittest.TestCase):
    def make(self, display=None):
        cpu = FakeCpu()
        k = Kernel(cpu, streams={1: io.BytesIO()},
                   display_factory=(lambda: display) if display else None)
        return cpu, k

    def test_present_sends_pixels_to_display(self):
        d = RecordingDisplay()
        cpu, k = self.make(d)
        pixels = bytes(range(16))  # 2x2 pixels, 4 bytes each
        cpu.write(0x5000, pixels)
        self.assertEqual(call(k, cpu, 0x1000, 0x5000, 2, 2), 0)
        self.assertEqual(d.frames, [(2, 2, pixels)])

    def test_present_reports_closed_window(self):
        d = RecordingDisplay(closed=True)
        cpu, k = self.make(d)
        cpu.write(0x5000, bytes(16))
        self.assertEqual(call(k, cpu, 0x1000, 0x5000, 2, 2), 1)

    def test_present_without_display_is_enodev(self):
        cpu, k = self.make(None)
        self.assertEqual(call(k, cpu, 0x1000, 0x5000, 2, 2), -19)

    def test_present_validates_size_and_memory(self):
        cpu, k = self.make(RecordingDisplay())
        self.assertEqual(call(k, cpu, 0x1000, 0x5000, 0, 2), -22)
        self.assertEqual(call(k, cpu, 0x1000, 0x5000, 5000, 5000), -22)
        self.assertEqual(call(k, cpu, 0x1000, 0x5000, 2, 2), -14)  # nothing mapped there

    def test_display_is_created_lazily_and_shut_down(self):
        d = RecordingDisplay()
        created = []
        cpu = FakeCpu()
        k = Kernel(cpu, streams={}, display_factory=lambda: created.append(1) or d)
        self.assertEqual(created, [])  # a program that never draws never opens a window
        cpu.write(0x5000, bytes(16))
        call(k, cpu, 0x1000, 0x5000, 2, 2)
        call(k, cpu, 0x1000, 0x5000, 2, 2)
        self.assertEqual(created, [1])
        k.shutdown()
        self.assertTrue(d.shut)

    def test_nanosleep_pumps_window_events(self):
        d = RecordingDisplay()
        cpu, k = self.make(d)
        cpu.write(0x5000, bytes(16))
        call(k, cpu, 0x1000, 0x5000, 2, 2)  # creates the display
        cpu.write(0x6000, struct.pack("<qq", 0, 1000))
        self.assertEqual(call(k, cpu, 35, 0x6000, 0), 0)
        self.assertEqual(d.pumps, 1)
        cpu.write(0x6000, struct.pack("<qq", 0, 2 * 10**9))
        self.assertEqual(call(k, cpu, 35, 0x6000, 0), -22)

    def test_pixel_conversion(self):
        # guest bytes are B, G, R, unused  ->  RGB
        self.assertEqual(bgrx_to_rgb(bytes([1, 2, 3, 0, 10, 20, 30, 0])), bytes([3, 2, 1, 30, 20, 10]))

    def test_ppm_display_saves_every_nth_frame(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = PpmDisplay(tmp, every=2)
            for _ in range(3):
                d.present(2, 1, bytes([1, 2, 3, 0, 4, 5, 6, 0]))
            self.assertEqual(sorted(os.listdir(tmp)), ["frame_00000.ppm", "frame_00002.ppm"])
            with open(os.path.join(tmp, "frame_00000.ppm"), "rb") as f:
                self.assertEqual(f.read(), b"P6\n2 1\n255\n" + bytes([3, 2, 1, 6, 5, 4]))

    def test_display_options(self):
        a = build_parser().parse_intermixed_args(["x.elf"])
        self.assertIsNotNone(make_display_factory(a))      # window by default (created lazily)
        a = build_parser().parse_intermixed_args(["x.elf", "--display", "none"])
        self.assertIsNone(make_display_factory(a))


class InputTests(unittest.TestCase):
    def test_key_bits_match_the_c_header(self):
        header = os.path.join(os.path.dirname(__file__), "..", "examples", "orb.h")
        with open(header) as f:
            text = f.read()
        for name, value in (("UP", KEY_UP), ("DOWN", KEY_DOWN), ("LEFT", KEY_LEFT),
                            ("RIGHT", KEY_RIGHT), ("ACTION", KEY_ACTION), ("ESCAPE", KEY_ESCAPE)):
            self.assertIn(f"#define ORB_KEY_{name} {value}", text)
        self.assertIn("#define ORB_SYS_INPUT 0x1001", text)

    def test_keystate_press_release(self):
        k = KeyState()
        k.press("Up")
        k.press("Left")
        self.assertEqual(k.bits, KEY_UP | KEY_LEFT)
        k.release("Up")
        self.assertEqual(k.bits, KEY_LEFT)
        k.press("unmapped_key")
        self.assertEqual(k.bits, KEY_LEFT)
        k.clear()
        self.assertEqual(k.bits, 0)

    def test_wasd_and_case_insensitive_letters(self):
        k = KeyState()
        for sym in ("W", "a", "S", "d"):
            k.press(sym)
        self.assertEqual(k.bits, KEY_UP | KEY_LEFT | KEY_DOWN | KEY_RIGHT)

    def test_space_return_and_escape(self):
        k = KeyState()
        k.press("space")
        k.press("Escape")
        self.assertEqual(k.bits, KEY_ACTION | KEY_ESCAPE)
        k.release("space")
        k.press("Return")
        self.assertEqual(k.bits, KEY_ACTION | KEY_ESCAPE)

    def test_input_syscall_reports_held_keys(self):
        d = RecordingDisplay()
        cpu = FakeCpu()
        k = Kernel(cpu, streams={}, display_factory=lambda: d)
        self.assertEqual(call(k, cpu, 0x1001), 0)          # before the first frame: nothing held
        cpu.write(0x5000, bytes(16))
        call(k, cpu, 0x1000, 0x5000, 2, 2)                 # first frame creates the display
        d.held = KEY_UP | KEY_ACTION
        self.assertEqual(call(k, cpu, 0x1001), KEY_UP | KEY_ACTION)

    def test_input_syscall_without_display(self):
        cpu = FakeCpu()
        k = Kernel(cpu, streams={})
        self.assertEqual(call(k, cpu, 0x1001), -19)

    def test_ppm_display_max_frames_acts_like_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = PpmDisplay(tmp, every=100, max_frames=3)
            results = [d.present(1, 1, bytes(4)) for _ in range(3)]
            self.assertEqual(results, [False, False, True])
            self.assertEqual(d.keys(), 0)

    def test_max_frames_option(self):
        a = build_parser().parse_intermixed_args(["x.elf", "--display", "ppm", "--max-frames", "5"])
        self.assertEqual(a.max_frames, 5)


# --- a fake pygame, so the controller mapping logic can be tested without hardware ---
class FakeController:
    def __init__(self, buttons=(), axes=None):
        self.buttons, self.axes, self.alive = set(buttons), dict(axes or {}), True

    def attached(self):
        return self.alive

    def get_button(self, b):
        return b in self.buttons

    def get_axis(self, a):
        return self.axes.get(a, 0)


def make_fake_pygame(controllers):
    names = [n for n, _ in padmod.BUTTON_MAP if n != "CONTROLLER_BUTTON_TOUCHPAD"]
    names += ["CONTROLLER_AXIS_LEFTX", "CONTROLLER_AXIS_LEFTY", "CONTROLLER_AXIS_RIGHTX",
              "CONTROLLER_AXIS_RIGHTY", "CONTROLLER_AXIS_TRIGGERLEFT", "CONTROLLER_AXIS_TRIGGERRIGHT"]
    pg = SimpleNamespace(display=SimpleNamespace(init=lambda: None),
                         event=SimpleNamespace(pump=lambda: None, clear=lambda: None),
                         **{n: n for n in names})  # each constant is just its own name
    ctl = SimpleNamespace(init=lambda: None, set_eventstate=lambda on: None, quit=lambda: None,
                          get_count=lambda: len(controllers),
                          is_controller=lambda i: True,
                          Controller=lambda i: controllers[i])
    return pg, ctl


class PadTests(unittest.TestCase):
    def test_axis_conversion(self):
        self.assertEqual(padmod.axis_to_u8(-32768), 0)
        self.assertEqual(padmod.axis_to_u8(0), 128)
        self.assertEqual(padmod.axis_to_u8(32767), 255)
        self.assertEqual(padmod.trigger_to_u8(0), 0)
        self.assertEqual(padmod.trigger_to_u8(32767), 255)
        self.assertEqual(padmod.trigger_to_u8(99999), 255)  # clamped

    def test_packed_struct_is_16_bytes(self):
        st = padmod.PadState(buttons=0x4010, lx=1, ly=2, rx=3, ry=4, l2=5, r2=6, connected=1)
        raw = padmod.pack_state(st, 1234)
        self.assertEqual(len(raw), 16)
        self.assertEqual(struct.unpack("<I8BI", raw), (0x4010, 1, 2, 3, 4, 5, 6, 1, 0, 1234))

    def test_button_bits_match_the_c_header(self):
        header = os.path.join(os.path.dirname(__file__), "..", "examples", "orb.h")
        with open(header) as f:
            text = f.read()
        for name, value in (("L3", 0x2), ("R3", 0x4), ("OPTIONS", 0x8), ("UP", 0x10),
                            ("RIGHT", 0x20), ("DOWN", 0x40), ("LEFT", 0x80), ("L2", 0x100),
                            ("R2", 0x200), ("L1", 0x400), ("R1", 0x800), ("TRIANGLE", 0x1000),
                            ("CIRCLE", 0x2000), ("CROSS", 0x4000), ("SQUARE", 0x8000),
                            ("TOUCHPAD", 0x100000)):
            self.assertIn(f"#define ORB_PAD_{name} {value:#x}", text)
            self.assertEqual(getattr(padmod, "BTN_" + name), value)
        self.assertIn("#define ORB_SYS_PAD 0x1002", text)

    def test_face_buttons_map_to_ps4_names(self):
        c = FakeController(buttons={"CONTROLLER_BUTTON_A", "CONTROLLER_BUTTON_Y",
                                    "CONTROLLER_BUTTON_DPAD_LEFT", "CONTROLLER_BUTTON_START"})
        pg, ctl = make_fake_pygame([c])
        state = padmod.PygamePad(pg, ctl).poll()
        self.assertEqual(state.connected, 1)
        self.assertEqual(state.buttons, padmod.BTN_CROSS | padmod.BTN_TRIANGLE
                         | padmod.BTN_LEFT | padmod.BTN_OPTIONS)

    def test_sticks_and_triggers(self):
        c = FakeController(axes={"CONTROLLER_AXIS_LEFTX": 32767, "CONTROLLER_AXIS_LEFTY": -32768,
                                 "CONTROLLER_AXIS_TRIGGERLEFT": 32767,
                                 "CONTROLLER_AXIS_TRIGGERRIGHT": 100})
        pg, ctl = make_fake_pygame([c])
        state = padmod.PygamePad(pg, ctl).poll()
        self.assertEqual((state.lx, state.ly, state.rx, state.ry), (255, 0, 128, 128))
        self.assertEqual((state.l2, state.r2), (255, 0))   # 100 >> 7 == 0
        self.assertEqual(state.buttons, padmod.BTN_L2)     # fully pressed trigger counts as L2

    def test_no_controller_means_neutral_state(self):
        pg, ctl = make_fake_pygame([])
        state = padmod.PygamePad(pg, ctl).poll()
        self.assertEqual((state.connected, state.buttons, state.lx, state.ly), (0, 0, 128, 128))

    def test_unplug_and_replug(self):
        c = FakeController(buttons={"CONTROLLER_BUTTON_B"})
        pg, ctl = make_fake_pygame([c])
        pad = padmod.PygamePad(pg, ctl)
        self.assertEqual(pad.poll().connected, 1)
        c.alive = False
        self.assertEqual(pad.poll().connected, 0)          # unplugged
        c.alive = True
        pad._last_scan = float("-inf")                     # skip the 1-second rescan delay
        self.assertEqual(pad.poll().connected, 1)          # found again

    def test_missing_pygame_gives_null_pad(self):
        self.assertEqual(padmod.NullPad().poll().connected, 0)

    def test_pad_syscall_writes_struct(self):
        cpu = FakeCpu()

        class OnePad:
            def poll(self):
                return padmod.PadState(buttons=padmod.BTN_CROSS, lx=200, connected=1)

            def close(self):
                self.closed = True

        pad = OnePad()
        k = Kernel(cpu, streams={}, pad_factory=lambda: pad)
        self.assertEqual(call(k, cpu, 0x1002, 0x7000), 0)
        buttons, lx, ly, rx, ry, l2, r2, connected, _res, ts = struct.unpack("<I8BI", cpu.read(0x7000, 16))
        self.assertEqual((buttons, lx, ly, connected), (0x4000, 200, 128, 1))
        k.shutdown()
        self.assertTrue(pad.closed)

    def test_pad_syscall_disabled(self):
        cpu = FakeCpu()
        k = Kernel(cpu, streams={})
        self.assertEqual(call(k, cpu, 0x1002, 0x7000), -19)

    def test_pad_is_created_lazily(self):
        created = []
        cpu = FakeCpu()
        k = Kernel(cpu, streams={}, pad_factory=lambda: created.append(1) or padmod.NullPad())
        self.assertEqual(created, [])
        call(k, cpu, 0x1002, 0x7000)
        call(k, cpu, 0x1002, 0x7000)
        self.assertEqual(created, [1])

    def test_pad_option(self):
        a = build_parser().parse_intermixed_args(["x.elf"])
        self.assertIsNotNone(make_pad_factory(a))
        a = build_parser().parse_intermixed_args(["x.elf", "--pad", "none"])
        self.assertIsNone(make_pad_factory(a))


EXAMPLES = os.path.join(os.path.dirname(__file__), "..", "examples")


def load_example(name):
    with open(os.path.join(EXAMPLES, name), "rb") as f:
        return f.read()


class DynamicLinkTests(unittest.TestCase):
    BASE = 0x40000000

    def setUp(self):
        self.data = load_example("dyn_hello.elf")
        self.image = parse_elf(self.data)

    def test_parses_dynamic_section(self):
        self.assertEqual(self.image.e_type, ET_DYN)
        self.assertEqual(self.image.dynamic.needed, ["libstub.so"])
        self.assertEqual([r.sym for r in self.image.dynamic.relocs],
                         ["orb_add", "printf", "puts", "malloc", "memset", "strlen"])
        self.assertTrue(all(r.rtype == 7 and not r.sym_defined for r in self.image.dynamic.relocs))

    def test_static_files_have_no_dynamic_info(self):
        self.assertIsNone(parse_elf(load_example("hello_libc.elf")).dynamic)

    def test_loads_at_base_address(self):
        cpu = FakeCpu()
        entry = load_image(self.image, self.data, cpu, self.BASE)
        self.assertEqual(entry, self.BASE + self.image.entry)
        self.assertTrue(all(addr >= self.BASE for addr, _, _ in cpu.maps))
        self.assertEqual(cpu.read(entry, 1), self.data[self.image.entry:self.image.entry + 1])

    def test_imports_are_pointed_at_stubs(self):
        cpu = FakeCpu()
        load_image(self.image, self.data, cpu, self.BASE)
        stubs = StubTable(cpu, make_default_registry())
        report = apply_relocations(self.image, self.BASE, cpu, stubs)
        self.assertEqual(report.missing, [])
        self.assertEqual(sorted(report.resolved), sorted(stubs.names))
        for r in self.image.dynamic.relocs:
            slot = struct.unpack("<Q", cpu.read(self.BASE + r.offset, 8))[0]
            self.assertEqual(slot, stubs.address_for(r.sym))
            self.assertEqual(cpu.read(slot, 3), b"\x49\x89\xca")  # mov r10, rcx

    def test_unimplemented_imports_are_reported_and_do_not_crash(self):
        cpu = FakeCpu()
        load_image(self.image, self.data, cpu, self.BASE)
        stubs = StubTable(cpu, HleRegistry())  # no functions at all
        report = apply_relocations(self.image, self.BASE, cpu, stubs)
        self.assertEqual(len(report.missing), 6)
        k = Kernel(cpu, streams={})
        k.stubs = stubs
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(call(k, cpu, HLE_SYSCALL_BASE, 1, 2), 0)
            call(k, cpu, HLE_SYSCALL_BASE, 1, 2)
        self.assertEqual(err.getvalue().count("unimplemented import orb_add"), 1)  # said once

    def test_relative_and_data_relocations(self):
        from orbemu.elf import DynamicInfo, ElfImage, Reloc
        cpu = FakeCpu()
        image = ElfImage(entry=0, dynamic=DynamicInfo(relocs=[
            Reloc(0x10, 8, None, False, 0, False, 0x500),            # RELATIVE: base + addend
            Reloc(0x18, 6, "own", True, 0x700, False, 0),            # GLOB_DAT to a symbol the file defines
            Reloc(0x20, 1, "own", True, 0x700, False, 8),            # 64: S + A
            Reloc(0x28, 6, "optional", False, 0, True, 0),           # weak and nobody provides it: NULL
            Reloc(0x30, 99, None, False, 0, False, 0),               # a type we do not know
        ]))
        stubs = StubTable(cpu, HleRegistry())
        report = apply_relocations(image, 0x1000, cpu, stubs)
        word = lambda off: struct.unpack("<Q", cpu.read(0x1000 + off, 8))[0]
        self.assertEqual((word(0x10), word(0x18), word(0x20), word(0x28)),
                         (0x1500, 0x1700, 0x1708, 0))
        self.assertEqual(report.unsupported, [99])

    def test_stack_gets_relocated_phdr_and_entry(self):
        cpu = FakeCpu()
        rsp = build_initial_stack(cpu, self.image, ["x"], random_bytes=b"R" * 16, base=self.BASE)
        words = struct.unpack("<19Q", cpu.read(rsp, 152))   # argc, argv[1], 2 NULLs, 7 auxv pairs.. (first 19 words)
        aux = dict(zip(words[4::2], words[5::2]))
        self.assertEqual(aux[3], self.BASE + self.image.phdr_addr)
        self.assertEqual(aux[9], self.BASE + self.image.entry)

    def test_stub_machine_code_runs_natively(self):
        """Linux/x86-64 only: run a real stub and check the rcx->r10 argument shuffle works."""
        if not (sys.platform.startswith("linux") and os.uname().machine == "x86_64"):
            self.skipTest("needs Linux on x86-64")
        code = bytearray(make_stub(0))
        code[4:8] = struct.pack("<I", 9)  # pretend the stub number is Linux's mmap
        try:
            buf = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        except OSError:
            self.skipTest("cannot create executable memory here")
        buf.write(bytes(code))
        fn = ctypes.CFUNCTYPE(ctypes.c_long, *[ctypes.c_long] * 6)(
            ctypes.addressof(ctypes.c_char.from_buffer(buf)))
        result = fn(0, 4096, 3, 0x22, -1, 0)  # mmap(0, 4096, RW, PRIVATE|ANON, -1, 0); flags are arg 4
        self.assertGreater(result, 4096)       # a real address, not -EINVAL


class HleLibcTests(unittest.TestCase):
    def fmt(self, text, *args, memory=None):
        cpu = FakeCpu()
        for addr, value in (memory or {}).items():
            cpu.write(addr, value + b"\x00")
        return format_printf(cpu, text.encode(), args)

    def test_integers(self):
        self.assertEqual(self.fmt("%d|%u|%x|%X", -5 & 0xFFFFFFFF, 7, 255, 255), b"-5|7|ff|FF")
        self.assertEqual(self.fmt("%ld", (-5) & (2**64 - 1)), b"-5")
        self.assertEqual(self.fmt("%lu", 2**40), str(2**40).encode())
        self.assertEqual(self.fmt("%d", 0xFFFFFFFF), b"-1")           # 32-bit by default
        self.assertEqual(self.fmt("%#x", 255), b"0xff")

    def test_width_and_flags(self):
        self.assertEqual(self.fmt("[%5d]", 42), b"[   42]")
        self.assertEqual(self.fmt("[%-5d]", 42), b"[42   ]")
        self.assertEqual(self.fmt("[%05d]", 42), b"[00042]")
        self.assertEqual(self.fmt("[%05d]", -42 & 0xFFFFFFFF), b"[-0042]")
        self.assertEqual(self.fmt("[%+d]", 3), b"[+3]")

    def test_strings_chars_percent(self):
        self.assertEqual(self.fmt("%s and %c 100%%", 0x100, ord("Z"), memory={0x100: b"text"}), b"text and Z 100%")
        self.assertEqual(self.fmt("%s", 0), b"(null)")
        self.assertEqual(self.fmt("[%6s]", 0x100, memory={0x100: b"ab"}), b"[    ab]")

    def test_missing_arguments_read_as_zero_and_unknown_conversions_pass_through(self):
        self.assertEqual(self.fmt("%d %d", 1), b"1 0")
        self.assertEqual(self.fmt("%q"), b"%q")
        self.assertEqual(self.fmt("trailing %"), b"trailing ")

    def test_simulated_dyn_hello_matches_the_native_output(self):
        """Replay dyn_hello.c's library calls through the real syscall path."""
        cpu = FakeCpu()
        out = io.BytesIO()
        k = Kernel(cpu, streams={1: out})
        stubs = StubTable(cpu, make_default_registry())
        k.stubs = stubs
        num = lambda name: (stubs.address_for(name), HLE_SYSCALL_BASE + stubs.names.index(name))[1]
        cpu.write(0x1000, b"Hello from a dynamically linked program!\x00")
        cpu.write(0x1100, b'orb_add(2, 3) = %d, strlen("orbemu") = %lu, %s, 0x%x, %c\n\x00')
        cpu.write(0x1200, b"orbemu\x00")
        cpu.write(0x1300, b"string\x00")
        cpu.write(0x1400, b"malloc+memset: %s\n\x00")
        call(k, cpu, num("puts"), 0x1000)
        total = call(k, cpu, num("orb_add"), 2, 3)
        length = call(k, cpu, num("strlen"), 0x1200)
        call(k, cpu, num("printf"), 0x1100, total, length, 0x1300, 255, ord("Z"))
        p = call(k, cpu, num("malloc"), 16)
        call(k, cpu, num("memset"), p, ord("A"), 15)
        cpu.write(p + 15, b"\x00")
        call(k, cpu, num("printf"), 0x1400, p)
        self.assertEqual(out.getvalue(), (
            b"Hello from a dynamically linked program!\n"
            b'orb_add(2, 3) = 5, strlen("orbemu") = 6, string, 0xff, Z\n'
            b"malloc+memset: AAAAAAAAAAAAAAA\n"))  # byte-for-byte what the native run printed
        self.assertEqual(p, 0x38000000)

    def test_malloc_alignment_and_exhaustion(self):
        cpu = FakeCpu()
        k = Kernel(cpu, streams={})
        malloc = make_default_registry().functions["malloc"]
        a, b = malloc(k, 1), malloc(k, 20)
        self.assertEqual((a % 16, b - a), (0, 16))
        self.assertEqual(malloc(k, 1 << 30), 0)  # too big: NULL


class RumbleController(FakeController):
    def __init__(self, floats=True, **kw):
        super().__init__(**kw)
        self.floats, self.calls, self.stopped = floats, [], 0

    def rumble(self, low, high, duration):
        is_float = isinstance(low, float)
        if is_float != self.floats:
            raise TypeError("wrong argument type")
        self.calls.append((low, high, duration))
        return True

    def stop_rumble(self):
        self.stopped += 1


class RumbleTests(unittest.TestCase):
    def pad_with(self, controller):
        pg, ctl = make_fake_pygame([controller])
        pad = padmod.PygamePad(pg, ctl)
        pad.poll()  # connects
        return pad

    def test_rumble_scales_to_0_1_floats(self):
        c = RumbleController(floats=True)
        self.assertTrue(self.pad_with(c).rumble(255, 0, 500))
        self.assertEqual(c.calls, [(1.0, 0.0, 500)])

    def test_rumble_falls_back_to_raw_integers(self):
        c = RumbleController(floats=False)
        self.assertTrue(self.pad_with(c).rumble(255, 128, 500))
        self.assertEqual(c.calls, [(65535, 128 * 257, 500)])

    def test_zero_duration_means_until_changed(self):
        c = RumbleController()
        self.pad_with(c).rumble(10, 10, 0)
        self.assertEqual(c.calls[0][2], 60000)

    def test_both_zero_stops(self):
        c = RumbleController()
        self.assertTrue(self.pad_with(c).rumble(0, 0, 0))
        self.assertEqual((c.stopped, c.calls), (1, []))

    def test_unsupported_or_missing_controller(self):
        self.assertFalse(self.pad_with(FakeController()).rumble(255, 255, 100))  # no rumble method
        pg, ctl = make_fake_pygame([])
        self.assertFalse(padmod.PygamePad(pg, ctl).rumble(255, 255, 100))        # nothing plugged in
        self.assertFalse(padmod.NullPad().rumble(255, 255, 100))

    def test_close_stops_vibration(self):
        c = RumbleController()
        pad = self.pad_with(c)
        pad.rumble(200, 200, 0)
        pad.close()
        self.assertEqual(c.stopped, 1)

    def test_rumble_syscall(self):
        class OnePad:
            def __init__(self):
                self.last, self.ok = None, True

            def poll(self):
                return padmod.PadState()

            def rumble(self, large, small, ms):
                self.last = (large, small, ms)
                return self.ok

            def close(self):
                pass

        pad, cpu = OnePad(), FakeCpu()
        k = Kernel(cpu, streams={}, pad_factory=lambda: pad)
        self.assertEqual(call(k, cpu, 0x1003, 255, 128, 250), 0)
        self.assertEqual(pad.last, (255, 128, 250))
        call(k, cpu, 0x1003, 9999, 9999, 10**9)                       # clamped
        self.assertEqual(pad.last, (255, 255, 60000))
        pad.ok = False
        self.assertEqual(call(k, cpu, 0x1003, 255, 255, 0), -19)      # cannot vibrate
        self.assertEqual(call(Kernel(cpu, streams={}), cpu, 0x1003, 1, 1, 1), -19)  # no pad support

    def test_guest_header_declares_rumble(self):
        with open(os.path.join(EXAMPLES, "orb.h")) as f:
            self.assertIn("#define ORB_SYS_PAD_RUMBLE 0x1003", f.read())


# NIDs taken from public PlayStation symbol tables (remembered by the author); all seven are reproduced
# by the algorithm in nid.py, which is what justifies trusting both.
KNOWN_NIDS = {"printf": "hcuQgD53UxM", "malloc": "gQX+4GDQjpM", "free": "tIhsqj0qsFE",
              "memcpy": "Q3VBxCXhUHs", "memset": "8zTFvBIAIN8", "strlen": "j4ViWNHEgww",
              "puts": "YQ0navp+YIc"}


class NidTests(unittest.TestCase):
    def test_known_nids(self):
        for name, nid in KNOWN_NIDS.items():
            self.assertEqual(nid_for(name), nid, name)

    def test_nid_shape(self):
        for name in ("a", "sceKernelUsleep", "x" * 200):
            nid = nid_for(name)
            self.assertEqual(len(nid), 11)
            self.assertRegex(nid, r"^[A-Za-z0-9+\-]{11}$")

    def test_split_import_name(self):
        self.assertEqual(split_import_name("hcuQgD53UxM#A#B"), ("hcuQgD53UxM", "A", "B"))
        self.assertEqual(split_import_name("printf"), ("printf", None, None))

    def test_registry_finds_functions_by_name_nid_and_full_import_name(self):
        r = make_default_registry()
        printf = r.functions["printf"]
        self.assertIs(r.lookup("hcuQgD53UxM"), printf)
        self.assertIs(r.lookup("hcuQgD53UxM#A#B"), printf)
        self.assertIs(r.lookup("printf"), printf)
        self.assertIsNone(r.lookup("notAFunction"))
        self.assertIsNone(r.lookup("AAAAAAAAAAA#A#B"))

    def test_functions_added_later_are_found_by_nid(self):
        r = HleRegistry()
        self.assertIsNone(r.lookup(nid_for("late")))
        r.function("late")(lambda k, *a: 7)
        self.assertEqual(r.lookup(nid_for("late"))(None), 7)

    def test_import_by_nid_links_and_runs(self):
        from orbemu.elf import DynamicInfo, ElfImage, Reloc
        cpu, out = FakeCpu(), io.BytesIO()
        image = ElfImage(entry=0, dynamic=DynamicInfo(relocs=[
            Reloc(0x10, 7, "hcuQgD53UxM#A#B", False, 0, False, 0),   # printf, the way a PS4 program names it
            Reloc(0x18, 7, "zzzzzzzzzzz#A#B", False, 0, False, 0)]))  # something we do not know
        stubs = StubTable(cpu, make_default_registry())
        report = apply_relocations(image, 0x1000, cpu, stubs)
        self.assertEqual((report.resolved, report.missing), (["hcuQgD53UxM#A#B"], ["zzzzzzzzzzz#A#B"]))
        k = Kernel(cpu, streams={1: out})
        k.stubs = stubs
        cpu.write(0x2000, b"n=%d\x00")
        call(k, cpu, HLE_SYSCALL_BASE + stubs.names.index("hcuQgD53UxM#A#B"), 0x2000, 42)
        self.assertEqual(out.getvalue(), b"n=42")

    def test_ps4_kernel_functions(self):
        r = make_default_registry()
        k = Kernel(FakeCpu(), streams={})
        self.assertEqual(r.lookup(nid_for("sceKernelUsleep"))(k, 1000), 0)
        t1 = r.lookup("sceKernelGetProcessTime")(k)
        c1 = r.lookup("sceKernelGetProcessTimeCounter")(k)
        r.lookup("sceKernelUsleep")(k, 2000)
        self.assertGreater(r.lookup("sceKernelGetProcessTime")(k), t1)
        self.assertGreater(r.lookup("sceKernelGetProcessTimeCounter")(k), c1)
        self.assertEqual(r.lookup("sceKernelGetProcessTimeCounterFrequency")(k), 10**9)


def build_fake_self(elf, encrypt_segment=None):
    """Wrap an ELF in a SELF container laid out as the public documentation describes
    (used to test describe.py's reading of that layout; real files still need checking)."""
    ehdr, phdrs = read_phdrs(elf)
    segs = [ph for ph in phdrs if ph["filesz"]]
    head_len = ehdr["phoff"] + ehdr["phnum"] * ehdr["phentsize"]
    elf_off = 0x20 + 0x20 * len(segs)
    pos = (elf_off + head_len + 15) & ~15
    entries, blobs = [], []
    for ph in segs:
        props = (ph["index"] << 20) | (0x2 if ph["index"] == encrypt_segment else 0)
        entries.append(struct.pack("<QQQQ", props, pos, ph["filesz"], ph["memsz"]))
        blobs.append(elf[ph["offset"]:ph["offset"] + ph["filesz"]])
        pos = (pos + ph["filesz"] + 15) & ~15
    out = bytearray(b"\x4f\x15\x3d\x1d" + bytes([0, 1, 1, 18]) +
                    struct.pack("<IHHQHH", 0x101, elf_off + head_len, 0, pos, len(segs), 0x22) + bytes(4))
    out += b"".join(entries)
    out += elf[:head_len]
    for entry, blob in zip(entries, blobs):
        offset = struct.unpack_from("<Q", entry, 8)[0]
        out += bytes(offset - len(out)) + blob
    return bytes(out)


class DescribeTests(unittest.TestCase):
    def test_describes_an_ordinary_elf(self):
        text = "\n".join(describe(load_example("dyn_hello.elf")))
        self.assertIn("type=0x3 DYN", text)
        self.assertIn("NEEDED", text)
        self.assertIn("LOAD", text)
        self.assertIn("(none: this does not look like a PlayStation-style file)", text)

    def test_sony_segment_types_exclude_gnu_ones(self):
        for t in (0x61000000, 0x61000001, 0x61000002, 0x61000010, 0x6FFFFF00, 0x6FFFFF01):
            self.assertTrue(is_sony_segment(t), hex(t))
        for t in (1, 2, 0x6474E550, 0x6474E551, 0x6474E552, 0x6474E553):
            self.assertFalse(is_sony_segment(t), hex(t))

    def test_self_round_trip(self):
        elf = load_example("hello_libc.elf")
        wrapped = build_fake_self(elf)
        header, entries = parse_self(wrapped)
        self.assertEqual(header["num_entries"], len(entries))
        unwrapped, _notes = unwrap_self(wrapped)
        for ph in read_phdrs(elf)[1]:
            self.assertEqual(unwrapped[ph["offset"]:ph["offset"] + ph["filesz"]],
                             elf[ph["offset"]:ph["offset"] + ph["filesz"]])
        parse_elf(unwrapped)  # and orbemu's own loader accepts the result
        text = "\n".join(describe(wrapped))
        self.assertIn("SELF container", text)
        self.assertIn("can be unwrapped", text)

    def test_encrypted_segments_are_refused_not_decrypted(self):
        wrapped = build_fake_self(load_example("hello_libc.elf"), encrypt_segment=1)
        with self.assertRaisesRegex(DescribeError, "encrypted"):
            unwrap_self(wrapped)
        self.assertIn("cannot unwrap", "\n".join(describe(wrapped)))

    def test_rejects_non_self(self):
        with self.assertRaises(DescribeError):
            parse_self(b"definitely not a self file" * 4)

    def test_hexdump(self):
        lines = hexdump(b"ABC\x00" * 8, 20)
        self.assertEqual(len(lines), 2)
        self.assertIn("41 42 43 00", lines[0])
        self.assertTrue(lines[0].endswith("ABC.ABC.ABC.ABC."))


def build_sony_elf(plain):
    """Convert an ordinary dynamic ELF into the PlayStation layout: type 0xFE10, symbol/string/
    relocation tables inside an SCE_DYNLIBDATA segment, NID-style symbol names, and Sony dynamic
    tags whose values are offsets into that segment. The structure follows a real OpenOrbis build
    (where every table offset and size was checked to line up); this is only a test fixture."""
    img = parse_elf(plain)
    _ehdr, phdrs = read_phdrs(plain)
    loads = [ph for ph in phdrs if ph["type"] == 1]
    relocs = img.dynamic.relocs
    imports = list(dict.fromkeys(r.sym for r in relocs))
    strtab = bytearray(b"\0libkernel.prx\0libkernel\0hello_world\0.\\x64\\Debug\\hello_world.elf\0")
    name_off = {}
    for name in imports:
        name_off[name] = len(strtab)
        strtab += (nid_for(name) + "#A#B").encode() + b"\0"
    blob = bytearray(b"OPENORBIS-HOMEBREW\0".ljust(0x18, b"\0"))
    str_off = len(blob)
    blob += strtab
    while len(blob) % 8:
        blob.append(0)
    sym_off = len(blob)
    symtab = bytes(24) + b"".join(struct.pack("<IBBHQQ", name_off[n], 0x12, 0, 0, 0, 0) for n in imports)
    blob += symtab
    jmprel_off = len(blob)
    jmprel = b"".join(struct.pack("<QQq", r.offset, ((imports.index(r.sym) + 1) << 32) | r.rtype, 0)
                      for r in relocs)
    blob += jmprel
    rela_off = hash_off = len(blob)
    blob += bytes(16)
    dyn_off = len(blob)
    tags = [(DT_SCE["HASH"], hash_off), (DT_SCE["HASHSZ"], 16), (DT_SCE["STRTAB"], str_off),
            (DT_SCE["STRSIZE"], len(strtab)), (DT_SCE["SYMTAB"], sym_off),
            (DT_SCE["SYMTABSZ"], len(symtab)), (DT_SCE["SYMENT"], 24), (DT_SCE["RELA"], rela_off),
            (DT_SCE["RELASZ"], 0), (DT_SCE["RELAENT"], 24), (DT_SCE["JMPREL"], jmprel_off),
            (DT_SCE["PLTRELSZ"], len(jmprel)), (DT_SCE["PLTREL"], 7), (DT_SCE["FINGERPRINT"], 0),
            (DT_SCE["ORIGINAL_FILENAME"], 37), (DT_SCE["MODULE_INFO"], 0x0000010100000019),
            (DT_SCE["NEEDED_MODULE"], 0x000101010000000F), (DT_SCE["IMPORT_LIB"], 0x000100010000000F),
            (0, 0)]
    dyn = b"".join(struct.pack("<QQ", t, v) for t, v in tags)
    blob += dyn
    out = bytearray(plain)
    while len(out) % 16:
        out.append(0)
    lib_file = len(out)
    out += blob
    while len(out) % 8:
        out.append(0)
    phoff = len(out)

    def phdr(kind, flags, off, vaddr, filesz, memsz, align):
        return struct.pack("<IIQQQQQQ", kind, flags, off, vaddr, vaddr, filesz, memsz, align)

    table = b"".join(phdr(p["type"], p["flags"], p["offset"], p["vaddr"], p["filesz"], p["memsz"],
                          p["align"]) for p in loads)
    table += phdr(2, 6, lib_file + dyn_off, lib_file + dyn_off, len(dyn), len(dyn), 8)
    table += phdr(0x61000000, 4, lib_file, 0, len(blob), 0, 16)
    out += table
    struct.pack_into("<H", out, 16, 0xFE10)          # e_type: SCE_DYNEXEC
    struct.pack_into("<Q", out, 32, phoff)           # e_phoff
    struct.pack_into("<H", out, 56, len(loads) + 2)  # e_phnum
    return bytes(out)


class SonyFormatTests(unittest.TestCase):
    def setUp(self):
        self.plain = load_example("dyn_hello.elf")
        self.sony = build_sony_elf(self.plain)

    def test_sony_layout_gives_the_same_relocations_as_the_plain_layout(self):
        a, b = parse_elf(self.plain), parse_elf(self.sony)
        self.assertTrue(b.sony and not a.sony)
        self.assertEqual(b.e_type, 0xFE10)
        self.assertTrue(b.position_independent)
        self.assertEqual(b.module_name, "hello_world")
        self.assertEqual(b.dynamic.needed, ["libkernel"])
        self.assertEqual(b.segments, a.segments)
        self.assertEqual([(r.offset, r.rtype, r.addend) for r in b.dynamic.relocs],
                         [(r.offset, r.rtype, r.addend) for r in a.dynamic.relocs])
        self.assertEqual([r.sym for r in b.dynamic.relocs],
                         [nid_for(r.sym) + "#A#B" for r in a.dynamic.relocs])

    def test_nid_imports_reach_the_same_python_functions(self):
        cpu, image = FakeCpu(), parse_elf(self.sony)
        load_image(image, self.sony, cpu, 0x40000000)
        stubs = StubTable(cpu, make_default_registry())
        report = apply_relocations(image, 0x40000000, cpu, stubs)
        self.assertEqual((len(report.resolved), report.missing), (6, []))
        out = io.BytesIO()
        k = Kernel(cpu, streams={1: out})
        k.stubs = stubs
        cpu.write(0x2000, b"hi %d\x00")
        name = nid_for("printf") + "#A#B"
        call(k, cpu, HLE_SYSCALL_BASE + stubs.names.index(name), 0x2000, 7)
        self.assertEqual(out.getvalue(), b"hi 7")

    def test_describe_understands_sony_files(self):
        text = "\n".join(describe(self.sony))
        for expected in ("PlayStation-style dynamic data: yes", "SCE_STRTAB", "SCE_DYNLIBDATA",
                         "[python]", "imports: 6", "SCE_DYNEXEC (Sony)"):
            self.assertIn(expected, text)
        self.assertNotIn("MISSING", text)

    def test_unimplemented_import_is_marked_missing(self):
        from orbemu.hle import HleRegistry as Reg
        registry = Reg()
        registry.function("puts")(lambda k, *a: 0)
        cpu, image = FakeCpu(), parse_elf(self.sony)
        load_image(image, self.sony, cpu, 0x40000000)
        report = apply_relocations(image, 0x40000000, cpu, StubTable(cpu, registry))
        self.assertEqual(len(report.resolved), 1)
        self.assertEqual(len(report.missing), 5)

    def test_describe_does_not_crash_when_a_self_cannot_be_unwrapped(self):
        wrapped = build_fake_self(load_example("dyn_hello.elf"), encrypt_segment=1)
        text = "\n".join(describe(wrapped))
        self.assertIn("cannot unwrap", text)
        self.assertIn("segment contents are not shown", text)
        self.assertIn("LOAD", text)  # the embedded ELF header was still readable

    def test_position_independence_by_type(self):
        self.assertFalse(parse_elf(load_example("hello_libc.elf")).position_independent)
        self.assertTrue(parse_elf(self.plain).position_independent)
        self.assertTrue(parse_elf(self.sony).position_independent)


class TlsTests(unittest.TestCase):
    def test_block_layout(self):
        cpu, base = FakeCpu(), 0x40000000
        cpu.write(base + 0x100, b"\x11\x22\x33\x44")           # the initial values live in the file
        tp = setup_tls(cpu, ElfImage(entry=0, tls=(0x100, 4, 24, 8)), base)
        self.assertEqual(tp % 16, 0)
        self.assertEqual(cpu.regs["fs_base"], tp)
        self.assertEqual(struct.unpack("<Q", cpu.read(tp, 8))[0], tp)          # %fs:0 points at itself
        self.assertEqual(struct.unpack("<Q", cpu.read(tp + 0x10, 8))[0], tp)   # and so does %fs:0x10
        self.assertEqual(cpu.read(tp - 32, 4), b"\x11\x22\x33\x44")           # 24 bytes rounded up to 32
        self.assertEqual(cpu.maps[-1][0], 0x3C000000)

    def test_no_tls_segment(self):
        self.assertIsNone(setup_tls(FakeCpu(), ElfImage(entry=0), 0))

    def test_tls_segment_is_parsed_from_real_files(self):
        tls = parse_elf(load_example("hello_libc.elf")).tls
        self.assertIsNotNone(tls)
        self.assertEqual(len(tls), 4)
        self.assertIsNone(parse_elf(load_example("dyn_hello.elf")).tls)


# Imports of a real OpenOrbis hello-world build (hello_world.elf has the names, hello_world.oelf the
# NIDs). The two lists describe the same program, so they check the NID algorithm against real data.
REAL_ELF_IMPORT_NAMES = """sysconf open ioctl sigprocmask fstat nanosleep _write sigaction _exit pthread_cond_broadcast
pthread_rwlock_wrlock pthread_cond_destroy pthread_rwlock_rdlock pthread_setspecific pthread_equal
pthread_mutex_unlock pthread_cond_timedwait poll pthread_rwlock_unlock pthread_detach pthread_mutexattr_init
pthread_mutex_lock munmap pthread_mutex_destroy pthread_mutex_trylock mmap sched_yield pthread_join
pthread_getspecific pthread_mutexattr_destroy pthread_self close pthread_mutexattr_settype pthread_key_create
pthread_mutex_init madvise _writev lseek __error pthread_once pthread_cond_wait raise pthread_cond_signal
sceKernelUsleep""".split()
REAL_OELF_IMPORT_NIDS = """mkawd0NA9ts wuCroIGjt2g PfccT7qURYE aPcyptbOiZs mqQMh1zPPT8 yS8U2TGCe1A FxVZqBAA7ks KiJEPEWRyUY
6Z83sYWFlA8 mkx2fVhNMsg sIlRvQqsN2Y RXXqi4CtF8w iGjsr1WAtI0 WrOLvHU0yQM 7Xl257M4VNI 2Z+PpY6CaJg 27bAgiJmOh0
ku7D4q1Y9PI EgmLo6EWgso +U1R4WtXvoc dQHWEsJtoE4 7H0iTOciTLo UqDGjXA5yUM ltCfaGr2JGE 1jfXLRVzisc K-jXhbt2gn4
BPE9s9vQQXo 6XG4B33N09g h9CcP3J0oVM 0-KXaS70xy4 HF7lK46xzjY EotR8a3ASf4 bY-PO6JhzhQ mDmgMOGVUqg mqULNdimTn0
ttHNfU+qDBU Jahsnh4KKkg YSHRBRLn2pI Oy6IpwgtYOk 9BcDykPmo1I Z4QosVuAsA0 Op8TBGY5KHg 0t0-MxQNwK4 2MOy+rUfuhQ""".split()


class RealBuildTests(unittest.TestCase):
    def test_nids_in_the_real_oelf_are_the_hashes_of_the_real_elf_names(self):
        self.assertEqual((len(REAL_ELF_IMPORT_NAMES), len(REAL_OELF_IMPORT_NIDS)), (44, 44))
        self.assertEqual(set(REAL_OELF_IMPORT_NIDS), {nid_for(n) for n in REAL_ELF_IMPORT_NAMES})

    def test_every_import_of_that_program_has_a_python_answer(self):
        r = make_default_registry()
        self.assertEqual([n for n in REAL_ELF_IMPORT_NAMES if not r.has(n)], [])
        self.assertEqual([n for n in REAL_OELF_IMPORT_NIDS if not r.has(n + "#B#B")], [])

    def test_the_two_imports_the_first_real_run_stopped_on(self):
        self.assertEqual(name_for("7H0iTOciTLo#B#B"), "pthread_mutex_lock")
        self.assertEqual(name_for("9BcDykPmo1I#B#B"), "__error")

    def test_names_and_pretty_printing(self):
        self.assertEqual(name_for("printf"), "printf")                 # plain names pass through
        self.assertIsNone(name_for("zzzzzzzzzzz#B#B"))
        self.assertEqual(pretty("7H0iTOciTLo#B#B"), "pthread_mutex_lock [7H0iTOciTLo]")
        self.assertEqual(pretty("zzzzzzzzzzz#B#B"), "zzzzzzzzzzz#B#B")
        self.assertEqual(pretty("puts"), "puts")


class NativeStubTests(unittest.TestCase):
    def test_native_and_syscall_stubs_share_the_table_without_overlap(self):
        r = HleRegistry()
        r.function("plain")(lambda k, *a: 1)
        r.native_function("fast", bytes(range(1, 25)))     # 24 bytes: needs two 16-byte slots
        r.function("plain2")(lambda k, *a: 2)
        cpu = FakeCpu()
        stubs = StubTable(cpu, r)
        a, b, c = (stubs.address_for(n) for n in ("plain", "fast", "plain2"))
        self.assertEqual([a % 16, b % 16, c % 16], [0, 0, 0])
        self.assertEqual((b - a, c - b), (16, 32))
        self.assertEqual(cpu.read(b, 24), bytes(range(1, 25)))
        self.assertEqual(stubs.names, ["plain", "plain2"])           # only syscall-style stubs are numbered
        self.assertEqual(struct.unpack("<I", cpu.read(c + 4, 4))[0], HLE_SYSCALL_BASE + 1)

    def test_native_functions_are_found_by_nid_too(self):
        r = make_default_registry()
        self.assertTrue(r.has(nid_for("pthread_once") + "#B#B"))
        self.assertEqual(r.native_code("pthread_once"), PTHREAD_ONCE)
        self.assertIsNone(r.lookup("pthread_once"))      # no Python body: it is machine code

    def test_pthread_once_machine_code_runs_natively(self):
        """Linux/x86-64 only: run the stub for real. The init routine must run exactly once, and the
        stack must be 16-byte aligned when it is called (ctypes would misbehave otherwise)."""
        if not (sys.platform.startswith("linux") and os.uname().machine == "x86_64"):
            self.skipTest("needs Linux on x86-64")
        try:
            buf = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        except OSError:
            self.skipTest("cannot create executable memory here")
        buf.write(PTHREAD_ONCE)
        once = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)(
            ctypes.addressof(ctypes.c_char.from_buffer(buf)))
        calls, alignment = [], []

        @ctypes.CFUNCTYPE(None)
        def init_routine():
            calls.append(1)

        state = ctypes.c_int(0)
        routine = ctypes.cast(init_routine, ctypes.c_void_p).value
        self.assertEqual(once(ctypes.addressof(state), routine), 0)
        self.assertEqual(once(ctypes.addressof(state), routine), 0)
        self.assertEqual((len(calls), state.value), (1, 1))


class PosixTests(unittest.TestCase):
    def setUp(self):
        self.cpu, self.out = FakeCpu(), io.BytesIO()
        self.k = Kernel(self.cpu, streams={1: self.out})
        self.r = make_default_registry()

    def f(self, name, *args):
        return self.r.functions[name](self.k, *args)

    def errno(self):
        return struct.unpack("<I", self.cpu.read(errno_address(self.k), 4))[0]

    def test_error_returns_a_stable_pointer_to_errno(self):
        a = self.f("__error")
        self.assertNotEqual(a, 0)                  # the bug the first real run hit: NULL here crashed the program
        self.assertEqual(self.f("__error"), a)
        self.assertEqual(self.f("fstat", 1, 0x1000), -1)
        self.assertEqual(self.errno(), 9)

    def test_locks_and_condition_variables_succeed(self):
        for name in ("pthread_mutex_init", "pthread_mutex_lock", "pthread_mutex_unlock", "pthread_cond_wait",
                     "pthread_rwlock_rdlock", "pthread_mutexattr_settype", "sched_yield", "madvise", "raise", "poll"):
            self.assertEqual(self.f(name, 0x1000, 0, 0), 0, name)

    def test_thread_identity(self):
        me = self.f("pthread_self")
        self.assertNotEqual(me, 0)
        self.assertEqual(self.f("pthread_self"), me)
        self.assertEqual((self.f("pthread_equal", me, me), self.f("pthread_equal", me, me + 1)), (1, 0))

    def test_thread_specific_keys(self):
        self.f("pthread_key_create", 0x2000, 0)
        self.f("pthread_key_create", 0x2010, 0)
        k0, k1 = (struct.unpack("<I", self.cpu.read(a, 4))[0] for a in (0x2000, 0x2010))
        self.assertEqual((k0, k1), (0, 1))
        self.f("pthread_setspecific", k1, 0xABCD)
        self.assertEqual((self.f("pthread_getspecific", k0), self.f("pthread_getspecific", k1)), (0, 0xABCD))

    def test_sysconf(self):
        self.assertEqual(self.f("sysconf", 47), 16384)       # the PlayStation page size
        self.assertEqual(self.f("sysconf", 9999), -1)
        self.assertEqual(self.errno(), 22)

    def test_mmap_is_16k_aligned_and_munmap_releases(self):
        first = self.f("mmap", 0, 100, 3, 0x1002, -1, 0)
        second = self.f("mmap", 0, 0x5000, 3, 0x1002, -1, 0)
        self.assertEqual((first % 0x4000, second % 0x4000), (0, 0))
        self.assertEqual(self.cpu.maps[-2:], [(first, 0x4000, 3), (second, 0x8000, 3)])
        self.assertGreaterEqual(second, first + 0x4000)
        self.assertEqual(self.f("munmap", first, 0x4000), 0)
        self.assertEqual(self.cpu.unmaps, [(first, 0x4000)])

    def test_file_backed_mmap_is_refused(self):
        self.assertEqual(self.f("mmap", 0, 4096, 1, 0x0002, 3, 0), -1)   # no MAP_ANON
        self.assertEqual(self.errno(), 78)                               # FreeBSD's ENOSYS

    def test_write_and_writev_reach_stdout(self):
        self.cpu.write(0x1000, b"hello ")
        self.cpu.write(0x1100, b"world")
        self.assertEqual(self.f("_write", 1, 0x1000, 6), 6)
        self.cpu.write(0x2000, struct.pack("<QQ", 0x1100, 5))
        self.assertEqual(self.f("_writev", 1, 0x2000, 1), 5)
        self.assertEqual(self.out.getvalue(), b"hello world")
        self.assertEqual(self.f("_write", 9, 0x1000, 6), -1)
        self.assertEqual(self.errno(), 9)

    def test_ioctl_says_stdout_is_a_terminal_so_output_is_line_buffered(self):
        self.assertEqual(self.f("ioctl", 1, 0x402C7413, 0x3000), 0)
        self.assertEqual(self.cpu.read(0x3000, 44), bytes(44))
        self.assertEqual(self.f("ioctl", 5, 0x402C7413, 0x3000), -1)
        self.assertEqual(self.errno(), 25)
        self.assertEqual(self.f("ioctl", 1, 0x1234, 0x3000), -1)

    def test_signals_are_accepted_and_report_empty_state(self):
        self.cpu.write(0x4000, b"\xff" * 32)
        self.assertEqual(self.f("sigaction", 2, 0, 0x4000), 0)
        self.assertEqual(self.cpu.read(0x4000, 32), bytes(32))
        self.cpu.write(0x4100, b"\xff" * 16)
        self.assertEqual(self.f("sigprocmask", 0, 0, 0x4100), 0)
        self.assertEqual(self.cpu.read(0x4100, 16), bytes(16))

    def test_files_through_the_c_convention(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "a.txt"), "wb") as fh:
                fh.write(b"0123456789")
            self.k.root = root
            self.cpu.write(0x1000, b"a.txt\x00")
            self.cpu.write(0x1100, b"missing.txt\x00")
            fd = self.f("open", 0x1000, 0, 0)
            self.assertEqual(fd, 3)
            self.assertEqual(self.f("lseek", fd, 4, 0), 4)
            self.assertEqual(self.f("close", fd), 0)
            self.assertEqual(self.f("close", fd), -1)
            self.assertEqual(self.errno(), 9)
            self.assertEqual(self.f("open", 0x1100, 0, 0), -1)
            self.assertEqual(self.errno(), 2)

    def test_nanosleep_and_exit(self):
        self.cpu.write(0x1000, struct.pack("<qq", 0, 1000))
        self.assertEqual(self.f("nanosleep", 0x1000, 0), 0)
        self.f("_exit", 7)
        self.assertEqual((self.k.exit_code, self.cpu.stopped), (7, True))

    def test_calls_made_through_stubs_are_remembered_for_crash_reports(self):
        stubs = StubTable(self.cpu, self.r)
        self.k.stubs = stubs
        for name in ("__error", "pthread_mutex_lock", "7H0iTOciTLo#B#B"):
            stubs.address_for(name)
        call(self.k, self.cpu, HLE_SYSCALL_BASE + stubs.names.index("pthread_mutex_lock"), 0x1000)
        call(self.k, self.cpu, HLE_SYSCALL_BASE + stubs.names.index("7H0iTOciTLo#B#B"), 0x1000)
        self.assertEqual(list(stubs.recent), ["pthread_mutex_lock", "pthread_mutex_lock"])
        err = io.StringIO()
        stubs.trace = True
        with contextlib.redirect_stderr(err):
            call(self.k, self.cpu, HLE_SYSCALL_BASE + stubs.names.index("__error"))
        self.assertIn("[hle] __error(", err.getvalue())


class FakePad:
    def __init__(self, **state):
        self.state, self.rumbles = padmod.PadState(**state), []

    def poll(self):
        return self.state

    def rumble(self, large, small, ms):
        self.rumbles.append((large, small, ms))
        return True

    def close(self):
        pass


class PlayStationPadTests(unittest.TestCase):
    def make(self, pad=None):
        cpu = FakeCpu()
        k = Kernel(cpu, streams={1: io.BytesIO()}, pad_factory=(lambda: pad) if pad else None)
        return cpu, k, make_default_registry()

    def test_struct_layout_matches_the_compiled_header(self):
        # computed by compiling OrbisPadData / OrbisPadInformation from the OpenOrbis headers
        self.assertEqual((hle_ps4.PAD_DATA_SIZE, hle_ps4.PAD_INFO_SIZE), (120, 28))
        self.assertEqual((hle_ps4.PAD_OFF_BUTTONS, hle_ps4.PAD_OFF_STICKS, hle_ps4.PAD_OFF_TRIGGERS), (0, 4, 8))
        self.assertEqual((hle_ps4.PAD_OFF_QUAT, hle_ps4.PAD_OFF_CONNECTED, hle_ps4.PAD_OFF_TIMESTAMP), (12, 76, 80))

    def test_read_state_fills_the_structure(self):
        pad = FakePad(buttons=0x4010, lx=10, ly=20, rx=30, ry=40, l2=50, r2=60, connected=1)
        cpu, k, r = self.make(pad)
        self.assertEqual(r.functions["scePadReadState"](k, 1, 0x5000), 0)
        raw = cpu.read(0x5000, 120)
        self.assertEqual(struct.unpack_from("<I", raw, 0)[0], 0x4010)
        self.assertEqual(tuple(raw[4:10]), (10, 20, 30, 40, 50, 60))
        self.assertEqual(struct.unpack_from("<4f", raw, 12), (0.0, 0.0, 0.0, 1.0))
        self.assertEqual(raw[76], 1)
        self.assertGreaterEqual(struct.unpack_from("<Q", raw, 80)[0], 0)

    def test_read_returns_one_sample(self):
        cpu, k, r = self.make(FakePad(connected=1))
        self.assertEqual(r.functions["scePadRead"](k, 1, 0x5000, 4), 1)
        self.assertEqual(r.functions["scePadRead"](k, 1, 0x5000, 0), 0)

    def test_without_controller_support_the_pad_reads_as_disconnected(self):
        cpu, k, r = self.make(None)
        r.functions["scePadReadState"](k, 1, 0x5000)
        raw = cpu.read(0x5000, 120)
        self.assertEqual((raw[76], tuple(raw[4:8])), (0, (128, 128, 128, 128)))

    def test_vibration_reaches_the_controller(self):
        pad = FakePad(connected=1)
        cpu, k, r = self.make(pad)
        cpu.write(0x6000, bytes([200, 90]))               # OrbisPadVibeParam { lgMotor, smMotor }
        self.assertEqual(r.functions["scePadSetVibration"](k, 1, 0x6000), 0)
        self.assertEqual(pad.rumbles, [(200, 90, 0)])

    def test_handles_and_setup_calls(self):
        cpu, k, r = self.make(FakePad())
        self.assertEqual(r.functions["scePadInit"](k), 0)
        self.assertEqual(r.functions["scePadOpen"](k, 1, 0, 0, 0), hle_ps4.PAD_HANDLE)
        self.assertEqual(r.functions["scePadGetHandle"](k, 1, 0, 0), hle_ps4.PAD_HANDLE)
        self.assertEqual(r.functions["scePadClose"](k, 1), 0)

    def test_controller_information(self):
        cpu, k, r = self.make(FakePad(connected=1))
        r.functions["scePadGetControllerInformation"](k, 1, 0x7000)
        raw = cpu.read(0x7000, 28)
        self.assertEqual(struct.unpack_from("<HH", raw, 4), (1920, 942))
        self.assertEqual(struct.unpack_from("<ii", raw, 12), (1, 0))   # connected, deviceClass = pad

    def test_user_service_and_debug_text(self):
        cpu, k, r = self.make(None)
        self.assertEqual(r.functions["sceUserServiceInitialize"](k, 0), 0)
        r.functions["sceUserServiceGetInitialUser"](k, 0x8000)
        self.assertEqual(struct.unpack("<i", cpu.read(0x8000, 4))[0], hle_ps4.USER_ID)
        cpu.write(0x9000, b"debug text\x00")
        r.functions["sceKernelDebugOutText"](k, 0, 0x9000)
        self.assertEqual(k.streams[1].getvalue(), b"debug text")

    def test_pad_functions_are_found_by_nid(self):
        r = make_default_registry()
        for name in ("scePadReadState", "scePadSetVibration", "sceUserServiceInitialize"):
            self.assertTrue(r.has(nid_for(name) + "#B#B"), name)


class DiagnosticsTests(unittest.TestCase):
    def test_fault_description(self):
        self.assertEqual(format_fault(20, 0, 4), "write to unmapped memory (4 bytes) at address 0x0")
        self.assertIn("instruction fetch", format_fault(21, 0x1234, 1))
        self.assertIn("read-only", format_fault(22, 0x40000000, 8))
        self.assertIn("bad memory access", format_fault(99, 0, 1))

    def test_register_layout(self):
        lines = format_registers([("rax", 1), ("rbx", 2), ("rcx", 3)])
        self.assertEqual(len(lines), 2)
        self.assertIn("rax=0x0000000000000001", lines[0])
        self.assertIn("rbx=0x0000000000000002", lines[0])
        self.assertIn("rcx=0x0000000000000003", lines[1])


def build_ps4_style_self(elf):
    """A SELF laid out like a real OpenOrbis eboot.bin: for every segment that has data of its own, a
    small metadata entry (odd id, so ids collide with real segment indexes) followed by the data entry
    (flag 0x800, id = segment index); segments lying inside another one get no entry."""
    ehdr, phdrs = read_phdrs(elf)

    def inside_another(ph):
        return any(o is not ph and o["filesz"] and o["offset"] <= ph["offset"]
                   and ph["offset"] + ph["filesz"] <= o["offset"] + o["filesz"]
                   and (o["offset"], o["filesz"]) != (ph["offset"], ph["filesz"]) for o in phdrs)

    owners = [ph for ph in phdrs if ph["filesz"] and not inside_another(ph)]
    head_len = ehdr["phoff"] + ehdr["phnum"] * ehdr["phentsize"]
    elf_off = 0x20 + 0x20 * 2 * len(owners)
    pos = (elf_off + head_len + 15) & ~15
    entries, blobs = [], []
    for k, ph in enumerate(owners):
        entries.append(struct.pack("<QQQQ", ((2 * k + 1) << 20) | 0x4, pos, 0x20, 0x20))  # metadata
        blobs.append((pos, bytes(0x20)))
        pos += 0x20
        entries.append(struct.pack("<QQQQ", (ph["index"] << 20) | 0x2804, pos, ph["filesz"], ph["memsz"]))
        blobs.append((pos, elf[ph["offset"]:ph["offset"] + ph["filesz"]]))
        pos = (pos + ph["filesz"] + 15) & ~15
    out = bytearray(b"\x4f\x15\x3d\x1d" + bytes([0, 1, 1, 18]) +
                    struct.pack("<IHHQHH", 0x101, elf_off + head_len, 0, pos, len(entries), 0x22) + bytes(4))
    out += b"".join(entries)
    out += elf[:head_len]
    for offset, blob in blobs:
        out += bytes(offset - len(out)) + blob
    return bytes(out)


class RealStyleSelfTests(unittest.TestCase):
    def setUp(self):
        self.sony = build_sony_elf(load_example("dyn_hello.elf"))
        self.wrapped = build_ps4_style_self(self.sony)

    def test_unwraps_a_self_laid_out_like_the_real_one(self):
        unwrapped, notes = unwrap_self(self.wrapped)
        _ehdr, phdrs = read_phdrs(self.sony)
        for ph in phdrs:
            self.assertEqual(unwrapped[ph["offset"]:ph["offset"] + ph["filesz"]],
                             self.sony[ph["offset"]:ph["offset"] + ph["filesz"]], f"segment {ph['index']}")
        self.assertTrue(any("lies inside another segment" in n for n in notes))   # the DYNAMIC segment
        image = parse_elf(unwrapped)                                              # and the result loads
        self.assertTrue(image.sony)
        self.assertEqual([r.sym for r in image.dynamic.relocs],
                         [r.sym for r in parse_elf(self.sony).dynamic.relocs])

    def test_metadata_entries_with_colliding_ids_are_not_mistaken_for_data(self):
        _header, entries = parse_self(self.wrapped)
        ids = [e["id"] for e in entries]
        self.assertTrue(len(ids) != len(set(ids)), "the fixture must contain colliding ids")
        unwrapped, _ = unwrap_self(self.wrapped)
        self.assertEqual(parse_elf(unwrapped).segments, parse_elf(self.sony).segments)

    def test_describe_reports_that_it_can_unwrap_and_shows_the_program(self):
        text = "\n".join(describe(self.wrapped))
        self.assertIn("all segments are plain: can be unwrapped", text)
        self.assertIn("SCE_DYNEXEC (Sony)", text)
        self.assertIn("imports: 6", text)
        self.assertIn("blocked", text)       # the data entries are shown with their flag

    def test_an_encrypted_data_entry_is_still_refused(self):
        raw = bytearray(self.wrapped)
        # entry 1 is the first data entry: set its "encrypted" bit (props 0x2804 -> 0x2806)
        struct.pack_into("<Q", raw, 0x20 + 0x20 + 0, struct.unpack_from("<Q", raw, 0x20 + 0x20)[0] | 0x2)
        with self.assertRaisesRegex(DescribeError, "encrypted"):
            unwrap_self(bytes(raw))


class RunLoopTests(unittest.TestCase):
    def test_runs_slice_after_slice_until_the_guest_stops(self):
        calls, state = [], {"stop": False}

        def start(pc, microseconds):
            calls.append((pc, microseconds))
            state["stop"] = len(calls) == 3

        pcs = iter([0x2000, 0x3000])
        result = run_sliced(start, lambda: next(pcs), lambda: state["stop"], 0x1000)
        self.assertEqual(result, "stopped")
        self.assertEqual(calls, [(0x1000, 100000), (0x2000, 100000), (0x3000, 100000)])  # resumes where it left off

    def test_timeout_ends_the_run(self):
        ticks = itertools.count()
        calls = []
        result = run_sliced(lambda pc, us: calls.append(pc), lambda: 0x5000, lambda: False, 0x1000,
                            timeout=0.25, clock=lambda: next(ticks) * 0.1)
        self.assertEqual(result, "timeout")
        self.assertEqual(len(calls), 3)      # clock reads 0.1, 0.2, then 0.3 >= the 0.25 deadline

    def test_without_a_timeout_the_clock_is_never_consulted(self):
        def clock():
            raise AssertionError("no timeout was requested")
        state = {"n": 0}

        def start(pc, us):
            state["n"] += 1

        self.assertEqual(run_sliced(start, lambda: 0, lambda: state["n"] >= 5, 0, clock=clock), "stopped")

    def test_a_stop_request_wins_over_a_timeout(self):
        self.assertEqual(run_sliced(lambda pc, us: None, lambda: 0, lambda: True, 0, timeout=0.001,
                                    clock=lambda: 99.0), "stopped")

    def test_slice_length_and_ctrl_c(self):
        seen = []
        run_sliced(lambda pc, us: seen.append(us), lambda: 0, lambda: True, 0, slice_seconds=0.5)
        self.assertEqual(seen, [500000])

        def interrupted(pc, us):
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            run_sliced(interrupted, lambda: 0, lambda: False, 0)   # Ctrl+C between slices reaches the caller

    def test_timeout_option(self):
        self.assertEqual(build_parser().parse_intermixed_args(["x.elf", "--timeout", "2.5"]).timeout, 2.5)
        self.assertEqual(build_parser().parse_intermixed_args(["x.elf"]).timeout, 0.0)


def set_buffer_attribute(registry, k, ptr, pixel_format, tiling, aspect, width, height, pitch):
    """Call sceVideoOutSetBufferAttribute the way compiled code does: six arguments in registers and
    the seventh (pitch) on the stack, just above the return address."""
    k.cpu.regs["rsp"] = 0x9000
    k.cpu.write(0x9008, struct.pack("<Q", pitch))
    return registry.functions["sceVideoOutSetBufferAttribute"](k, ptr, pixel_format, tiling, aspect, width, height)


class ShrinkTests(unittest.TestCase):
    def test_keeps_every_nth_pixel_of_every_nth_row(self):
        raw = b"".join(struct.pack("<I", i) for i in range(8))     # row 0: 0 1 2 3, row 1: 4 5 6 7
        w, h, out = shrink_pixels(raw, 4, 2, 2)
        self.assertEqual((w, h), (2, 1))
        self.assertEqual(struct.unpack("<2I", out), (0, 2))

    def test_factor_one_changes_nothing(self):
        raw = bytes(range(16))
        self.assertEqual(shrink_pixels(raw, 2, 2, 1), (2, 2, raw))

    def test_a_dimension_never_shrinks_to_zero(self):
        raw = b"".join(struct.pack("<I", i) for i in range(8))
        w, h, out = shrink_pixels(raw, 8, 1, 4)
        self.assertEqual((w, h, struct.unpack("<2I", out)), (2, 1, (0, 4)))


class VideoOutTests(unittest.TestCase):
    def setUp(self):
        self.cpu, self.display = FakeCpu(), RecordingDisplay()
        self.k = Kernel(self.cpu, streams={}, display_factory=lambda: self.display)
        self.r = make_default_registry()
        patcher = mock.patch.object(hle_video, "_pace")      # no real 60 Hz sleeping in most tests
        patcher.start()
        self.addCleanup(patcher.stop)

    def f(self, name, *args):
        return self.r.functions[name](self.k, *args)

    def register_frame(self, pixels, width=2, height=2, pitch=None, fmt=0x80002200, tiling=1):
        set_buffer_attribute(self.r, self.k, 0x2000, fmt, tiling, 0, width, height, pitch or width)
        self.cpu.write(0x3000, struct.pack("<QQ", 0x10000, 0x20000))
        self.cpu.write(0x10000, pixels)
        self.cpu.write(0x20000, bytes(len(pixels)))                    # the second buffer (blank)
        self.assertEqual(self.f("sceVideoOutRegisterBuffers", 1, 0, 0x3000, 2, 0x2000), 0)

    def test_buffer_attribute_layout_matches_the_header(self):
        set_buffer_attribute(self.r, self.k, 0x2000, 0x80002200, 1, 0, 1920, 1080, 1920)
        self.assertEqual(struct.unpack("<IIIIII", self.cpu.read(0x2000, 24)), (0x80002200, 1, 0, 1920, 1080, 1920))
        self.assertEqual(self.cpu.read(0x2018, 16), bytes(16))          # reserved[2] at offset 24, struct is 40 bytes

    def test_flip_shows_the_buffer_with_red_and_blue_swapped(self):
        self.register_frame(bytes([1, 2, 3, 255]) * 4)                  # A8B8G8R8 stores R, G, B, A
        self.assertEqual(self.f("sceVideoOutSubmitFlip", 1, 0, 1, 0), 0)
        self.assertEqual(self.display.frames, [(2, 2, bytes([3, 2, 1, 255]) * 4)])

    def test_a8r8g8b8_is_passed_through(self):
        self.register_frame(bytes([1, 2, 3, 255]) * 4, fmt=0x80000000)
        self.f("sceVideoOutSubmitFlip", 1, 0, 1, 0)
        self.assertEqual(self.display.frames[0][2], bytes([1, 2, 3, 255]) * 4)

    def test_pitch_wider_than_width_is_cropped(self):
        row0 = bytes([1] * 4) + bytes([2] * 4) + bytes([9] * 4)         # two pixels and padding
        row1 = bytes([3] * 4) + bytes([4] * 4) + bytes([9] * 4)
        self.register_frame(row0 + row1, pitch=3, fmt=0x80000000)
        self.f("sceVideoOutSubmitFlip", 1, 0, 1, 0)
        self.assertEqual(self.display.frames[0], (2, 2, bytes([1] * 4 + [2] * 4 + [3] * 4 + [4] * 4)))

    def test_wide_frames_are_shrunk_before_display(self):
        pixels = b"".join(struct.pack("<I", i) for i in range(16))       # 8 x 2
        with mock.patch.object(hle_video, "MAX_FRAME_WIDTH", 4):
            self.register_frame(pixels, width=8, height=2, fmt=0x80000000)
            self.f("sceVideoOutSubmitFlip", 1, 0, 1, 0)
        w, h, raw = self.display.frames[0]
        self.assertEqual((w, h, struct.unpack("<4I", raw)), (4, 1, (0, 2, 4, 6)))

    def test_closing_the_window_ends_the_program(self):
        self.display.closed = True
        self.register_frame(bytes(16))
        self.f("sceVideoOutSubmitFlip", 1, 0, 1, 0)
        self.assertEqual((self.k.exit_code, self.cpu.stopped), (0, True))

    def test_flip_status_counts_flips(self):
        self.register_frame(bytes(16))
        self.f("sceVideoOutSubmitFlip", 1, 0, 1, 0x1234)
        self.f("sceVideoOutSubmitFlip", 1, 1, 1, 0x1234)
        self.f("sceVideoOutGetFlipStatus", 1, 0x4000)
        num, _pt, _st, arg, _res, gpu_pending, pending, current, _r1 = struct.unpack("<QQQq16siiiI", self.cpu.read(0x4000, 64))
        self.assertEqual((num, arg, gpu_pending, pending, current), (2, 0x1234, 0, 0, 1))

    def test_flipping_an_unregistered_buffer_fails(self):
        self.register_frame(bytes(16))
        self.assertEqual(self.f("sceVideoOutSubmitFlip", 1, 5, 1, 0), hle_video.SCE_EINVAL)
        self.assertEqual(self.display.frames, [])

    def test_without_a_display_flips_still_succeed(self):
        k = Kernel(self.cpu, streams={})                                # --display none
        self.cpu.write(0x3000, struct.pack("<QQ", 0x10000, 0x20000))
        set_buffer_attribute(self.r, k, 0x2000, 0x80002200, 1, 0, 2, 2, 2)
        self.r.functions["sceVideoOutRegisterBuffers"](k, 1, 0, 0x3000, 2, 0x2000)
        self.assertEqual(self.r.functions["sceVideoOutSubmitFlip"](k, 1, 0, 1, 0), 0)

    def test_tiled_buffers_get_one_warning(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.register_frame(bytes(16), tiling=0)
            self.register_frame(bytes(16), tiling=0)
        self.assertEqual(err.getvalue().count("tiled"), 1)

    def test_resolution_status(self):
        self.f("sceVideoOutGetResolutionStatus", 1, 0x5000)
        self.assertEqual(struct.unpack("<IIII", self.cpu.read(0x5000, 16)), (1920, 1080, 1920, 1080))

    def test_open_and_simple_calls(self):
        self.assertEqual(self.f("sceVideoOutOpen", 0xFF, 0, 0, 0), hle_video.VIDEO_HANDLE)
        for name in ("sceVideoOutClose", "sceVideoOutSetFlipRate", "sceVideoOutAddFlipEvent", "sceVideoOutIsFlipPending"):
            self.assertEqual(self.f(name, 1, 0, 0), 0, name)

    def test_functions_are_found_by_nid(self):
        for name in ("sceVideoOutSubmitFlip", "sceKernelAllocateDirectMemory", "sceKernelMapDirectMemory"):
            self.assertTrue(self.r.has(nid_for(name) + "#B#B"), name)


class PacingTests(unittest.TestCase):
    def test_a_second_flip_right_after_the_first_waits_for_the_next_frame(self):
        cpu, r = FakeCpu(), make_default_registry()
        k = Kernel(cpu, streams={})
        cpu.write(0x3000, struct.pack("<QQ", 0x10000, 0x20000))
        set_buffer_attribute(r, k, 0x2000, 0x80002200, 1, 0, 2, 2, 2)
        r.functions["sceVideoOutRegisterBuffers"](k, 1, 0, 0x3000, 2, 0x2000)
        with mock.patch.object(hle_video._time, "sleep") as sleep:
            r.functions["sceVideoOutSubmitFlip"](k, 1, 0, 1, 0)
            r.functions["sceVideoOutSubmitFlip"](k, 1, 1, 1, 0)
        self.assertEqual(sleep.call_count, 1)                           # only the quick second flip waits
        self.assertTrue(0 < sleep.call_args[0][0] <= hle_video.FRAME_SECONDS)


class DirectMemoryTests(unittest.TestCase):
    def setUp(self):
        self.cpu = FakeCpu()
        self.k = Kernel(self.cpu, streams={})
        self.r = make_default_registry()

    def f(self, name, *args):
        return self.r.functions[name](self.k, *args)

    def test_allocation_returns_aligned_non_overlapping_blocks(self):
        self.assertEqual(self.f("sceKernelAllocateDirectMemory", 0, 1 << 32, 0x400000, 0x200000, 3, 0x1000), 0)
        self.assertEqual(self.f("sceKernelAllocateDirectMemory", 0, 1 << 32, 0x1000, 0x200000, 3, 0x1008), 0)
        first, second = (struct.unpack("<q", self.cpu.read(a, 8))[0] for a in (0x1000, 0x1008))
        self.assertEqual((first % 0x200000, second % 0x200000), (0, 0))
        self.assertGreaterEqual(second, first + 0x400000)

    def test_allocation_fails_when_the_pool_is_exhausted(self):
        self.assertEqual(self.f("sceKernelAllocateDirectMemory", 0, 1 << 40, 1 << 40, 0x4000, 3, 0x1000), hle_video.SCE_ENOMEM)
        self.assertEqual(self.f("sceKernelGetDirectMemorySize"), hle_video.DMEM_TOTAL)

    def test_mapping_gives_cpu_read_write_and_16k_alignment(self):
        self.cpu.write(0x2000, bytes(8))
        self.assertEqual(self.f("sceKernelMapDirectMemory", 0x2000, 0x5000, 0x33, 0, 0x100000, 0x4000), 0)
        base = struct.unpack("<Q", self.cpu.read(0x2000, 8))[0]
        self.assertEqual(base % 0x4000, 0)
        self.assertEqual(self.cpu.maps[-1], (base, 0x8000, 3))          # 0x33 -> CPU read+write; size rounded to 16 KB
        self.cpu.write(0x2008, bytes(8))
        self.f("sceKernelMapDirectMemory", 0x2008, 0x1000, 0x30, 0, 0, 0)  # GPU-only bits still map writable
        self.assertEqual(self.cpu.maps[-1][2], 3)

    def test_a_fixed_mapping_uses_the_requested_address(self):
        self.cpu.write(0x2000, struct.pack("<Q", 0x50000000))
        self.f("sceKernelMapDirectMemory", 0x2000, 0x4000, 0x33, 0x10, 0, 0)
        self.assertEqual(self.cpu.maps[-1][0], 0x50000000)

    def test_seventh_argument_comes_from_the_stack(self):
        self.cpu.regs["rsp"] = 0x7000
        self.cpu.write(0x7008, struct.pack("<Q", 0x6000))               # arg 7: where sceKernelMmap stores the address
        self.assertEqual(stack_arg(self.k, 0), 0x6000)
        self.assertEqual(self.f("sceKernelMmap", 0, 0x4000, 3, 0x1002, -1, 0), 0)
        self.assertEqual(struct.unpack("<Q", self.cpu.read(0x6000, 8))[0] % 0x4000, 0)
        self.assertEqual(self.f("sceKernelMmap", 0, 0x4000, 3, 0x0002, 3, 0), hle_video.SCE_EINVAL)  # no MAP_ANON

    def test_map_direct_memory2_takes_alignment_from_the_stack(self):
        self.cpu.regs["rsp"] = 0x7000
        self.cpu.write(0x7008, struct.pack("<Q", 0x200000))             # alignment
        self.cpu.write(0x2000, bytes(8))
        self.f("sceKernelMapDirectMemory2", 0x2000, 0x4000, 0, 0x33, 0, 0x100000)
        self.assertEqual(struct.unpack("<Q", self.cpu.read(0x2000, 8))[0] % 0x200000, 0)

    def test_available_memory_and_release(self):
        self.assertEqual(self.f("sceKernelAvailableDirectMemorySize", 0, 1 << 32, 0x4000, 0x3000, 0x3008), 0)
        self.assertGreater(struct.unpack("<Q", self.cpu.read(0x3008, 8))[0], 1 << 30)
        self.assertEqual(self.f("sceKernelReleaseDirectMemory", 0x10000, 0x4000), 0)


class EventQueueTests(unittest.TestCase):
    def test_create_and_wait(self):
        cpu, r = FakeCpu(), make_default_registry()
        k = Kernel(cpu, streams={})
        with mock.patch.object(hle_video, "_pace"):
            self.assertEqual(r.functions["sceKernelCreateEqueue"](k, 0x1000, 0x2000), 0)
            self.assertNotEqual(struct.unpack("<Q", cpu.read(0x1000, 8))[0], 0)
            cpu.write(0x3000, b"\xff" * 32)
            self.assertEqual(r.functions["sceKernelWaitEqueue"](k, 1, 0x3000, 1, 0x4000, 0), 0)
        self.assertEqual(cpu.read(0x3000, 32), bytes(32))               # an (empty) event was returned
        self.assertEqual(struct.unpack("<i", cpu.read(0x4000, 4))[0], 1)
        self.assertEqual(r.functions["sceKernelDeleteEqueue"](k, 1), 0)


class DispatchPathTests(unittest.TestCase):
    """The tests above call functions directly. These go through the real path a program takes: a
    syscall from a stub, with all six argument registers filled in (extra ones are garbage)."""

    def setUp(self):
        self.cpu, self.display = FakeCpu(), RecordingDisplay()
        self.k = Kernel(self.cpu, streams={}, display_factory=lambda: self.display)
        self.stubs = StubTable(self.cpu, make_default_registry())
        self.k.stubs = self.stubs
        patcher = mock.patch.object(hle_video, "_pace")
        patcher.start()
        self.addCleanup(patcher.stop)

    def invoke(self, name, *args):
        """Call an import like compiled code does: six registers always set, the rest filled with junk."""
        self.stubs.address_for(name)
        registers = list(args) + [0xDEAD] * (6 - len(args))
        return call(self.k, self.cpu, HLE_SYSCALL_BASE + self.stubs.names.index(name), *registers)

    def test_the_framebuffer_sequence_of_the_real_test_program(self):
        pixels = bytes([1, 2, 3, 255]) * 4
        self.cpu.write(0x10000, pixels)
        self.cpu.write(0x20000, bytes(16))
        self.cpu.write(0x3000, struct.pack("<QQ", 0x10000, 0x20000))
        self.cpu.regs["rsp"] = 0x9000
        self.cpu.write(0x9008, struct.pack("<Q", 2))                        # pitch: the 7th argument, on the stack
        self.assertEqual(self.invoke("sceVideoOutOpen", 0xFF, 0, 0, 0), 1)
        self.invoke("sceVideoOutSetBufferAttribute", 0x2000, 0x80002200, 1, 0, 2, 2)
        self.assertEqual(self.invoke("sceVideoOutRegisterBuffers", 1, 0, 0x3000, 2, 0x2000), 0)
        self.assertEqual(self.invoke("sceVideoOutSubmitFlip", 1, 0, 1, 0), 0)
        self.assertEqual(self.display.frames, [(2, 2, bytes([3, 2, 1, 255]) * 4)])
        self.assertEqual(self.stubs.failures, {})                           # nothing raised along the way

    def test_every_function_fits_the_six_register_arguments(self):
        r = make_default_registry()
        too_many = []
        for name, fn in r.functions.items():
            params = list(inspect.signature(fn).parameters.values())[1:]
            positional = [p for p in params if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
            if len(positional) > 6:
                too_many.append((name, len(positional)))
        self.assertEqual(too_many, [])   # a 7th argument must be read with stack_arg()

    def test_functions_get_only_the_arguments_they_declare(self):
        seen = {}
        r = HleRegistry()

        def two(k, a, b):
            seen["two"] = (a, b)

        def every(k, *a):
            seen["all"] = a

        r.function("two")(two)
        r.function("all")(every)
        stubs = StubTable(self.cpu, r)
        k = Kernel(self.cpu, streams={})
        for name in ("two", "all"):
            stubs.address_for(name)
            stubs.dispatch(k, stubs.names.index(name), [1, 2, 3, 4, 5, 6])
        self.assertEqual(seen["two"], (1, 2))
        self.assertEqual(seen["all"], (1, 2, 3, 4, 5, 6))

    def test_a_failing_function_is_reported_once_and_counted(self):
        r = HleRegistry()

        def broken(k, *_):
            raise ValueError("boom")

        r.function("broken")(broken)
        stubs = StubTable(self.cpu, r)
        stubs.address_for("broken")
        k = Kernel(self.cpu, streams={})
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            results = [stubs.dispatch(k, 0, [0] * 6) for _ in range(5)]
            stubs.report_failures()
        self.assertEqual(results, [-1] * 5)
        lines = err.getvalue().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertIn("broken() failed: ValueError('boom')", lines[0])
        self.assertIn("failed 5 times in total", lines[1])


if __name__ == "__main__":
    unittest.main()
