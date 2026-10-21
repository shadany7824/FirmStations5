import io
import os
import struct
import tempfile
import unittest
from types import SimpleNamespace

from orbemu.__main__ import build_parser, make_display_factory, make_pad_factory
from orbemu import pad as padmod
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


if __name__ == "__main__":
    unittest.main()
