"""High-level emulation (HLE) of a tiny OS kernel: syscalls are handled in Python.

Two syscall tables: 'linux' (easy to test with programs you build yourself) and
'freebsd' (the numbering family that PlayStation-style kernels descend from).
Error handling is simplified to the Linux convention (negative errno in rax).
Real FreeBSD signals errors via the carry flag; that is a TODO for later.
"""
import os
import struct
import sys
import time as _time

from .hle import HLE_SYSCALL_BASE

ENOENT, EBADF, ENOMEM, EACCES, EFAULT, EISDIR, EINVAL, ENODEV, ENOTTY, ESPIPE, ENOSYS = (
    2, 9, 12, 13, 14, 21, 22, 19, 25, 29, 38)

MAP_ANON = {"linux": 0x20, "freebsd": 0x1000}
MMAP_BASE = 0x10000000
BRK_BASE = 0x20000000
BRK_LIMIT = 0x10000000  # the program break may grow by at most 256 MB
PAGE = 0x1000
MAX_PATH = 4096

ORB_PRESENT = 0x1000  # orbemu's own syscall: show a frame (buf, width, height)
ORB_INPUT = 0x1001    # orbemu's own syscall: bitmask of held keys
ORB_PAD = 0x1002      # orbemu's own syscall: read the game controller (16-byte struct)
ORB_PAD_RUMBLE = 0x1003  # orbemu's own syscall: vibrate the controller (large, small, ms)
MAX_W, MAX_H = 1920, 1080

ARCH_SET_GS, ARCH_SET_FS, ARCH_GET_FS, ARCH_GET_GS = 0x1001, 0x1002, 0x1003, 0x1004


def _align_up(x):
    return (x + PAGE - 1) & ~(PAGE - 1)


class Kernel:
    def __init__(self, cpu, abi="linux", streams=None, root=None, display_factory=None,
                 pad_factory=None):
        """root: host directory the guest may open files from (read-only).
        With root=None, open() is refused entirely."""
        self.cpu = cpu
        self.abi = abi
        self.root = root
        self.display_factory = display_factory  # called on the first frame, not before
        self._display = None
        self.pad_factory = pad_factory  # called on the first controller read
        self._pad = None
        self.stubs = None      # set by __main__: the HLE stub table for dynamic imports
        self.hle_state = {}    # scratch space for HLE functions (e.g. the malloc arena)
        self._started = _time.monotonic()
        self.exit_code = None
        self.mmap_ptr = MMAP_BASE
        self.brk = BRK_BASE
        self.brk_mapped = BRK_BASE
        self.fds = {}
        self.next_fd = 3
        self.streams = streams if streams is not None else {
            0: sys.stdin.buffer, 1: sys.stdout.buffer, 2: sys.stderr.buffer}
        if abi == "linux":
            self.table = {0: self.sys_read, 1: self.sys_write, 2: self.sys_open,
                          3: self.sys_close, 5: self.sys_fstat, 8: self.sys_lseek,
                          9: self.sys_mmap, 10: self.sys_mprotect, 11: self.sys_munmap,
                          12: self.sys_brk, 16: self.sys_ioctl, 20: self.sys_writev,
                          35: self.sys_nanosleep, 39: self.sys_getpid, 60: self.sys_exit,
                          96: self.sys_gettimeofday, ORB_PRESENT: self.sys_orb_present,
                          ORB_INPUT: self.sys_orb_input, ORB_PAD: self.sys_orb_pad,
                          ORB_PAD_RUMBLE: self.sys_orb_pad_rumble,
                          158: self.sys_arch_prctl, 201: self.sys_time,
                          218: self.sys_set_tid_address, 228: self.sys_clock_gettime,
                          231: self.sys_exit, 257: self.sys_openat, 262: self.sys_newfstatat,
                          267: self.sys_readlinkat, 273: self.sys_set_robust_list,
                          302: self.sys_prlimit64, 318: self.sys_getrandom,
                          334: self.sys_rseq}
        elif abi == "freebsd":
            self.table = {1: self.sys_exit, 3: self.sys_read, 4: self.sys_write,
                          5: self.sys_open, 6: self.sys_close, 20: self.sys_getpid,
                          477: self.sys_mmap}
        else:
            raise ValueError(f"unknown abi {abi!r}")

    def handle_syscall(self, cpu):
        num = cpu.get_reg("rax")
        args = [cpu.get_reg(r) for r in ("rdi", "rsi", "rdx", "r10", "r8", "r9")]
        if num >= HLE_SYSCALL_BASE and self.stubs is not None:  # a call to an imported function
            cpu.set_reg("rax", self.stubs.dispatch(self, num - HLE_SYSCALL_BASE, args) & 0xFFFFFFFFFFFFFFFF)
            return
        fn = self.table.get(num)
        if fn is None:
            print(f"[kernel] unimplemented syscall {num} args={[hex(a) for a in args]}",
                  file=sys.stderr)
            ret = -ENOSYS
        else:
            ret = fn(*args)
        cpu.set_reg("rax", ret & 0xFFFFFFFFFFFFFFFF)

    # --- helpers --------------------------------------------------------
    def _read_cstring(self, addr):
        out = bytearray()
        try:
            for i in range(MAX_PATH):
                b = self.cpu.read(addr + i, 1)
                if b == b"\x00":
                    return out.decode("utf-8", errors="replace")
                out += b
        except Exception:
            return None
        return None  # no terminator within MAX_PATH

    # --- syscalls -------------------------------------------------------
    def sys_write(self, fd, buf, count, *_):
        stream = self.streams.get(fd)
        if stream is None:
            return -EBADF
        try:
            data = self.cpu.read(buf, count)
        except Exception:
            return -EFAULT
        stream.write(data)
        if hasattr(stream, "flush"):
            stream.flush()
        return count

    def sys_read(self, fd, buf, count, *_):
        if count == 0:
            return 0
        count = min(count, 1 << 20)
        if fd in self.fds:
            data = self.fds[fd].read(count)
        else:
            stream = self.streams.get(fd)
            if stream is None:
                return -EBADF
            data = stream.read1(count) if hasattr(stream, "read1") else stream.read(count)
        try:
            self.cpu.write(buf, data)
        except Exception:
            return -EFAULT
        return len(data)

    def sys_open(self, path_ptr, flags, mode, *_):
        path = self._read_cstring(path_ptr)
        if path is None:
            return -EFAULT
        if self.root is None or flags & 3 != 0:  # read-only access, inside root only
            return -EACCES
        root = os.path.realpath(self.root)
        host = os.path.realpath(os.path.join(root, path.lstrip("/\\")))
        try:
            if os.path.commonpath([host, root]) != root:
                return -EACCES
        except ValueError:
            return -EACCES
        try:
            f = open(host, "rb")
        except FileNotFoundError:
            return -ENOENT
        except IsADirectoryError:
            return -EISDIR
        except OSError:
            return -EACCES
        fd = self.next_fd
        self.next_fd += 1
        self.fds[fd] = f
        return fd

    def sys_close(self, fd, *_):
        f = self.fds.pop(fd, None)
        if f is not None:
            f.close()
            return 0
        return 0 if fd in (0, 1, 2) else -EBADF

    def sys_brk(self, addr, *_):
        """Linux semantics: returns the new break, or the current one if the request fails."""
        if addr < BRK_BASE or addr - BRK_BASE > BRK_LIMIT:
            return self.brk
        new_end = _align_up(addr)
        if new_end > self.brk_mapped:
            self.cpu.map(self.brk_mapped, new_end - self.brk_mapped, 3)  # RW
            self.brk_mapped = new_end
        self.brk = addr
        return self.brk

    def sys_arch_prctl(self, code, addr, *_):
        regs = {ARCH_SET_FS: "fs_base", ARCH_SET_GS: "gs_base",
                ARCH_GET_FS: "fs_base", ARCH_GET_GS: "gs_base"}
        reg = regs.get(code)
        if reg is None:
            return -EINVAL
        try:
            if code in (ARCH_SET_FS, ARCH_SET_GS):
                self.cpu.set_reg(reg, addr)
            else:
                self.cpu.write(addr, struct.pack("<Q", self.cpu.get_reg(reg)))
        except KeyError:
            return -EINVAL
        except Exception:
            return -EFAULT
        return 0

    def sys_fstat(self, fd, buf, *_):
        if fd in (0, 1, 2):
            mode, size = 0o020620, 0            # character device (a terminal)
        elif fd in self.fds:
            mode, size = 0o100444, os.fstat(self.fds[fd].fileno()).st_size
        else:
            return -EBADF
        # struct stat on x86-64 Linux: 144 bytes
        st = struct.pack("<QQQIIIIQqqqQQQQQQqqq", 1, 1, 1, mode, 0, 0, 0, 0, size, 4096,
                         (size + 511) // 512, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        try:
            self.cpu.write(buf, st)
        except Exception:
            return -EFAULT
        return 0

    def sys_ioctl(self, *_):
        return -ENOTTY  # nothing is a terminal, so libc will buffer stdout fully

    def sys_mprotect(self, addr, length, prot, *_):
        if addr & (PAGE - 1):
            return -EINVAL
        try:
            self.cpu.protect(addr, _align_up(length), prot & 7)
        except Exception:
            return -ENOMEM
        return 0

    def sys_set_tid_address(self, *_):
        return 1  # our one and only thread id

    def sys_set_robust_list(self, *_):
        return 0

    def sys_rseq(self, *_):
        return -ENOSYS  # optional feature; libc falls back gracefully

    def sys_readlinkat(self, *_):
        return -ENOENT  # no /proc/self/exe

    def sys_prlimit64(self, pid, resource, new_ptr, old_ptr, *_):
        if old_ptr:
            cur = 8 << 20 if resource == 3 else 0xFFFFFFFFFFFFFFFF  # 8 MB stack, rest unlimited
            try:
                self.cpu.write(old_ptr, struct.pack("<QQ", cur, 0xFFFFFFFFFFFFFFFF))
            except Exception:
                return -EFAULT
        return 0

    def sys_getrandom(self, buf, buflen, flags, *_):
        n = min(buflen, 256)
        try:
            self.cpu.write(buf, os.urandom(n))
        except Exception:
            return -EFAULT
        return n

    def sys_openat(self, dirfd, path_ptr, flags, mode, *_):
        return self.sys_open(path_ptr, flags, mode)  # only paths relative to --root, any dirfd

    def sys_newfstatat(self, dirfd, path_ptr, buf, flags, *_):
        path = self._read_cstring(path_ptr)
        if path is None:
            return -EFAULT
        if path == "" and flags & 0x1000:  # AT_EMPTY_PATH: this is just fstat(dirfd)
            return self.sys_fstat(dirfd, buf)
        return -ENOENT

    def sys_lseek(self, fd, offset, whence, *_):
        f = self.fds.get(fd)
        if f is None:
            return -ESPIPE if fd in (0, 1, 2) else -EBADF
        if offset >= 1 << 63:
            offset -= 1 << 64
        try:
            f.seek(offset, whence)
        except (OSError, ValueError):
            return -EINVAL
        return f.tell()

    def sys_writev(self, fd, iov, iovcnt, *_):
        total = 0
        for i in range(min(iovcnt, 1024)):
            try:
                base, length = struct.unpack("<QQ", self.cpu.read(iov + 16 * i, 16))
            except Exception:
                return -EFAULT if total == 0 else total
            ret = self.sys_write(fd, base, length)
            if ret < 0:
                return ret if total == 0 else total
            total += ret
        return total

    def sys_munmap(self, addr, length, *_):
        if addr & (PAGE - 1) or length == 0:
            return -EINVAL
        try:
            self.cpu.unmap(addr, _align_up(length))
        except Exception:
            return -EINVAL
        return 0

    def sys_clock_gettime(self, clock_id, tp, *_):
        if clock_id == 0:
            ns = _time.time_ns()
        elif clock_id in (1, 4, 6, 7):
            ns = _time.monotonic_ns()
        elif clock_id in (2, 3):
            ns = _time.process_time_ns()
        else:
            return -EINVAL
        try:
            self.cpu.write(tp, struct.pack("<qq", ns // 10**9, ns % 10**9))
        except Exception:
            return -EFAULT
        return 0

    def sys_time(self, tloc, *_):
        secs = int(_time.time())
        if tloc:
            try:
                self.cpu.write(tloc, struct.pack("<q", secs))
            except Exception:
                return -EFAULT
        return secs

    def sys_gettimeofday(self, tv, tz, *_):
        if tv:
            ns = _time.time_ns()
            try:
                self.cpu.write(tv, struct.pack("<qq", ns // 10**9, ns % 10**9 // 1000))
            except Exception:
                return -EFAULT
        return 0

    def sys_nanosleep(self, req, rem, *_):
        try:
            sec, nsec = struct.unpack("<qq", self.cpu.read(req, 16))
        except Exception:
            return -EFAULT
        if sec < 0 or not 0 <= nsec < 10**9:
            return -EINVAL
        if self._display is not None:
            self._display.pump()  # keep the window responsive
        _time.sleep(min(sec + nsec / 1e9, 5.0))
        return 0

    def sys_orb_present(self, buf, width, height, *_):
        """Show one frame: width*height pixels of 32-bit 0x00RRGGBB at guest address buf.
        Returns 0 normally, 1 if the window has been closed, or a negative errno."""
        if self.display_factory is None:
            return -ENODEV
        if not (1 <= width <= MAX_W and 1 <= height <= MAX_H):
            return -EINVAL
        try:
            raw = self.cpu.read(buf, width * height * 4)
        except Exception:
            return -EFAULT
        return 1 if self.get_display().present(width, height, raw) else 0

    def sys_orb_input(self, *_):
        """Bitmask of currently held keys (see KEY_* in display.py). 0 before the first frame."""
        if self.display_factory is None:
            return -ENODEV
        return self._display.keys() if self._display is not None else 0

    def sys_orb_pad(self, out_ptr, *_):
        """Write the controller state (16 bytes, see orbemu/pad.py) to guest memory."""
        pad = self.get_pad()
        if pad is None:
            return -ENODEV
        from .pad import pack_state
        ms = int((_time.monotonic() - self._started) * 1000)
        try:
            self.cpu.write(out_ptr, pack_state(pad.poll(), ms))
        except Exception:
            return -EFAULT
        return 0

    def sys_orb_pad_rumble(self, large, small, duration_ms, *_):
        """Vibrate: large = heavy motor, small = light motor (0..255 each); both 0 stops it.
        duration_ms 0 means "until changed" (capped at 60 s). Returns -ENODEV if unsupported."""
        pad = self.get_pad()
        if pad is None:
            return -ENODEV
        ok = pad.rumble(min(large, 255), min(small, 255), min(duration_ms, 60000))
        return 0 if ok else -ENODEV

    def shutdown(self):
        if self._display is not None:
            self._display.close()
            self._display = None
        if self._pad is not None:
            self._pad.close()
            self._pad = None

    def sys_exit(self, code, *_):
        self.exit_code = code & 0xFF
        self.cpu.stop()
        return 0

    def sys_getpid(self, *_):
        return 1

    def alloc_anon(self, length, prot, align=PAGE):
        """Map fresh anonymous memory at the next free address, aligned to `align` (PlayStation
        pages are 16 KB). Returns the address, or -ENOMEM for an empty request."""
        size = (length + align - 1) & ~(align - 1)
        if size == 0:
            return -ENOMEM
        base = (self.mmap_ptr + align - 1) & ~(align - 1)
        self.cpu.map(base, size, prot & 7)
        self.mmap_ptr = base + size
        return base

    def sys_mmap(self, addr, length, prot, flags, fd, offset):
        if not flags & MAP_ANON[self.abi]:
            return -ENOSYS  # file-backed mappings not supported yet
        return self.alloc_anon(length, prot)

    def get_display(self):
        """The display object, created on first use (None if display output is off)."""
        if self._display is None and self.display_factory is not None:
            self._display = self.display_factory()
        return self._display

    def get_pad(self):
        """The controller object, created on first use (None if controller support is off)."""
        if self._pad is None and self.pad_factory is not None:
            self._pad = self.pad_factory()
        return self._pad
