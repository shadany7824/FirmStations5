"""POSIX and pthread functions, answered by Python (what libkernel provides on a PlayStation).

The program is single-threaded for now, so locks never block and condition variables never wait.
Constants and struct sizes follow FreeBSD, which is what PlayStation system software is based on;
a few come from memory and are marked.
"""
import struct
import time as _time

from .hle_util import alloc, errno_address, fail, posix_result, read_cstr  # noqa: F401

MAP_ANON = 0x1000          # FreeBSD's value (Linux uses 0x20)
PAGE_SIZE = 0x4000         # PlayStation memory pages are 16 KB
TIOCGETA = 0x402C7413      # ioctl "get terminal attributes": _IOR('t', 19, struct termios of 44 bytes)
TERMIOS_SIZE = 44
ENOTTY, EBADF, EINVAL, ENOSYS_BSD = 25, 9, 22, 78

# sysconf(name) answers, FreeBSD numbering (from memory)
SYSCONF = {47: PAGE_SIZE, 57: 8, 58: 8, 3: 100}  # _SC_PAGESIZE, _SC_NPROCESSORS_CONF/ONLN, _SC_CLK_TCK

# pthread_once(once_control, init_routine) in machine code, because it must call guest code:
#   cmp dword [rdi], 0 ; jne done ; mov dword [rdi], 1 ; sub rsp, 8 ; call rsi ; add rsp, 8
#   done: xor eax, eax ; ret
PTHREAD_ONCE = bytes([0x83, 0x3F, 0x00, 0x75, 0x10, 0xC7, 0x07, 0x01, 0x00, 0x00, 0x00,
                      0x48, 0x83, 0xEC, 0x08, 0xFF, 0xD6, 0x48, 0x83, 0xC4, 0x08, 0x31, 0xC0, 0xC3])

# Functions that do nothing and report success (single thread, no signals, no polling).
ALWAYS_ZERO = """
pthread_mutex_init pthread_mutex_lock pthread_mutex_unlock pthread_mutex_trylock pthread_mutex_destroy
pthread_mutexattr_init pthread_mutexattr_destroy pthread_mutexattr_settype
pthread_cond_wait pthread_cond_timedwait pthread_cond_signal pthread_cond_broadcast pthread_cond_destroy
pthread_rwlock_rdlock pthread_rwlock_wrlock pthread_rwlock_unlock pthread_detach pthread_join
sched_yield madvise raise poll
""".split()


def register(r):
    for name in ALWAYS_ZERO:
        r.function(name)(lambda k, *_: 0)
    r.native_function("pthread_once", PTHREAD_ONCE)

    @r.function("__error")
    def __error(k, *_):
        return errno_address(k)  # a pointer to errno; the C library stores errors through it

    @r.function("pthread_self")
    def pthread_self(k, *_):
        if "thread_self" not in k.hle_state:
            k.hle_state["thread_self"] = alloc(k, 256)  # a zeroed stand-in thread structure
        return k.hle_state["thread_self"]

    @r.function("pthread_equal")
    def pthread_equal(k, a, b, *_):
        return int(a == b)

    @r.function("pthread_key_create")
    def pthread_key_create(k, key_ptr, destructor, *_):
        keys = k.hle_state.setdefault("tls_keys", {})
        key = len(keys)
        keys[key] = 0
        k.cpu.write(key_ptr, struct.pack("<I", key))
        return 0

    @r.function("pthread_setspecific")
    def pthread_setspecific(k, key, value, *_):
        k.hle_state.setdefault("tls_keys", {})[key] = value
        return 0

    @r.function("pthread_getspecific")
    def pthread_getspecific(k, key, *_):
        return k.hle_state.setdefault("tls_keys", {}).get(key, 0)

    @r.function("sysconf")
    def sysconf(k, name, *_):
        return SYSCONF[name] if name in SYSCONF else fail(k, EINVAL)

    @r.function("mmap")
    def mmap(k, addr, length, prot, flags, fd, offset):
        if not flags & MAP_ANON:
            return fail(k, ENOSYS_BSD)  # file-backed mappings are not supported yet
        base = k.alloc_anon(length, prot, PAGE_SIZE)
        return fail(k, 12) if base < 0 else base  # 12 = ENOMEM

    @r.function("munmap")
    def munmap(k, addr, length, *_):
        return posix_result(k, k.sys_munmap(addr, length))

    @r.function("_write")
    def _write(k, fd, buf, count, *_):
        return posix_result(k, k.sys_write(fd, buf, count))

    @r.function("_writev")
    def _writev(k, fd, iov, count, *_):
        return posix_result(k, k.sys_writev(fd, iov, count))

    @r.function("_exit")
    def _exit(k, code, *_):
        return k.sys_exit(code)

    @r.function("open")
    def open_(k, path, flags, mode, *_):
        return posix_result(k, k.sys_open(path, flags, mode))

    @r.function("close")
    def close(k, fd, *_):
        return posix_result(k, k.sys_close(fd))

    @r.function("lseek")
    def lseek(k, fd, offset, whence, *_):
        return posix_result(k, k.sys_lseek(fd, offset, whence))

    @r.function("fstat")
    def fstat(k, fd, buf, *_):
        # FreeBSD's struct stat layout differs from Linux's; failing makes stdio fall back to
        # default buffering, which is fine for now.
        return fail(k, EBADF)

    @r.function("ioctl")
    def ioctl(k, fd, request, argp, *_):
        if request == TIOCGETA and fd in (1, 2) and argp:
            k.cpu.write(argp, bytes(TERMIOS_SIZE))  # "yes, a terminal": stdout becomes line-buffered
            return 0
        return fail(k, ENOTTY)

    @r.function("nanosleep")
    def nanosleep(k, req, rem, *_):
        return posix_result(k, k.sys_nanosleep(req, rem))

    @r.function("sigaction")
    def sigaction(k, sig, act, oact, *_):
        if oact:
            k.cpu.write(oact, bytes(32))  # struct sigaction: no handler installed
        return 0

    @r.function("sigprocmask")
    def sigprocmask(k, how, new_set, old_set, *_):
        if old_set:
            k.cpu.write(old_set, bytes(16))  # sigset_t: nothing blocked
        return 0
