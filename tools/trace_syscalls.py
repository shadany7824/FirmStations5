"""Linux-only helper: lists the syscalls a program makes (like a mini strace).
Usage: python tools/trace_syscalls.py ./program.elf
Use it to find which syscalls orbemu still needs to implement."""
import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.restype = ctypes.c_long
libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
PTRACE_TRACEME, PTRACE_SYSCALL, PTRACE_GETREGS = 0, 24, 12
class Regs(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in
        "r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs".split()]
pid = os.fork()
if pid == 0:
    libc.ptrace(PTRACE_TRACEME, 0, None, None)
    os.execv(sys.argv[1], sys.argv[1:])
os.waitpid(pid, 0)
entering = True
seen = []
while True:
    if libc.ptrace(PTRACE_SYSCALL, pid, None, None) < 0:
        print("ptrace failed, errno", ctypes.get_errno()); break
    _, status = os.waitpid(pid, 0)
    if os.WIFEXITED(status):
        break
    r = Regs()
    libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(r))
    if entering:
        seen.append((r.orig_rax, r.rdi, r.rsi, r.rdx))
    entering = not entering
for n, a, b, c in seen:
    print(f"syscall {n:4d}  args {a:#x} {b:#x} {c:#x}", file=sys.stderr)
