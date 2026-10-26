"""CPU + memory backend built on the Unicorn engine (pip install unicorn)."""
import struct

from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_HOOK_INSN
from unicorn import x86_const as x

from .diag import format_fault, format_registers
from .runloop import run_sliced

_REGS = {
    "rax": x.UC_X86_REG_RAX, "rdi": x.UC_X86_REG_RDI, "rsi": x.UC_X86_REG_RSI,
    "rdx": x.UC_X86_REG_RDX, "r10": x.UC_X86_REG_R10, "r8": x.UC_X86_REG_R8,
    "r9": x.UC_X86_REG_R9, "rsp": x.UC_X86_REG_RSP, "rip": x.UC_X86_REG_RIP,
    "rbx": x.UC_X86_REG_RBX, "rcx": x.UC_X86_REG_RCX, "rbp": x.UC_X86_REG_RBP,
    "r11": x.UC_X86_REG_R11, "r12": x.UC_X86_REG_R12, "r13": x.UC_X86_REG_R13,
    "r14": x.UC_X86_REG_R14, "r15": x.UC_X86_REG_R15,
}
for _name, _const in (("fs_base", "UC_X86_REG_FS_BASE"), ("gs_base", "UC_X86_REG_GS_BASE")):
    if hasattr(x, _const):  # needs Unicorn 2.x
        _REGS[_name] = getattr(x, _const)


class UnicornCpu:
    def __init__(self):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.fault = None  # (access type, address, size) of the last failed memory access
        self._stopped = False
        try:  # remember what a crash touched, for the report; never let this break the emulator
            from unicorn import (UC_HOOK_MEM_FETCH_PROT, UC_HOOK_MEM_FETCH_UNMAPPED,
                                 UC_HOOK_MEM_READ_PROT, UC_HOOK_MEM_READ_UNMAPPED,
                                 UC_HOOK_MEM_WRITE_PROT, UC_HOOK_MEM_WRITE_UNMAPPED)

            def on_fault(uc, access, address, size, value, user_data):
                self.fault = (access, address, size)
                return False  # not handled: the emulation stops with an error as before

            self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED
                             | UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_READ_PROT
                             | UC_HOOK_MEM_WRITE_PROT | UC_HOOK_MEM_FETCH_PROT, on_fault)
        except Exception:
            pass

    # memory
    def map(self, addr, size, perms):
        self.uc.mem_map(addr, size, perms)

    def unmap(self, addr, size):
        self.uc.mem_unmap(addr, size)

    def protect(self, addr, size, perms):
        self.uc.mem_protect(addr, size, perms)

    def read(self, addr, size):
        return bytes(self.uc.mem_read(addr, size))

    def write(self, addr, data):
        self.uc.mem_write(addr, bytes(data))

    # registers
    def get_reg(self, name):
        return self.uc.reg_read(_REGS[name])

    def set_reg(self, name, value):
        self.uc.reg_write(_REGS[name], value)

    # execution
    def on_syscall(self, handler):
        def _hook(uc, user_data):
            handler(self)
        self.uc.hook_add(UC_HOOK_INSN, _hook, None, 1, 0, x.UC_X86_INS_SYSCALL)

    def stop(self):
        self._stopped = True
        self.uc.emu_stop()

    def describe_state(self):
        """Registers, the code at rip and the top of the stack, for a crash report."""
        lines = []
        if self.fault is not None:
            lines.append("  " + format_fault(*self.fault))
        order = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                 "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
        lines += format_registers([(n, self.get_reg(n)) for n in order])
        try:
            lines.append("  code at rip: " + self.read(self.get_reg("rip"), 16).hex(" "))
        except Exception:
            lines.append("  code at rip: (not readable)")
        try:
            words = struct.unpack("<4Q", self.read(self.get_reg("rsp"), 32))
            lines.append("  top of stack: " + " ".join(f"{w:#x}" for w in words))
        except Exception:
            lines.append("  top of stack: (not readable)")
        return "\n".join(lines)

    def run(self, entry, timeout=0.0):
        """Run until the guest exits (returns "stopped") or `timeout` seconds pass ("timeout")."""
        self._stopped = False
        try:
            return run_sliced(lambda pc, us: self.uc.emu_start(pc, 0, timeout=us),
                              lambda: self.get_reg("rip"), lambda: self._stopped, entry, timeout)
        except UcError as e:
            raise RuntimeError(f"CPU fault at rip={self.get_reg('rip'):#x}: {e}\n"
                               + self.describe_state()) from e
