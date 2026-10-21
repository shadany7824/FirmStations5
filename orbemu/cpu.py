"""CPU + memory backend built on the Unicorn engine (pip install unicorn)."""
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_HOOK_INSN
from unicorn import x86_const as x

_REGS = {
    "rax": x.UC_X86_REG_RAX, "rdi": x.UC_X86_REG_RDI, "rsi": x.UC_X86_REG_RSI,
    "rdx": x.UC_X86_REG_RDX, "r10": x.UC_X86_REG_R10, "r8": x.UC_X86_REG_R8,
    "r9": x.UC_X86_REG_R9, "rsp": x.UC_X86_REG_RSP, "rip": x.UC_X86_REG_RIP,
}
for _name, _const in (("fs_base", "UC_X86_REG_FS_BASE"), ("gs_base", "UC_X86_REG_GS_BASE")):
    if hasattr(x, _const):  # needs Unicorn 2.x
        _REGS[_name] = getattr(x, _const)


class UnicornCpu:
    def __init__(self):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)

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
        self.uc.emu_stop()

    def run(self, entry):
        try:
            self.uc.emu_start(entry, 0)
        except UcError as e:
            raise RuntimeError(f"CPU fault at rip={self.get_reg('rip'):#x}: {e}") from e
