"""Formatting for crash reports (kept free of any Unicorn import so it can be tested anywhere)."""

# Unicorn's memory access types (UC_MEM_*) that mean "this access failed".
FAULT_NAMES = {19: "read from unmapped memory", 20: "write to unmapped memory",
               21: "instruction fetch from unmapped memory", 22: "write to read-only memory",
               23: "read from protected memory", 24: "instruction fetch from non-executable memory"}


def format_fault(access, address, size):
    return f"{FAULT_NAMES.get(access, 'bad memory access')} ({size} bytes) at address {address:#x}"


def format_registers(regs):
    """regs: ordered list of (name, value) pairs -> lines, two per row."""
    cells = [f"{name:>3}={value:#018x}" for name, value in regs]
    return ["  " + "  ".join(cells[i:i + 2]) for i in range(0, len(cells), 2)]
