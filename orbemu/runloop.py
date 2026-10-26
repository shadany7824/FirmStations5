"""Running the CPU in short slices instead of one endless call.

A guest that spins in a loop never calls back into Python, and Python only notices Ctrl+C while it
is running Python code. Running in slices of a tenth of a second lets Ctrl+C work, and makes a
`--timeout` possible. (A slice ends at an instruction boundary; the next one resumes at the saved pc.)
"""
import time


def run_sliced(start, get_pc, stopped, entry, timeout=0.0, slice_seconds=0.1, clock=time.monotonic):
    """start(pc, microseconds) runs the CPU for at most that long; stopped() says whether the guest
    asked to stop (exit). Returns "stopped" or "timeout"."""
    deadline = clock() + timeout if timeout else None
    pc = entry
    while True:
        start(pc, max(1, int(slice_seconds * 1_000_000)))
        if stopped():
            return "stopped"
        if deadline is not None and clock() >= deadline:
            return "timeout"
        pc = get_pc()
