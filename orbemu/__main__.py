import argparse
import sys

from .dynlink import apply_relocations
from .elf import ElfError, parse_elf
from .hle import StubTable
from .hle_libc import make_default_registry
from .kernel import Kernel
from .loader import load_image
from .names import pretty
from .stack import build_initial_stack
from .tls import setup_tls

DYN_BASE = 0x40000000  # where position-independent programs are loaded


def make_display_factory(args):
    if args.display == "none":
        return None
    if args.display == "ppm":
        from .display import PpmDisplay
        return lambda: PpmDisplay(args.frames_dir, args.dump_every, args.max_frames)

    def window():
        from .display import TkDisplay
        return TkDisplay()
    return window


def make_pad_factory(args):
    if args.pad == "none":
        return None

    def factory():
        from .pad import NullPad, PygamePad
        try:
            return PygamePad()
        except ImportError:
            print("orbemu: pygame is not installed, so no controller "
                  "(run: python -m pip install pygame)", file=sys.stderr)
        except Exception as e:  # pygame is there but the controller system failed to start
            print(f"orbemu: controller support failed to start: {e}", file=sys.stderr)
        return NullPad()
    return factory


def build_parser():
    ap = argparse.ArgumentParser(prog="orbemu")
    ap.add_argument("elf", help="x86-64 ELF executable (ET_EXEC)")
    ap.add_argument("--abi", choices=["linux", "freebsd"], default="linux")
    ap.add_argument("--root", help="host directory the guest may read files from (default: none)")
    ap.add_argument("--display", choices=["window", "ppm", "none"], default="window",
                    help="where frames go: a window (default), .ppm files, or nowhere")
    ap.add_argument("--frames-dir", default="frames", help="folder for --display ppm")
    ap.add_argument("--dump-every", type=int, default=30, help="save every Nth frame (ppm)")
    ap.add_argument("--pad", choices=["auto", "none"], default="auto",
                    help="game controller: auto (needs pygame; default) or none")
    ap.add_argument("--timeout", type=float, default=0.0, metavar="SECONDS",
                    help="stop the program after this many seconds (for programs that never exit)")
    ap.add_argument("--trace-imports", action="store_true",
                    help="print every call the program makes into the Python libraries")
    ap.add_argument("--max-frames", type=int, default=0,
                    help="with --display ppm: stop the program after this many frames")
    ap.add_argument("guest_args", nargs="*",
                    help="arguments passed to the program (use -- before any that start with -)")
    return ap


def main(argv=None):
    args = build_parser().parse_intermixed_args(argv)  # options may appear anywhere

    with open(args.elf, "rb") as f:
        data = f.read()
    try:
        image = parse_elf(data)
    except ElfError as e:
        print(f"orbemu: {e}", file=sys.stderr)
        return 2

    from .cpu import UnicornCpu  # imported late so the other modules work without unicorn
    cpu = UnicornCpu()
    base = DYN_BASE if image.position_independent else 0
    entry = load_image(image, data, cpu, base)
    stubs = StubTable(cpu, make_default_registry())
    report = apply_relocations(image, base, cpu, stubs)
    if report.missing:
        print("orbemu: imports with no Python implementation yet: "
              + ", ".join(pretty(m, stubs.registry) for m in report.missing), file=sys.stderr)
    if report.unsupported:
        print(f"orbemu: unsupported relocation types: {report.unsupported}", file=sys.stderr)

    rsp = build_initial_stack(cpu, image, [args.elf] + args.guest_args, base=base)
    cpu.set_reg("rsp", rsp)
    cpu.set_reg("rdi", rsp)  # FreeBSD-style entry: rdi points at argc/argv on the stack
    cpu.set_reg("rsi", 0)    # ... and rsi is the (absent) cleanup function
    if image.position_independent:
        try:
            setup_tls(cpu, image, base)
        except KeyError:
            print("orbemu: this Unicorn has no fs_base register; TLS not set up", file=sys.stderr)

    kernel = Kernel(cpu, abi=args.abi, root=args.root,
                    display_factory=make_display_factory(args),
                    pad_factory=make_pad_factory(args))
    kernel.stubs = stubs
    stubs.trace = args.trace_imports
    cpu.on_syscall(kernel.handle_syscall)

    try:
        status = cpu.run(entry, timeout=args.timeout)
        if status == "timeout":
            print(f"orbemu: stopped the program after {args.timeout:g} seconds (--timeout)", file=sys.stderr)
            return 0
    except KeyboardInterrupt:
        print("orbemu: interrupted", file=sys.stderr)
        return 130
    except RuntimeError as e:
        print(f"orbemu: {e}", file=sys.stderr)
        try:
            rip = cpu.get_reg("rip")
            if base:
                print(f"  rip is at image offset {rip - base:#x} (load base {base:#x})", file=sys.stderr)
        except Exception:
            pass
        if stubs.recent:
            print("  last imports called: " + ", ".join(stubs.recent), file=sys.stderr)
        return 1
    finally:
        stubs.report_failures()
        kernel.shutdown()
    return kernel.exit_code if kernel.exit_code is not None else 1


if __name__ == "__main__":
    sys.exit(main())
