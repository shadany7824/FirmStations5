"""PlayStation video output and kernel memory functions, answered by Python.

Programs draw into memory they map with sceKernelAllocateDirectMemory / sceKernelMapDirectMemory,
register those buffers with sceVideoOutRegisterBuffers, and show one with sceVideoOutSubmitFlip. We
read the pixels out of emulated memory and hand them to the display window.

Structure layouts come from the OpenOrbis headers (include/orbis/_types/video.h). Pixel format
0x80002200 (A8B8G8R8) is from the header; 0x80000000 (A8R8G8B8) is from memory. Only linear
(non-tiled) buffers are understood. Event queues are minimal stand-ins: waiting just paces at 60 Hz.
"""
import struct
import sys
import time as _time

from .display import shrink_pixels
from .hle_util import stack_arg

PIXEL_A8B8G8R8 = 0x80002200
PIXEL_A8R8G8B8 = 0x80000000
TILING_TILE, TILING_LINEAR = 0, 1
MAX_FRAME_WIDTH = 960        # frames wider than this are shrunk (1920x1080 -> 960x540) before display
FRAME_SECONDS = 1 / 60
VIDEO_HANDLE = 1
DMEM_TOTAL = 0x140000000     # 5 GiB of "direct memory"
PAGE = 0x4000                # PlayStation pages are 16 KB
MAP_FIXED, MAP_ANON = 0x10, 0x1000
SCE_ENOMEM, SCE_EINVAL = 0x8002000C, 0x80020016


def _state(k):
    return k.hle_state.setdefault("video", {"buffers": {}, "attr": None, "flips": 0, "flip_arg": 0,
                                            "current": -1, "last_flip": 0.0, "warned": set()})


def _pace(st):
    """Sleep until the next 60 Hz frame boundary, like waiting for vsync."""
    wait = FRAME_SECONDS - (_time.monotonic() - st["last_flip"])
    if wait > 0:
        _time.sleep(wait)
    st["last_flip"] = _time.monotonic()


def frame_for_display(raw, width, height, pitch, pixel_format):
    """Guest pixels -> (width, height, BGRx bytes) for the display."""
    stride, row = pitch * 4, width * 4
    if pitch != width:
        raw = b"".join(raw[y * stride:y * stride + row] for y in range(height))
    factor = -(-width // MAX_FRAME_WIDTH)
    width, height, raw = shrink_pixels(raw, width, height, factor)
    if pixel_format != PIXEL_A8R8G8B8:   # A8B8G8R8 stores R,G,B,A in memory; the display wants B,G,R,x
        swapped = bytearray(raw)
        swapped[0::4] = raw[2::4]
        swapped[2::4] = raw[0::4]
        raw = bytes(swapped)
    return width, height, raw


def register(r):
    # ---------------- direct memory ----------------
    @r.function("sceKernelGetDirectMemorySize")
    def sceKernelGetDirectMemorySize(k, *_):
        return DMEM_TOTAL

    @r.function("sceKernelAvailableDirectMemorySize")
    def sceKernelAvailableDirectMemorySize(k, start, end, alignment, phys_ptr, size_ptr, *_):
        st = k.hle_state.setdefault("dmem", {"next": 0x10000})
        k.cpu.write(phys_ptr, struct.pack("<q", st["next"]))
        k.cpu.write(size_ptr, struct.pack("<Q", DMEM_TOTAL - st["next"]))
        return 0

    @r.function("sceKernelAllocateDirectMemory")
    def sceKernelAllocateDirectMemory(k, start, end, length, alignment, mem_type, phys_ptr):
        st = k.hle_state.setdefault("dmem", {"next": 0x10000})
        align = max(alignment, PAGE)
        phys = (st["next"] + align - 1) & ~(align - 1)
        size = (length + PAGE - 1) & ~(PAGE - 1)
        if size == 0 or phys + size > DMEM_TOTAL:
            return SCE_ENOMEM
        st["next"] = phys + size
        k.cpu.write(phys_ptr, struct.pack("<q", phys))   # the "physical address" of the new block
        return 0

    def map_direct(k, addr_ptr, length, prot, flags, alignment):
        wanted = struct.unpack("<Q", k.cpu.read(addr_ptr, 8))[0]
        perms = (prot & 7) or 3                    # always give the CPU read+write access
        if flags & MAP_FIXED and wanted:
            size = (length + PAGE - 1) & ~(PAGE - 1)
            k.cpu.map(wanted, size, perms)
            base = wanted
        else:
            base = k.alloc_anon(length, perms, max(alignment, PAGE))
            if base < 0:
                return SCE_ENOMEM
        k.cpu.write(addr_ptr, struct.pack("<Q", base))
        return 0

    @r.function("sceKernelMapDirectMemory")
    def sceKernelMapDirectMemory(k, addr_ptr, length, prot, flags, phys, alignment):
        return map_direct(k, addr_ptr, length, prot, flags, alignment)

    @r.function("sceKernelMapNamedDirectMemory")
    def sceKernelMapNamedDirectMemory(k, addr_ptr, length, prot, flags, phys, alignment):
        return map_direct(k, addr_ptr, length, prot, flags, alignment)   # the 7th argument is just a name

    @r.function("sceKernelMapDirectMemory2")
    def sceKernelMapDirectMemory2(k, addr_ptr, length, mem_type, prot, flags, phys):
        return map_direct(k, addr_ptr, length, prot, flags, stack_arg(k, 0))  # alignment is the 7th argument

    r.function("sceKernelReleaseDirectMemory")(lambda k, *_: 0)

    @r.function("sceKernelMmap")
    def sceKernelMmap(k, addr, length, prot, flags, fd, offset):
        result_ptr = stack_arg(k, 0)                                          # 7th argument: where to put the address
        if not flags & MAP_ANON:
            return SCE_EINVAL
        base = k.alloc_anon(length, (prot & 7) or 3, PAGE)
        if base < 0:
            return SCE_ENOMEM
        k.cpu.write(result_ptr, struct.pack("<Q", base))
        return 0

    # ---------------- video out ----------------
    r.function("sceVideoOutOpen")(lambda k, *_: VIDEO_HANDLE)
    for name in ("sceVideoOutClose", "sceVideoOutSetFlipRate", "sceVideoOutAddFlipEvent",
                 "sceVideoOutIsFlipPending"):
        r.function(name)(lambda k, *_: 0)

    @r.function("sceVideoOutSetBufferAttribute")
    def sceVideoOutSetBufferAttribute(k, attr_ptr, pixel_format, tiling, aspect, width, height):
        pitch = stack_arg(k, 0) & 0xFFFFFFFF      # the 7th argument travels on the stack
        k.cpu.write(attr_ptr, struct.pack("<IIIIII16s", pixel_format, tiling, aspect, width, height, pitch, bytes(16)))
        return 0

    @r.function("sceVideoOutRegisterBuffers")
    def sceVideoOutRegisterBuffers(k, handle, start, addrs_ptr, count, attr_ptr):
        st = _state(k)
        fmt, tiling, _aspect, width, height, pitch = struct.unpack("<IIIIII", k.cpu.read(attr_ptr, 24))
        if tiling == TILING_TILE and "tile" not in st["warned"]:
            st["warned"].add("tile")
            print("[video] the program uses a tiled (GPU-layout) framebuffer, which orbemu cannot "
                  "show correctly yet; expect a scrambled picture", file=sys.stderr)
        for i in range(count):
            st["buffers"][start + i] = struct.unpack("<Q", k.cpu.read(addrs_ptr + 8 * i, 8))[0]
        st["attr"] = (fmt, tiling, width, height, pitch)
        return 0

    @r.function("sceVideoOutUnregisterBuffers")
    def sceVideoOutUnregisterBuffers(k, handle, index, *_):
        _state(k)["buffers"].pop(index, None)
        return 0

    @r.function("sceVideoOutSubmitFlip")
    def sceVideoOutSubmitFlip(k, handle, index, mode, flip_arg):
        st = _state(k)
        addr = st["buffers"].get(index)
        if st["attr"] is None or addr is None:
            return SCE_EINVAL
        fmt, _tiling, width, height, pitch = st["attr"]
        display = k.get_display()
        st["flips"] += 1
        st["flip_arg"] = flip_arg - (1 << 64) if flip_arg >= 1 << 63 else flip_arg
        st["current"] = index
        if display is not None:
            raw = k.cpu.read(addr, pitch * 4 * height)
            w, h, frame = frame_for_display(raw, width, height, pitch, fmt)
            closed = display.present(w, h, frame)
            if closed:
                k.sys_exit(0)    # closing the window ends the program
        _pace(st)
        return 0

    @r.function("sceVideoOutGetFlipStatus")
    def sceVideoOutGetFlipStatus(k, handle, status_ptr, *_):
        st = _state(k)
        micros = int((_time.monotonic() - k._started) * 1e6)
        k.cpu.write(status_ptr, struct.pack("<QQQq16siiiI", st["flips"], micros, micros, st["flip_arg"],
                                            bytes(16), 0, 0, st["current"], 0))
        return 0

    @r.function("sceVideoOutGetResolutionStatus")
    def sceVideoOutGetResolutionStatus(k, handle, status_ptr, *_):
        # width, height, paneWidth, paneHeight, refreshRate, screenSize, flags, reserved0, reserved1[3]
        k.cpu.write(status_ptr, struct.pack("<IIIIQfHH12s4x", 1920, 1080, 1920, 1080, 3, 0.0, 0, 0, bytes(12)))
        return 0

    @r.function("sceVideoOutWaitVblank")
    def sceVideoOutWaitVblank(k, *_):
        _pace(_state(k))
        return 0

    # ---------------- event queues (minimal) ----------------
    @r.function("sceKernelCreateEqueue")
    def sceKernelCreateEqueue(k, eq_ptr, name, *_):
        k.cpu.write(eq_ptr, struct.pack("<Q", 1))
        return 0

    r.function("sceKernelDeleteEqueue")(lambda k, *_: 0)

    @r.function("sceKernelWaitEqueue")
    def sceKernelWaitEqueue(k, eq, events_ptr, count, out_ptr, timeout_ptr):
        _pace(_state(k))                       # the only event we have is "a frame passed"
        if events_ptr and count >= 1:
            k.cpu.write(events_ptr, bytes(32))
        if out_ptr:
            k.cpu.write(out_ptr, struct.pack("<i", 1))
        return 0
