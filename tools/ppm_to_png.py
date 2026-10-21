"""Convert the .ppm frames saved by `--display ppm` into .png files any image viewer can open.

Usage: python tools/ppm_to_png.py frames
"""
import os
import struct
import sys
import zlib


def read_ppm(path):
    with open(path, "rb") as f:
        data = f.read()
    magic, w, h, maxval, rest = data.split(None, 4)  # "P6", width, height, 255, then pixels
    if magic != b"P6" or maxval != b"255":
        raise ValueError(f"{path}: not a binary 8-bit PPM")
    w, h = int(w), int(h)
    return w, h, rest[:w * h * 3]


def write_png(path, w, h, rgb):
    def chunk(tag, body):
        return (struct.pack(">I", len(body)) + tag + body
                + struct.pack(">I", zlib.crc32(tag + body) & 0xFFFFFFFF))

    rows = b"".join(b"\x00" + rgb[y * w * 3:(y + 1) * w * 3] for y in range(h))
    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n")
        f.write(chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)))
        f.write(chunk(b"IDAT", zlib.compress(rows)))
        f.write(chunk(b"IEND", b""))


def main(folder):
    count = 0
    for name in sorted(os.listdir(folder)):
        if name.lower().endswith(".ppm"):
            w, h, rgb = read_ppm(os.path.join(folder, name))
            write_png(os.path.join(folder, name[:-4] + ".png"), w, h, rgb)
            count += 1
    print(f"converted {count} frame(s) in {folder}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
