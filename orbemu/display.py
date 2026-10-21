"""Where emulated frames go. A display receives raw 32-bit pixels (little-endian 0x00RRGGBB)."""
import os

# Keyboard bits returned by orbemu's input syscall (0x1001). Keep in sync with examples/orb.h.
KEY_UP, KEY_DOWN, KEY_LEFT, KEY_RIGHT, KEY_ACTION, KEY_ESCAPE = 1, 2, 4, 8, 16, 32

KEYSYMS = {
    "Up": KEY_UP, "w": KEY_UP, "Down": KEY_DOWN, "s": KEY_DOWN,
    "Left": KEY_LEFT, "a": KEY_LEFT, "Right": KEY_RIGHT, "d": KEY_RIGHT,
    "space": KEY_ACTION, "Return": KEY_ACTION, "Escape": KEY_ESCAPE,
}


class KeyState:
    """Tracks which mapped keys are currently held down."""

    def __init__(self):
        self.bits = 0

    @staticmethod
    def _bit(keysym):
        return KEYSYMS.get(keysym.lower() if len(keysym) == 1 else keysym, 0)

    def press(self, keysym):
        self.bits |= self._bit(keysym)

    def release(self, keysym):
        self.bits &= ~self._bit(keysym)

    def clear(self):
        self.bits = 0


def bgrx_to_rgb(raw):
    """Convert guest pixels (bytes B, G, R, unused per pixel) to packed RGB bytes."""
    n = len(raw) // 4
    rgb = bytearray(n * 3)
    rgb[0::3] = raw[2::4]
    rgb[1::3] = raw[1::4]
    rgb[2::3] = raw[0::4]
    return bytes(rgb)


class PpmDisplay:
    """Headless: saves every Nth frame as a .ppm image (viewable in most image tools)."""

    def __init__(self, directory="frames", every=30, max_frames=0):
        self.directory, self.every, self.count = directory, max(1, every), 0
        self.max_frames = max_frames  # 0 = unlimited; otherwise act as "closed" after this many
        os.makedirs(directory, exist_ok=True)

    def present(self, width, height, raw):
        if self.count % self.every == 0:
            path = os.path.join(self.directory, f"frame_{self.count:05d}.ppm")
            with open(path, "wb") as f:
                f.write(b"P6\n%d %d\n255\n" % (width, height))
                f.write(bgrx_to_rgb(raw))
        self.count += 1
        return bool(self.max_frames) and self.count >= self.max_frames

    def keys(self):
        return 0  # headless: no keyboard

    def pump(self):
        pass

    def close(self):
        pass


class TkDisplay:
    """A window built on tkinter (included with the standard Python installer on Windows)."""

    def __init__(self, scale=2):
        import tkinter as tk
        self.tk, self.scale, self.closed, self.image = tk, scale, False, None
        self.keystate = KeyState()
        self.root = tk.Tk()
        self.root.title("orbemu")
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.label = tk.Label(self.root, borderwidth=0)
        self.label.pack()
        self.root.bind("<KeyPress>", lambda e: self.keystate.press(e.keysym))
        self.root.bind("<KeyRelease>", lambda e: self.keystate.release(e.keysym))
        self.root.bind("<FocusOut>", lambda e: self.keystate.clear())  # avoid stuck keys
        self.root.focus_force()

    def keys(self):
        return self.keystate.bits

    def _on_close(self):
        self.closed = True
        self.root.destroy()

    def present(self, width, height, raw):
        if self.closed:
            return True
        ppm = b"P6 %d %d 255\n" % (width, height) + bgrx_to_rgb(raw)
        img = self.tk.PhotoImage(width=width, height=height, data=ppm, format="PPM")
        if self.scale > 1:
            img = img.zoom(self.scale)
        self.image = img  # keep a reference, or Tk drops the picture
        self.label.configure(image=img)
        self.root.update()
        return self.closed

    def pump(self):
        if not self.closed:
            self.root.update()

    def close(self):
        if not self.closed:
            self.closed = True
            self.root.destroy()
