"""Game controller support. Button bits follow the PS4's own pad API (ORBIS_PAD_BUTTON_*),
so a future PS4 emulation layer can reuse them. Sticks are 0..255 with 128 = centered,
y = 0 at the top. Triggers are 0..255.

The real controller is read through pygame (pip install pygame), which uses SDL's game
controller mapping, so a PS4 controller is recognised over USB or Bluetooth.
"""
import os
import struct
import time
from dataclasses import dataclass

BTN_L3, BTN_R3, BTN_OPTIONS = 0x2, 0x4, 0x8
BTN_UP, BTN_RIGHT, BTN_DOWN, BTN_LEFT = 0x10, 0x20, 0x40, 0x80
BTN_L2, BTN_R2, BTN_L1, BTN_R1 = 0x100, 0x200, 0x400, 0x800
BTN_TRIANGLE, BTN_CIRCLE, BTN_CROSS, BTN_SQUARE = 0x1000, 0x2000, 0x4000, 0x8000
BTN_TOUCHPAD = 0x100000

# SDL "game controller" names -> bit. On a PS4 pad: A=Cross, B=Circle, X=Square, Y=Triangle.
BUTTON_MAP = (
    ("CONTROLLER_BUTTON_A", BTN_CROSS), ("CONTROLLER_BUTTON_B", BTN_CIRCLE),
    ("CONTROLLER_BUTTON_X", BTN_SQUARE), ("CONTROLLER_BUTTON_Y", BTN_TRIANGLE),
    ("CONTROLLER_BUTTON_LEFTSHOULDER", BTN_L1), ("CONTROLLER_BUTTON_RIGHTSHOULDER", BTN_R1),
    ("CONTROLLER_BUTTON_LEFTSTICK", BTN_L3), ("CONTROLLER_BUTTON_RIGHTSTICK", BTN_R3),
    ("CONTROLLER_BUTTON_START", BTN_OPTIONS),
    ("CONTROLLER_BUTTON_DPAD_UP", BTN_UP), ("CONTROLLER_BUTTON_DPAD_DOWN", BTN_DOWN),
    ("CONTROLLER_BUTTON_DPAD_LEFT", BTN_LEFT), ("CONTROLLER_BUTTON_DPAD_RIGHT", BTN_RIGHT),
    ("CONTROLLER_BUTTON_TOUCHPAD", BTN_TOUCHPAD),  # only on newer SDL; skipped if missing
)
TRIGGER_PRESSED = 30  # analog trigger value above which L2/R2 also count as buttons


@dataclass
class PadState:
    buttons: int = 0
    lx: int = 128
    ly: int = 128
    rx: int = 128
    ry: int = 128
    l2: int = 0
    r2: int = 0
    connected: int = 0


def axis_to_u8(value):
    """SDL stick axis (-32768..32767) -> 0..255 with 128 in the middle."""
    return max(0, min(255, (value + 32768) >> 8))


def trigger_to_u8(value):
    """SDL trigger axis (0..32767) -> 0..255."""
    return max(0, min(255, value >> 7))


def pack_state(state, timestamp_ms):
    """The 16-byte structure the guest receives (see struct orb_pad_state in orb.h)."""
    return struct.pack("<I8BI", state.buttons, state.lx, state.ly, state.rx, state.ry,
                       state.l2, state.r2, state.connected, 0, timestamp_ms & 0xFFFFFFFF)


class NullPad:
    """No controller support: always reports 'not connected'."""

    def poll(self):
        return PadState()

    def close(self):
        pass


class PygamePad:
    def __init__(self, pygame=None, controller=None):
        if pygame is None:
            # Without this, SDL ignores the pad while its own (non-existent) window is unfocused.
            os.environ.setdefault("SDL_JOYSTICK_ALLOW_BACKGROUND_EVENTS", "1")
            os.environ.setdefault("PYGAME_HIDE_SUPPORT_PROMPT", "1")
            import pygame
            from pygame._sdl2 import controller
        self.pg, self.ctl = pygame, controller
        pygame.display.init()  # opens no window, but pygame.event.pump() needs it
        controller.init()
        controller.set_eventstate(True)
        self.ctrl = None
        self._last_scan = float("-inf")

    def _open_first(self):
        for i in range(self.ctl.get_count()):
            if self.ctl.is_controller(i):
                try:
                    return self.ctl.Controller(i)
                except Exception:
                    continue
        return None

    def poll(self):
        pg = self.pg
        pg.event.pump()
        pg.event.clear()  # we read state directly; don't let events pile up
        if self.ctrl is not None and not self.ctrl.attached():
            self.ctrl = None  # unplugged
        if self.ctrl is None and time.monotonic() - self._last_scan > 1.0:
            self._last_scan = time.monotonic()
            self.ctrl = self._open_first()  # (re)connect
        c = self.ctrl
        if c is None:
            return PadState()
        buttons = 0
        for name, bit in BUTTON_MAP:
            const = getattr(pg, name, None)
            if const is not None and c.get_button(const):
                buttons |= bit
        l2 = trigger_to_u8(c.get_axis(pg.CONTROLLER_AXIS_TRIGGERLEFT))
        r2 = trigger_to_u8(c.get_axis(pg.CONTROLLER_AXIS_TRIGGERRIGHT))
        if l2 > TRIGGER_PRESSED:
            buttons |= BTN_L2
        if r2 > TRIGGER_PRESSED:
            buttons |= BTN_R2
        return PadState(
            buttons=buttons,
            lx=axis_to_u8(c.get_axis(pg.CONTROLLER_AXIS_LEFTX)),
            ly=axis_to_u8(c.get_axis(pg.CONTROLLER_AXIS_LEFTY)),
            rx=axis_to_u8(c.get_axis(pg.CONTROLLER_AXIS_RIGHTX)),
            ry=axis_to_u8(c.get_axis(pg.CONTROLLER_AXIS_RIGHTY)),
            l2=l2, r2=r2, connected=1)

    def close(self):
        try:
            self.ctl.quit()
        except Exception:
            pass
