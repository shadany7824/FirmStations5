"""PlayStation system functions, answered by Python: the controller, user service and a few others.

Structure layouts come from the OpenOrbis toolchain's headers (include/orbis/_types/pad.h); the
offsets below were computed by compiling those definitions.
"""
import struct
import time as _time

from .hle_util import read_cstr, stdout_write
from .pad import PadState

# OrbisPadData is 120 bytes
PAD_DATA_SIZE = 120
PAD_OFF_BUTTONS, PAD_OFF_STICKS, PAD_OFF_TRIGGERS = 0, 4, 8   # sticks: lx ly rx ry; triggers: l2 r2
PAD_OFF_QUAT, PAD_OFF_CONNECTED, PAD_OFF_TIMESTAMP = 12, 76, 80
# OrbisPadInformation is 28 bytes
PAD_INFO_SIZE = 28
PAD_HANDLE = 1
USER_ID = 1


def read_pad_state(k):
    pad = k.get_pad()
    return pad.poll() if pad is not None else PadState()


def fill_pad_data(k, ptr):
    """Write one OrbisPadData sample into guest memory."""
    st = read_pad_state(k)
    buf = bytearray(PAD_DATA_SIZE)
    struct.pack_into("<I", buf, PAD_OFF_BUTTONS, st.buttons)
    buf[PAD_OFF_STICKS:PAD_OFF_STICKS + 4] = bytes([st.lx, st.ly, st.rx, st.ry])
    buf[PAD_OFF_TRIGGERS:PAD_OFF_TRIGGERS + 2] = bytes([st.l2, st.r2])
    struct.pack_into("<4f", buf, PAD_OFF_QUAT, 0.0, 0.0, 0.0, 1.0)  # orientation: no rotation
    buf[PAD_OFF_CONNECTED] = st.connected
    struct.pack_into("<Q", buf, PAD_OFF_TIMESTAMP, int((_time.monotonic() - k._started) * 1e6))
    k.cpu.write(ptr, bytes(buf))


def register(r):
    for name in ("scePadInit", "scePadClose", "scePadResetLightBar", "scePadSetLightBar",
                 "sceUserServiceInitialize", "sceUserServiceTerminate",
                 "sceSystemServiceHideSplashScreen", "sceSysmoduleLoadModule"):
        r.function(name)(lambda k, *_: 0)

    @r.function("scePadOpen")
    def scePadOpen(k, user_id, kind, index, param, *_):
        return PAD_HANDLE

    r.function("scePadGetHandle")(lambda k, *_: PAD_HANDLE)

    @r.function("scePadReadState")
    def scePadReadState(k, handle, data, *_):
        fill_pad_data(k, data)
        return 0

    @r.function("scePadRead")
    def scePadRead(k, handle, data, count, *_):
        if count < 1:
            return 0
        fill_pad_data(k, data)
        return 1  # we always have exactly one fresh sample

    @r.function("scePadSetVibration")
    def scePadSetVibration(k, handle, param, *_):
        large, small = k.cpu.read(param, 2)  # OrbisPadVibeParam { lgMotor; smMotor; }
        pad = k.get_pad()
        if pad is not None:
            pad.rumble(large, small, 0)
        return 0

    @r.function("scePadGetControllerInformation")
    def scePadGetControllerInformation(k, handle, info, *_):
        connected = read_pad_state(k).connected
        # touchpadDensity, touchResolutionX/Y, stickDeadzoneL/R, connectionType, count, connected,
        # deviceClass, unknown[8]: typical DualShock 4 values
        k.cpu.write(info, struct.pack("<fHHBBBBii8s", 44.86, 1920, 942, 13, 13, 0, 1, connected, 0, bytes(8)))
        return 0

    @r.function("sceUserServiceGetInitialUser")
    def sceUserServiceGetInitialUser(k, out_ptr, *_):
        k.cpu.write(out_ptr, struct.pack("<i", USER_ID))
        return 0

    @r.function("sceKernelDebugOutText")
    def sceKernelDebugOutText(k, channel, text, *_):
        stdout_write(k, read_cstr(k.cpu, text))
        return 0
