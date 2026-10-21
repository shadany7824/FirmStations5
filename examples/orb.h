/* orb.h: orbemu's custom syscalls for freestanding guest programs (Linux x86-64 ABI). */
#ifndef ORB_H
#define ORB_H

#define ORB_SYS_NANOSLEEP 35
#define ORB_SYS_EXIT 60
#define ORB_SYS_PRESENT 0x1000
#define ORB_SYS_INPUT 0x1001
#define ORB_SYS_PAD 0x1002

/* Bits returned by orb_input(). */
#define ORB_KEY_UP 1
#define ORB_KEY_DOWN 2
#define ORB_KEY_LEFT 4
#define ORB_KEY_RIGHT 8
#define ORB_KEY_ACTION 16   /* space or enter */
#define ORB_KEY_ESCAPE 32

/* Controller buttons: the same bit values as the PS4's ORBIS_PAD_BUTTON_* constants. */
#define ORB_PAD_L3 0x2
#define ORB_PAD_R3 0x4
#define ORB_PAD_OPTIONS 0x8
#define ORB_PAD_UP 0x10
#define ORB_PAD_RIGHT 0x20
#define ORB_PAD_DOWN 0x40
#define ORB_PAD_LEFT 0x80
#define ORB_PAD_L2 0x100
#define ORB_PAD_R2 0x200
#define ORB_PAD_L1 0x400
#define ORB_PAD_R1 0x800
#define ORB_PAD_TRIANGLE 0x1000
#define ORB_PAD_CIRCLE 0x2000
#define ORB_PAD_CROSS 0x4000
#define ORB_PAD_SQUARE 0x8000
#define ORB_PAD_TOUCHPAD 0x100000

/* What orb_pad() fills in. Sticks: 0..255, 128 = centered, y = 0 at the top. Triggers: 0..255. */
struct orb_pad_state {
    unsigned int buttons;
    unsigned char lx, ly, rx, ry;
    unsigned char l2, r2;
    unsigned char connected;   /* 1 if a controller is attached */
    unsigned char reserved;
    unsigned int timestamp_ms;
};
typedef char orb_pad_state_must_be_16_bytes[sizeof(struct orb_pad_state) == 16 ? 1 : -1];

static long orb_syscall(long n, long a, long b, long c) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return r;
}

/* Show width*height 32-bit 0x00RRGGBB pixels. Returns 0, or nonzero if the window closed. */
static long orb_present(const void *pixels, int w, int h) {
    return orb_syscall(ORB_SYS_PRESENT, (long)pixels, w, h);
}

/* Keys currently held (ORB_KEY_* bits); 0 if there is no keyboard. */
static long orb_input(void) {
    long k = orb_syscall(ORB_SYS_INPUT, 0, 0, 0);
    return k < 0 ? 0 : k;
}

/* Read the controller. Without one (or without pygame), connected is 0 and the sticks are centered. */
static void orb_pad(struct orb_pad_state *out) {
    if (orb_syscall(ORB_SYS_PAD, (long)out, 0, 0) != 0) {
        out->buttons = 0;
        out->lx = out->ly = out->rx = out->ry = 128;
        out->l2 = out->r2 = out->connected = out->reserved = 0;
        out->timestamp_ms = 0;
    }
}

static void orb_sleep_ms(long ms) {
    long ts[2] = {ms / 1000, (ms % 1000) * 1000000};
    orb_syscall(ORB_SYS_NANOSLEEP, (long)ts, 0, 0);
}

static void orb_exit(int code) {
    orb_syscall(ORB_SYS_EXIT, code, 0, 0);
    for (;;) {}
}

#endif
