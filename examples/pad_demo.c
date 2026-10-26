/* Controller demo: left stick or d-pad moves the square (keyboard works too);
 * Cross/Circle/Square/Triangle change its color; L2/R2 show as bars and make the controller
 * vibrate (R2 = heavy motor, L2 = light motor); Options or Esc quits.
 * Build: gcc -static -nostdlib -no-pie -fno-pie -fno-stack-protector -fno-builtin \
 *        -fno-tree-loop-distribute-patterns -O1 -s -Wl,--build-id=none -o pad_demo.elf pad_demo.c
 * Run:   python -m orbemu examples/pad_demo.elf     (needs: python -m pip install pygame)
 */
#include "orb.h"
#include "gfx_draw.h"

#define PLAYER 44

static unsigned fb[GFX_W * GFX_H];

static int clamp(int v, int lo, int hi) { return v < lo ? lo : v > hi ? hi : v; }

/* Stick value (0..255, 128 = centered) -> speed in pixels per frame, with a dead zone. */
static int stick_speed(int v) {
    int d = v - 128;
    return (d > -16 && d < 16) ? 0 : d / 20;
}

static void step(int *px, int *py, const struct orb_pad_state *pad, long keys) {
    int dx = stick_speed(pad->lx), dy = stick_speed(pad->ly);
    if (pad->buttons & ORB_PAD_LEFT)  dx -= 3;
    if (pad->buttons & ORB_PAD_RIGHT) dx += 3;
    if (pad->buttons & ORB_PAD_UP)    dy -= 3;
    if (pad->buttons & ORB_PAD_DOWN)  dy += 3;
    if (keys & ORB_KEY_LEFT)  dx -= 3;
    if (keys & ORB_KEY_RIGHT) dx += 3;
    if (keys & ORB_KEY_UP)    dy -= 3;
    if (keys & ORB_KEY_DOWN)  dy += 3;
    *px = clamp(*px + dx, 0, GFX_W - PLAYER);
    *py = clamp(*py + dy, 0, GFX_H - PLAYER);
}

static unsigned face_color(unsigned buttons) {
    if (buttons & ORB_PAD_TRIANGLE) return 0x40D040;
    if (buttons & ORB_PAD_CIRCLE)   return 0xE03030;
    if (buttons & ORB_PAD_CROSS)    return 0x3070E0;
    if (buttons & ORB_PAD_SQUARE)   return 0xE070C0;
    return 0x404040;
}

/* Vibration follows the triggers, with a small dead zone so a resting finger does nothing. */
static void vibration_for(const struct orb_pad_state *pad, int *large, int *small) {
    *large = pad->r2 > 20 ? pad->r2 : 0;
    *small = pad->l2 > 20 ? pad->l2 : 0;
}

static void stick_box(int x, int y, int sx, int sy) {   /* shows where a stick is pointing */
    gfx_rect(fb, x, y, 36, 36, 0x202020);
    gfx_rect(fb, x + 15 + (sx - 128) * 15 / 128, y + 15 + (sy - 128) * 15 / 128, 6, 6, 0xFFFFFF);
}

static void trigger_bar(int x, int value) {
    gfx_rect(fb, x, 85, 8, 80, 0x202020);
    int h = value * 80 / 255;
    gfx_rect(fb, x, 165 - h, 8, h, 0xFFFFFF);
}

static void draw_frame(int t, int px, int py, const struct orb_pad_state *pad) {
    gfx_background(fb, t);
    gfx_rect(fb, 300, 8, 12, 12, pad->connected ? 0x00D000 : 0xD00000);  /* green = pad found */
    stick_box(20, 125, pad->lx, pad->ly);
    stick_box(264, 125, pad->rx, pad->ry);
    trigger_bar(4, pad->l2);
    trigger_bar(308, pad->r2);
    gfx_rect(fb, px, py, PLAYER, PLAYER, 0x000000);
    gfx_rect(fb, px + 2, py + 2, PLAYER - 4, PLAYER - 4, 0xFFFFFF);
    gfx_rect(fb, px + 12, py + 12, 20, 20, face_color(pad->buttons));
}

__attribute__((force_align_arg_pointer)) void _start(void) {
    struct orb_pad_state pad;
    int px = (GFX_W - PLAYER) / 2, py = 70;
    int last_large = 0, last_small = 0;
    for (int t = 0;; t++) {
        long keys = orb_input();
        orb_pad(&pad);
        if ((keys & ORB_KEY_ESCAPE) || (pad.buttons & ORB_PAD_OPTIONS)) break;
        int large, small;
        vibration_for(&pad, &large, &small);
        /* Only talk to the controller when something changed (plus a refresh every 30 s). */
        if (pad.connected && (large != last_large || small != last_small
                              || ((large || small) && t % 1800 == 0))) {
            orb_pad_vibrate(large, small, 0);
            last_large = large;
            last_small = small;
        }
        step(&px, &py, &pad, keys);
        draw_frame(t, px, py, &pad);
        if (orb_present(fb, GFX_W, GFX_H) != 0) break;
        orb_sleep_ms(16);
    }
    orb_pad_vibrate(0, 0, 0);   /* make sure it stops */
    orb_exit(0);
}
