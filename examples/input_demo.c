/* Interactive demo: move the square with arrow keys or WASD, hold space to go faster, Esc quits.
 * Build: gcc -static -nostdlib -no-pie -fno-pie -fno-stack-protector -fno-builtin \
 *        -fno-tree-loop-distribute-patterns -O1 -s -Wl,--build-id=none -o input_demo.elf input_demo.c
 * Run:   python -m orbemu examples/input_demo.elf
 */
#include "orb.h"
#include "gfx_draw.h"

#define PLAYER 44

static unsigned fb[GFX_W * GFX_H];

static int clamp(int v, int lo, int hi) { return v < lo ? lo : v > hi ? hi : v; }

static void step(int *px, int *py, long keys) {
    int speed = (keys & ORB_KEY_ACTION) ? 6 : 3;
    if (keys & ORB_KEY_LEFT)  *px -= speed;
    if (keys & ORB_KEY_RIGHT) *px += speed;
    if (keys & ORB_KEY_UP)    *py -= speed;
    if (keys & ORB_KEY_DOWN)  *py += speed;
    *px = clamp(*px, 0, GFX_W - PLAYER);
    *py = clamp(*py, 0, GFX_H - PLAYER);
}

static void hud_key(int x, int y, int on) {
    gfx_rect(fb, x, y, 10, 10, on ? 0xFFFF00 : 0x303030);
}

static void draw_frame(int t, int px, int py, long keys) {
    gfx_background(fb, t);
    hud_key(290, 8,  keys & ORB_KEY_UP);       /* a little d-pad that lights up */
    hud_key(278, 20, keys & ORB_KEY_LEFT);
    hud_key(290, 20, keys & ORB_KEY_DOWN);
    hud_key(302, 20, keys & ORB_KEY_RIGHT);
    gfx_rect(fb, px, py, PLAYER, PLAYER, 0x000000);
    gfx_rect(fb, px + 2, py + 2, PLAYER - 4, PLAYER - 4, 0xFFFFFF);
    gfx_rect(fb, px + 12, py + 12, 20, 20, (keys & ORB_KEY_ACTION) ? 0xFFE000 : 0xE02020);
}

__attribute__((force_align_arg_pointer)) void _start(void) {
    int px = (GFX_W - PLAYER) / 2, py = 70;
    for (int t = 0;; t++) {
        long keys = orb_input();
        if (keys & ORB_KEY_ESCAPE) break;
        step(&px, &py, keys);
        draw_frame(t, px, py, keys);
        if (orb_present(fb, GFX_W, GFX_H) != 0) break;   /* window closed (or no display) */
        orb_sleep_ms(16);
    }
    orb_exit(0);
}
