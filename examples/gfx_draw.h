/* gfx_draw.h: integer-only drawing code (no libc), shared by the guest demo and a host preview. */
#ifndef GFX_DRAW_H
#define GFX_DRAW_H

#define GFX_W 320
#define GFX_H 200

static unsigned gfx_rgb(int r, int g, int b) {
    return ((unsigned)(r & 255) << 16) | ((unsigned)(g & 255) << 8) | (unsigned)(b & 255);
}

/* Triangle wave: bounces between 0 and max as t grows. */
static int gfx_tri(int t, int max) {
    int m = t % (2 * max);
    return m < max ? m : 2 * max - m;
}

static void gfx_rect(unsigned *fb, int x0, int y0, int rw, int rh, unsigned c) {
    for (int y = y0; y < y0 + rh; y++) {
        if (y < 0 || y >= GFX_H) continue;
        for (int x = x0; x < x0 + rw; x++)
            if (x >= 0 && x < GFX_W) fb[y * GFX_W + x] = c;
    }
}

/* 5x7 bitmap letters: O R B E M U */
static const unsigned char gfx_font[6][7] = {
    {0x0E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E},
    {0x1E, 0x11, 0x11, 0x1E, 0x14, 0x12, 0x11},
    {0x1E, 0x11, 0x11, 0x1E, 0x11, 0x11, 0x1E},
    {0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x1F},
    {0x11, 0x1B, 0x15, 0x15, 0x11, 0x11, 0x11},
    {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E},
};

static void gfx_text(unsigned *fb, int x, int y, int scale, unsigned c) {
    for (int ch = 0; ch < 6; ch++)
        for (int row = 0; row < 7; row++)
            for (int col = 0; col < 5; col++)
                if (gfx_font[ch][row] & (16 >> col))
                    gfx_rect(fb, x + (ch * 6 + col) * scale, y + row * scale, scale, scale, c);
}

static void gfx_background(unsigned *fb, int t) {
    int ph = (t * 3) % 512;
    int blue = ph < 256 ? ph : 511 - ph;
    for (int y = 0; y < GFX_H; y++)
        for (int x = 0; x < GFX_W; x++)
            fb[y * GFX_W + x] = gfx_rgb(x * 255 / GFX_W, y * 255 / GFX_H, blue);

    static const unsigned palette[8] = {0xFFFFFF, 0xFFFF00, 0x00FFFF, 0x00FF00,
                                        0xFF00FF, 0xFF0000, 0x0000FF, 0x202020};
    for (int i = 0; i < 8; i++) gfx_rect(fb, i * 40, 170, 40, 30, palette[i]);

    gfx_text(fb, 22, 22, 4, gfx_rgb(0, 0, 0));
    gfx_text(fb, 20, 20, 4, gfx_rgb(255, 255, 255));
}

static void gfx_bouncer(unsigned *fb, int t) {
    int px = gfx_tri(t * 2, GFX_W - 44);
    int py = 60 + gfx_tri(t * 3 / 2, 66);
    gfx_rect(fb, px, py, 44, 44, 0x000000);
    gfx_rect(fb, px + 2, py + 2, 40, 40, 0xFFFFFF);
    gfx_rect(fb, px + 12, py + 12, 20, 20, gfx_rgb(255 - px * 255 / GFX_W, 80, py));
}

static void gfx_draw(unsigned *fb, int t) {
    gfx_background(fb, t);
    gfx_bouncer(fb, t);
}

#endif
