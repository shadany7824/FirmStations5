/* PS4 homebrew framebuffer test (OpenOrbis toolchain; runs in orbemu).
 *
 * Draws a square into a 1920x1080 framebuffer and moves it with the controller: left stick or d-pad
 * moves, Cross / Circle / Square / Triangle change its colour, holding Cross vibrates the pad,
 * Options quits. Uses two frame buffers (double buffering): each frame only the square is erased
 * and redrawn, so it stays fast in an emulator.
 *
 * Build:  .\examples\ps4\build_ps4.ps1 -Source examples\ps4\fb_test -Name fb_test `
 *            -Libs "-lc -lkernel -lc++ -lScePad -lSceUserService -lSceVideoOut"
 * Run:    python -m orbemu examples\ps4\fb_test\x64\Debug\fb_test.oelf --timeout 120
 */
#include <stdio.h>
#include <orbis/Pad.h>
#include <orbis/VideoOut.h>

extern "C" {
int sceUserServiceInitialize(void *params);
int sceUserServiceGetInitialUser(int *userId);
int sceKernelUsleep(unsigned int microseconds);
unsigned long sceKernelGetDirectMemorySize();
int sceKernelAllocateDirectMemory(long long searchStart, long long searchEnd, unsigned long length,
                                  unsigned long alignment, int type, long long *physOut);
int sceKernelMapDirectMemory(void **addr, unsigned long length, int prot, int flags,
                             long long start, unsigned long alignment);
}

static const int W = 1920, H = 1080, SQ = 160, BORDER = 6;
static const unsigned long FRAME_BYTES = (unsigned long)W * H * 4;
static const int KERNEL_WC_GARLIC = 3;          /* memory type the GPU/display reads */
static const int PROT_CPU_GPU_RW = 0x33;        /* CPU read+write, GPU read+write */

static unsigned int *buffers[2];
static OrbisPadData pad;

/* A8B8G8R8: red in the lowest byte */
static unsigned int rgb(unsigned r, unsigned g, unsigned b) {
    return 0xFF000000u | (b << 16) | (g << 8) | r;
}

static unsigned int background(int y) {         /* a vertical gradient: depends only on the row */
    return rgb(20 + (y * 40) / H, 30 + (y * 60) / H, 90 + (y * 100) / H);
}

static void fill_rows(unsigned int *buf, int x, int y, int w, int h, unsigned int color, bool erase) {
    for (int row = y; row < y + h; row++) {
        if (row < 0 || row >= H) continue;
        unsigned int c = erase ? background(row) : color;
        for (int col = x; col < x + w; col++)
            if (col >= 0 && col < W) buf[row * W + col] = c;
    }
}

static int clamp(int v, int lo, int hi) { return v < lo ? lo : v > hi ? hi : v; }

static int stick_speed(int v) {                 /* 0..255, 128 centred; dead zone of +-16 */
    int d = v - 128;
    return (d > -16 && d < 16) ? 0 : d / 8;
}

int main() {
    int user = 0;
    sceUserServiceInitialize(NULL);
    sceUserServiceGetInitialUser(&user);
    scePadInit();
    int pad_handle = scePadOpen(user, 0, 0, NULL);
    int video = sceVideoOutOpen(ORBIS_VIDEO_USER_MAIN, ORBIS_VIDEO_OUT_BUS_MAIN, 0, NULL);

    /* two frame buffers in one block of direct memory */
    unsigned long total = 2 * FRAME_BYTES;
    long long phys = 0;
    sceKernelAllocateDirectMemory(0, (long long)sceKernelGetDirectMemorySize(), total, 0x200000,
                                  KERNEL_WC_GARLIC, &phys);
    void *memory = NULL;
    sceKernelMapDirectMemory(&memory, total, PROT_CPU_GPU_RW, 0, phys, 0x200000);
    buffers[0] = (unsigned int *)memory;
    buffers[1] = (unsigned int *)((char *)memory + FRAME_BYTES);

    OrbisVideoOutBufferAttribute attr;
    sceVideoOutSetBufferAttribute(&attr, ORBIS_VIDEO_OUT_PIXEL_FORMAT_A8B8G8R8_SRGB,
                                  ORBIS_VIDEO_OUT_TILING_MODE_LINEAR, ORBIS_VIDEO_OUT_ASPECT_RATIO_16_9,
                                  W, H, W);
    sceVideoOutRegisterBuffers(video, 0, (void * const *)buffers, 2, &attr);
    printf("fb_test: video handle %d, pad handle %d, buffers at %p and %p\n", video, pad_handle,
           (void *)buffers[0], (void *)buffers[1]);

    for (int b = 0; b < 2; b++)                 /* paint the background once per buffer */
        fill_rows(buffers[b], 0, 0, W, H, 0, true);

    int px = (W - SQ) / 2, py = (H - SQ) / 2;
    int last_x[2] = {-1, -1}, last_y[2] = {-1, -1};
    unsigned int color = rgb(230, 230, 230);
    unsigned char last_large = 0;
    int back = 0;

    for (;;) {
        scePadReadState(pad_handle, &pad);
        int dx = stick_speed(pad.leftStick.x), dy = stick_speed(pad.leftStick.y);
        if (pad.buttons & ORBIS_PAD_BUTTON_LEFT)  dx -= 12;
        if (pad.buttons & ORBIS_PAD_BUTTON_RIGHT) dx += 12;
        if (pad.buttons & ORBIS_PAD_BUTTON_UP)    dy -= 12;
        if (pad.buttons & ORBIS_PAD_BUTTON_DOWN)  dy += 12;
        px = clamp(px + dx, 0, W - SQ);
        py = clamp(py + dy, 0, H - SQ);
        if (pad.buttons & ORBIS_PAD_BUTTON_CROSS)    color = rgb(60, 120, 240);
        if (pad.buttons & ORBIS_PAD_BUTTON_CIRCLE)   color = rgb(230, 60, 60);
        if (pad.buttons & ORBIS_PAD_BUTTON_SQUARE)   color = rgb(230, 120, 200);
        if (pad.buttons & ORBIS_PAD_BUTTON_TRIANGLE) color = rgb(70, 210, 90);

        /* this buffer still shows the square from two frames ago: erase that, draw the new one */
        if (last_x[back] >= 0) fill_rows(buffers[back], last_x[back], last_y[back], SQ, SQ, 0, true);
        fill_rows(buffers[back], px, py, SQ, SQ, rgb(10, 10, 20), false);
        fill_rows(buffers[back], px + BORDER, py + BORDER, SQ - 2 * BORDER, SQ - 2 * BORDER, color, false);
        last_x[back] = px;
        last_y[back] = py;

        sceVideoOutSubmitFlip(video, back, ORBIS_VIDEO_OUT_FLIP_VSYNC, 0);
        back ^= 1;

        unsigned char large = (pad.buttons & ORBIS_PAD_BUTTON_CROSS) ? 255 : 0;
        if (large != last_large) {
            OrbisPadVibeParam vibe;
            vibe.lgMotor = large;
            vibe.smMotor = 0;
            scePadSetVibration(pad_handle, &vibe);
            last_large = large;
        }
        if (pad.buttons & ORBIS_PAD_BUTTON_OPTIONS) break;
    }
    sceVideoOutClose(video);
    scePadClose(pad_handle);
    printf("fb_test: bye\n");
    return 0;
}
