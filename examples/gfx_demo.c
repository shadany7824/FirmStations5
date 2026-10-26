/* Graphics demo: draws an animated frame and hands it to orbemu with the custom syscall 0x1000.
 * Build: gcc -static -nostdlib -no-pie -fno-pie -fno-stack-protector -fno-builtin \
 *        -fno-tree-loop-distribute-patterns -O1 -s -Wl,--build-id=none -o gfx_demo.elf gfx_demo.c
 * Run:   python -m orbemu examples/gfx_demo.elf
 */
#include "gfx_draw.h"

#define SYS_NANOSLEEP 35
#define SYS_EXIT 60
#define ORB_PRESENT 0x1000

static unsigned fb[GFX_W * GFX_H];

static long sys(long n, long a, long b, long c) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return r;
}

__attribute__((force_align_arg_pointer)) void _start(void) {
    for (int t = 0; t < 600; t++) {                 /* about 10 seconds at 60 frames/s */
        gfx_draw(fb, t);
        if (sys(ORB_PRESENT, (long)fb, GFX_W, GFX_H) != 0) break;  /* closed or no display */
        long ts[2] = {0, 16000000};                 /* sleep 16 ms */
        sys(SYS_NANOSLEEP, (long)ts, 0, 0);
    }
    sys(SYS_EXIT, 0, 0, 0);
}
