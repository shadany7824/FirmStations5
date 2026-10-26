/* Freestanding test: uses only raw syscalls (no libc).
 * Build: gcc -static -nostdlib -no-pie -fno-pie -fno-stack-protector -O1 -s \
 *        -Wl,--build-id=none -o syscalls.elf syscalls.c
 * Run:   python -m orbemu examples/syscalls.elf --root examples
 */
static char tls[64];
static char buf[256];

static long sys(long n, long a, long b, long c) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return r;
}

static void say(const char *s) {
    long n = 0;
    while (s[n]) n++;
    sys(1, 1, (long)s, n);
}

__attribute__((force_align_arg_pointer)) void _start(void) {
    long base = sys(12, 0, 0, 0);
    long end = sys(12, base + 0x4000, 0, 0);
    if (end != base + 0x4000) { say("brk failed\n"); sys(60, 1, 0, 0); }
    ((char *)base)[0x3fff] = 'x';
    say("brk ok\n");

    if (sys(158, 0x1002, (long)tls, 0) != 0) { say("arch_prctl failed\n"); sys(60, 2, 0, 0); }
    say("arch_prctl ok\n");

    long fd = sys(2, (long)"msg.txt", 0, 0);
    if (fd < 0) { say("open failed\n"); sys(60, 3, 0, 0); }
    long n = sys(0, fd, (long)buf, sizeof buf);
    sys(1, 1, (long)buf, n);
    sys(3, fd, 0, 0);
    sys(60, 0, 0, 0);
}
