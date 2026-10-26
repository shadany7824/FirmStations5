/* libstub.so: a REAL implementation of the functions dyn_hello.c imports.
 *
 * It exists so (a) the program can be linked as a normal dynamic executable and (b) you can run
 * it natively on Linux to see what output to expect. orbemu never loads this library: it answers
 * the same imports with Python functions instead (orbemu/hle_libc.py).
 *
 * Build: gcc -shared -fPIC -nostdlib -O1 -fno-builtin -fno-stack-protector \
 *        -fno-tree-loop-distribute-patterns -Wl,-soname,libstub.so -o libstub.so libstub.c
 */
typedef unsigned long size_t;

static long sys3(long n, long a, long b, long c) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return r;
}

static void out(const char *s, size_t n) { sys3(1, 1, (long)s, (long)n); }

size_t strlen(const char *s) { size_t n = 0; while (s[n]) n++; return n; }

int puts(const char *s) { out(s, strlen(s)); out("\n", 1); return 0; }

int orb_add(int a, int b) { return a + b; }

void *memset(void *p, int c, size_t n) {
    for (size_t i = 0; i < n; i++) ((unsigned char *)p)[i] = (unsigned char)c;
    return p;
}

static char arena[1 << 16];
static size_t used;
void *malloc(size_t n) {
    n = (n + 15) & ~(size_t)15;
    if (used + n > sizeof arena) return 0;
    void *p = arena + used;
    used += n;
    return p;
}

static void put_num(unsigned long v, int base, int is_signed, int is_long) {
    char buf[32]; int i = 32;
    int neg = 0;
    if (!is_long) v = is_signed ? (unsigned long)(long)(int)v : (unsigned long)(unsigned int)v;
    if (is_signed && (long)v < 0) { neg = 1; v = -(long)v; }
    if (v == 0) buf[--i] = '0';
    while (v) { buf[--i] = "0123456789abcdef"[v % base]; v /= base; }
    if (neg) buf[--i] = '-';
    out(buf + i, 32 - i);
}

int printf(const char *fmt, ...) {
    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);
    for (; *fmt; fmt++) {
        if (*fmt != '%') { out(fmt, 1); continue; }
        fmt++;
        int is_long = 0;
        while (*fmt == 'l') { is_long = 1; fmt++; }
        switch (*fmt) {
        case 'd': put_num(is_long ? __builtin_va_arg(ap, long) : __builtin_va_arg(ap, int), 10, 1, is_long); break;
        case 'u': put_num(is_long ? __builtin_va_arg(ap, unsigned long) : __builtin_va_arg(ap, unsigned), 10, 0, is_long); break;
        case 'x': put_num(is_long ? __builtin_va_arg(ap, unsigned long) : __builtin_va_arg(ap, unsigned), 16, 0, is_long); break;
        case 'c': { char c = (char)__builtin_va_arg(ap, int); out(&c, 1); break; }
        case 's': { const char *s = __builtin_va_arg(ap, const char *); out(s, strlen(s)); break; }
        case '%': out("%", 1); break;
        default: break;
        }
    }
    __builtin_va_end(ap);
    return 0;
}
