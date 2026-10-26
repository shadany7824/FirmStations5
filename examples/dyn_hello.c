/* A dynamically linked program. At link time its library functions come from libstub.so;
 * orbemu ignores that library and answers every import with Python code instead.
 *
 * Build (see README): gcc -nostdlib -fPIE -pie -fno-builtin -fno-stack-protector -O1 -s \
 *   -Wl,--build-id=none -Wl,-z,now -Wl,--dynamic-linker=/lib64/ld-linux-x86-64.so.2 \
 *   -Wl,-rpath,'$ORIGIN' -L. -o dyn_hello.elf dyn_hello.c -lstub
 * Run in orbemu: python -m orbemu examples/dyn_hello.elf
 * Run natively (Linux): ./dyn_hello.elf      (uses the real libstub.so next to it)
 */
int puts(const char *s);
int printf(const char *fmt, ...);
unsigned long strlen(const char *s);
int orb_add(int a, int b);
void *malloc(unsigned long n);
void *memset(void *p, int c, unsigned long n);

static void exit_now(int code) {
    __asm__ volatile("syscall" : : "a"(60), "D"(code) : "rcx", "r11", "memory");
    for (;;) {}
}

__attribute__((force_align_arg_pointer)) void _start(void) {
    puts("Hello from a dynamically linked program!");
    printf("orb_add(2, 3) = %d, strlen(\"orbemu\") = %lu, %s, 0x%x, %c\n",
           orb_add(2, 3), strlen("orbemu"), "string", 255, 'Z');
    char *p = malloc(16);
    memset(p, 'A', 15);
    p[15] = 0;
    printf("malloc+memset: %s\n", p);
    exit_now(0);
}
