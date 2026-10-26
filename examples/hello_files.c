/* A bigger libc test: argv, fopen/fgets, qsort, time functions, a big malloc.
 * Build: gcc -static -no-pie -fno-pie -O1 -s -Wl,--build-id=none -o hello_files.elf hello_files.c
 * Run:   python -m orbemu examples/hello_files.elf --root examples
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int cmp(const void *a, const void *b) {
    int x = *(const int *)a, y = *(const int *)b;
    return (x > y) - (x < y);
}

int main(int argc, char **argv) {
    printf("argc=%d argv[0]=%s\n", argc, argv[0]);

    FILE *f = fopen("msg.txt", "r");
    if (!f) { perror("fopen"); return 1; }
    char line[256];
    while (fgets(line, sizeof line, f)) printf("read: %s", line);
    fclose(f);

    int v[] = {42, 7, 19, 3, 88, 1};
    qsort(v, 6, sizeof v[0], cmp);
    printf("sorted:");
    for (int i = 0; i < 6; i++) printf(" %d", v[i]);
    printf("\n");

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    time_t t = time(NULL);
    printf("time() looks sane: %s\n", t > 1700000000 ? "yes" : "no");
    printf("monotonic clock ok: %s\n", ts.tv_sec >= 0 ? "yes" : "no");

    size_t n = 5 * 1024 * 1024;   /* above glibc's mmap threshold: uses mmap/munmap */
    char *big = malloc(n);
    memset(big, 1, n);
    printf("big malloc ok: last byte = %d\n", big[n - 1]);  /* use it so the compiler keeps it */
    free(big);
    return 0;
}
