#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *p = malloc(100000);
    strcpy(p, "malloc and string functions work");
    printf("Hello from a normal static C program!\n%s\n", p);
    free(p);
    return 0;
}
