/* hello.c — trivial test program. FORTIFY+canary attach around strcpy. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    char buf[64];
    if (argc > 1) {
        strncpy(buf, argv[1], sizeof buf - 1);
        buf[sizeof buf - 1] = '\0';
        printf("hello, %s\n", buf);
    } else {
        puts("hello, world");
    }
    return 0;
}
