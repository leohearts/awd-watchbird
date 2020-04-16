#include <stdio.h>
#include <stdlib.h>
#include <string.h>
__attribute__((constructor)) watchbird(int argc, char *argv[]) {
    for (int i = 0; i < argc; i++) {
        if (strstr(argv[i], "flag") != NULL ||
            strstr(argv[i], "LD_PRELOAD") != NULL ||
            strstr(argv[i], "waf.so") != NULL ||
            strstr(argv[i], "watchbird") != NULL) {
            printf("hhhh");
            exit(1);
        }
    }
}