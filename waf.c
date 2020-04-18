#include <stdio.h>
#include <stdlib.h>
#include <string.h>
__attribute__((constructor)) watchbird(int argc, char *argv[]) {
    // exit(); // 去掉这个注释就可以禁止任何程序通过php执行
    int isenv = !strcmp(argv[0], "env");
    for (int i = 0; i < argc; i++) {
        if (isenv){
            if (strstr(argv[i], "-i") != NULL ||
                strstr(argv[i], "--ignore-environment") != NULL){
                    printf("hhhh, you want env?");
                    exit(1);
                }
        }
        if (strstr(argv[i], "flag") != NULL ||
            strstr(argv[i], "LD_PRELOAD") != NULL ||
            strstr(argv[i], "waf.so") != NULL ||
            strstr(argv[i], "watchbird") != NULL ||
            strstr(argv[i], "/dev/tcp/") != NULL){
                printf("hhhh");
                exit(1);
            }
    }
}