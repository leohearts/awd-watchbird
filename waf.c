#include <stdio.h>
#include <stdlib.h>
#include <string.h>
__attribute__((constructor)) watchbird(int argc, char *argv[]) {
    int isFirstrun = 1;
    int isenv = !strcmp(argv[0], "env");
    for (int i = 0; i < argc; i++) {
        if (isenv){
            if (strstr(argv[i], "-i") != NULL ||
                strstr(argv[i], "--ignore-environment") != NULL){
                    if (getenv("waf_firstrun") != NULL) {
                        isFirstrun = 0;
                    }
                    if (isFirstrun) {
                        char delimiter[] =
                            "a2f5464863e4ef86d07b7bd89e815407fbfaa912";
                        FILE *logfile =
                            fopen("/tmp/watchbird/log/rce_log.txt", "a");
                        fprintf(logfile, "%s%s%s%s", delimiter,
                                getenv("php_timestamp"), delimiter,
                                getenv("php_timestamp"));
                        fclose(logfile);
                        putenv("waf_firstrun=no");
                    }
                    printf("hhhh, you want env?");
                    exit(0);
                }
        }
        if (strstr(argv[i], "flag") != NULL ||
            strstr(argv[i], "LD_PRELOAD") != NULL ||
            strstr(argv[i], "waf.so") != NULL ||
            strstr(argv[i], "watchbird") != NULL ||
            strstr(argv[i], "/dev/tcp/") != NULL){
                if (getenv("waf_firstrun") != NULL) {
                    isFirstrun = 0;
                }
                if (isFirstrun) {
                    char delimiter[] = "a2f5464863e4ef86d07b7bd89e815407fbfaa912";
                    FILE *logfile = fopen("/tmp/watchbird/log/rce_log.txt", "a");
                    fprintf(logfile, "%s%s%s%s", delimiter, getenv("php_timestamp"),
                            delimiter, getenv("php_timestamp"));
                    fclose(logfile);
                    putenv("waf_firstrun=no");
                }
                printf("hhhh");
                exit(0);
            }
    }

    // exit(0); // 去掉这个注释就可以禁止任何程序通过php执行
    
}