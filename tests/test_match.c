#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "../match.h"

int
main(int argc, char **argv)
{
    char s[1024];
    char *p;
    int i;

    if(argc != 2) {
        fprintf(stderr, "Usage: match pattern\n");
        return 1;
    }
    p = argv[1];
    while(1) {
        if(!fgets(s, sizeof(s), stdin)) {
            break;
        }
        i = strlen(s) - 1;
        while(isspace(s[i--]));
        s[i + 2] = '\0';
        printf("%s ~ %s? ", s, p);
        if(match(s, p)) {
            printf("Matched.");
        } else {
            printf("Not matched.");
        }
        printf("\n");
    }
}
