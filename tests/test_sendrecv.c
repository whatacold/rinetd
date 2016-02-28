/**
 * test the very basic functionality of sending and receiving data
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define STR_SIZE 1500

int
main(int argc, char **argv)
{
    int rp, sp;
    int cs, ss, as;             /* client, server, accepted */
    int rc, i;
    struct sockaddr_in saddr;
    const char *s = "hello rinetd";
    char orig[STR_SIZE + 1], recved[STR_SIZE + 1];

    if(argc != 3) {
        fprintf(stderr, "Usage: %s rinetd-port server-port\n"
                "  rinetd-port, the port that rinetd listens on.\n"
                "  server-port, the backend server port.\n", argv[0]);
        return 1;
    }
    rp = atoi(argv[1]);
    sp = atoi(argv[2]);

    cs = socket(AF_INET, SOCK_STREAM, 0);
    ss = socket(AF_INET, SOCK_STREAM, 0);
    assert(cs >= 0);
    assert(ss >= 0);

    i = 1;
    setsockopt(ss, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(sp);
    saddr.sin_addr.s_addr = inet_addr("0.0.0.0");
    rc = bind(ss, (struct sockaddr *)&saddr, sizeof(saddr));
    assert(rc == 0);
    rc = listen(ss, 5);
    assert(rc == 0);

    saddr.sin_port = htons(rp);
    saddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    rc = connect(cs, (struct sockaddr *)&saddr, sizeof(saddr));
    assert(rc == 0);

    as = accept(ss, NULL, 0);   /* will block. */
    assert(as >= 0);

    /* construct content to be sent */
    memset(orig, 0, sizeof(orig));
    memset(recved, 0, sizeof(recved));
    i = 0;
    while(i < STR_SIZE) {
        strncpy(orig + i, s, STR_SIZE - i);
        i += strlen(s);                         /* assume that it has been entirely copied. */
    }
    assert(strlen(orig) == STR_SIZE);           /* buffer must be full. */

    /* test the stream in the direction from client to server */
    rc = send(cs, orig, STR_SIZE, 0);
    assert(rc == STR_SIZE);
    rc = recv(as, recved, STR_SIZE, 0);
    assert(rc == STR_SIZE);
    assert(0 == strcmp(orig, recved));
    printf("test of sending data from client to server is passed.\n");

    /* test the stream in the direction from server to client */
    memset(recved, 0, sizeof(recved));
    rc = send(as, orig, STR_SIZE, 0);
    assert(rc == STR_SIZE);
    rc = recv(cs, recved, STR_SIZE, 0);
    assert(rc == STR_SIZE);
    assert(0 == strcmp(orig, recved));
    printf("test of sending data from server to client is passed.\n");

    close(cs);
    close(ss);
    close(as);

    return 0;
}
