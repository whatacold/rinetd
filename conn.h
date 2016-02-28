#ifndef CONN_H
#define CONN_H

#include "rinetd.h"

#define NCONN_INITIAL 64            /* initial number of connections. */

#define ST_ESTABLISHED   0x00
#define ST_CLOSED_LOCAL  0x01
#define ST_CLOSED_REMOTE 0x02
#define ST_CLOSED_BOTH   0x03       /* both ends are closed. */

#define IS_CLOSING(c) (((c)->state) == ST_CLOSED_LOCAL || ((c)->state) == ST_CLOSED_REMOTE)
#define IS_CLOSED(c) (((c)->state) == ST_CLOSED_BOTH)

struct conn;

struct conn
{
    SOCKET reFd;
    SOCKET loFd;
    SOCKET seFd;                    /* whom reFd is accept()'ed by, slot index. */
    unsigned char reAddress[4];     /* in network order */
    int log;                        /* remember who closes conn first, for logging purpose. */

    char *inputBuf;                 /* FIXME loop buffer */
    char *outputBuf;
    unsigned int bufSize;
    int inputRPos;
    int inputWPos;
    int outputRPos;
    int outputWPos;

    int bytesInput;
    int bytesOutput;
    unsigned char state;
};

void conn_init(struct conn *c);

void handleRemoteWrite(struct conn *c);
void handleRemoteRead(struct conn *c);
void handleLocalWrite(struct conn *c);
void handleLocalRead(struct conn *c);
void handleCloseFromLocal(struct conn *c);
void handleCloseFromRemote(struct conn *c);
void openLocalFd(int se, struct conn *c);

#endif
