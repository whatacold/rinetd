#ifdef WIN32
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#endif
#include <string.h>
#include <stdio.h>
#include "conn.h"
#include "log.h"
#include "rinetd.h"

void conn_init(struct conn *c)
{
    c->reFd = INVALID_SOCKET;
    c->loFd = INVALID_SOCKET;
    c->seFd = INVALID_SOCKET;

    memset(c->reAddress, 0, sizeof(c->reAddress) / sizeof(c->reAddress[0]));

    c->inputRPos = 0;
    c->inputWPos = 0;
    c->outputRPos = 0;
    c->outputWPos = 0;

    c->bytesInput = 0;
    c->bytesOutput = 0;

    c->state = ST_CLOSED_BOTH;
}

/* handle read event of remote socket. */
void handleRemoteRead(struct conn *c)
{
    int got;

    if(c->inputRPos == c->bufSize) {
        return;
    }
    got = recv(c->reFd, c->inputBuf + c->inputRPos,
            c->bufSize - c->inputRPos, 0);
    if (got == 0) {
        /* Prepare for closing */
        handleCloseFromRemote(c);
        return;
    }
    if (got < 0) {
        if (GetLastError() == WSAEWOULDBLOCK) {
            return;
        }
        if (GetLastError() == WSAEINPROGRESS) {
            return;
        }
        handleCloseFromRemote(c);
        return;
    }
    c->inputRPos += got;
    c->bytesInput += got;
}

void handleRemoteWrite(struct conn *c)
{
    int got;

    if(IS_CLOSING(c) && c->outputWPos == c->outputRPos) {
        c->state = ST_CLOSED_BOTH;
        PERROR("rinetd: local closed and no more output");
        rd_log(c, conn->seFd, logDone | c->log);
        closesocket(c->reFd);
        return;
    }
    got = send(c->reFd, c->outputBuf + c->outputWPos,
            c->outputRPos - c->outputWPos, 0);
    if (got < 0) {
        if (GetLastError() == WSAEWOULDBLOCK) {
            return;
        }
        if (GetLastError() == WSAEINPROGRESS) {
            return;
        }
        handleCloseFromRemote(c);
        return;
    }
    c->outputWPos += got;
    c->bytesOutput += got;
    if(c->outputWPos == c->outputRPos) {
        c->outputRPos = 0;
        c->outputWPos = 0;
    }
}

void handleLocalRead(struct conn *c)
{
    int got;

    if(c->bufSize == c->outputRPos) {
        return;
    }
    got = recv(c->loFd, c->outputBuf + c->outputRPos,
            c->bufSize - c->outputRPos, 0);
    if (got == 0) {
        handleCloseFromLocal(c);
        return;
    }
    if (got < 0) {
        if (GetLastError() == WSAEWOULDBLOCK) {
            return;
        }
        if (GetLastError() == WSAEINPROGRESS) {
            return;
        }
        handleCloseFromLocal(c);
        return;
    }
    c->outputRPos += got;
}

void handleLocalWrite(struct conn *c)
{
    int got;

    if(IS_CLOSING(c) && c->inputWPos == c->inputRPos) {
        c->state = ST_CLOSED_BOTH;
        PERROR("remote closed and no more input");
        rd_log(c, c->seFd, logDone | c->log);
        closesocket(c->loFd);
        return;
    }
    got = send(c->loFd, c->inputBuf + c->inputWPos,
            c->inputRPos - c->inputWPos, 0);
    if (got < 0) {
        if (GetLastError() == WSAEWOULDBLOCK) {
            return;
        }
        if (GetLastError() == WSAEINPROGRESS) {
            return;
        }
        handleCloseFromLocal(c);
        return;
    }

    c->inputWPos += got;
    if(c->inputWPos == c->inputRPos) {
        c->inputWPos = 0;
        c->inputRPos = 0;
    }
}

void handleCloseFromLocal(struct conn *c)
{
    int arg;

    c->state |= ST_CLOSED_LOCAL;
    /* The local end fizzled out, so make sure
       we're all done with that */
    PERROR("close from local");
    closesocket(c->loFd);
    if (!(c->state & ST_CLOSED_REMOTE)) {
#ifndef LINUX
#ifndef WIN32
        /* Now set up the remote end for a polite closing */

        /* Request a low-water mark equal to the entire
           output buffer, so the next write notification
           tells us for sure that we can close the socket. */
        arg = 1024;
        setsockopt(c->reFd, SOL_SOCKET, SO_SNDLOWAT,
                &arg, sizeof(arg));	
#endif /* WIN32 */
#endif /* LINUX */
        c->log = logLocalClosedFirst;
    }
}

void handleCloseFromRemote(struct conn *c)
{
    int arg;

    c->state |= ST_CLOSED_REMOTE;
    /* The remote end fizzled out, so make sure
       we're all done with that */
    PERROR("close from remote");
    closesocket(c->reFd);
    if(!(c->state & ST_CLOSED_LOCAL)) {
#ifndef LINUX
#ifndef WIN32
        /* Now set up the local end for a polite closing */

        /* Request a low-water mark equal to the entire
           output buffer, so the next write notification
           tells us for sure that we can close the socket. */
        arg = 1024;
        setsockopt(c->loFd, SOL_SOCKET, SO_SNDLOWAT,
                &arg, sizeof(arg));	
#endif /* WIN32 */
#endif /* LINUX */
        c->log = logRemoteClosedFirst;
    }
}

void openLocalFd(int se, struct conn *c)
{
    int j;
    struct sockaddr_in saddr;

    c->loFd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (c->loFd == INVALID_SOCKET) {
        closesocket(c->reFd);
        c->state = ST_CLOSED_BOTH;
        rd_log(c, c->seFd, logLocalSocketFailed);
        return;
    }
#ifndef WIN32
    if (c->loFd > maxfd) {
        maxfd = c->loFd;
    }
#endif /* WIN32 */

    /* Bind the local socket */
    /* why do binding? */
    saddr.sin_family = AF_INET;
    saddr.sin_port = INADDR_ANY;
    saddr.sin_addr.s_addr = 0;
    if (bind(c->loFd, (struct sockaddr *) &saddr, sizeof(saddr)) == SOCKET_ERROR) {
        closesocket(c->loFd);
        closesocket(c->reFd);
        c->state = ST_CLOSED_BOTH;
        rd_log(c, c->seFd, logLocalBindFailed);
        return;
    }

    /* Connect the local server, which is configured by user. */
    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    memcpy(&saddr.sin_addr, &seLocalAddrs[se], sizeof(struct in_addr));
    saddr.sin_port = seLocalPorts[se];
#ifndef WIN32
#ifdef LINUX
    j = 0;
    setsockopt(c->loFd, SOL_SOCKET, SO_LINGER, &j, sizeof(j));
#else
    j = 1024;
    setsockopt(c->loFd, SOL_SOCKET, SO_SNDBUF, &j, sizeof(j));
#endif /* LINUX */
#endif /* WIN32 */
    j = 1;
    ioctlsocket(c->loFd, FIONBIO, (void *)&j);
    if (connect(c->loFd, (struct sockaddr *)&saddr,
                sizeof(struct sockaddr_in)) == INVALID_SOCKET)
    {
        if ((GetLastError() != WSAEINPROGRESS) &&
                (GetLastError() != WSAEWOULDBLOCK))
        {
            PERROR("rinetd: connect");
            closesocket(c->loFd);
            closesocket(c->reFd);
            c->state = ST_CLOSED_BOTH;
            rd_log(c, c->seFd, logLocalConnectFailed);
            return;
        }
    }
    c->state = ST_ESTABLISHED;
}
