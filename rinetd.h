#ifndef RINETD_H
#define RINETD_H

#ifdef WIN32
#include <windows.h>
#include <winsock.h>
#else
#include <errno.h>
#include <sys/ioctl.h>
#endif

#ifdef WIN32
#else
#define SOCKET int
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#endif

#ifndef WIN32
/* Windows sockets compatibility defines */
int closesocket(int s);

#define ioctlsocket ioctl
#define MAKEWORD(a, b)
#define WSAStartup(a, b) (0)
#define	WSACleanup()
#ifdef __MAC__
/* The constants for these are a little screwy in the prelinked
   MSL GUSI lib and we can't rebuild it, so roll with it */
#define WSAEWOULDBLOCK EWOULDBLOCK
#define WSAEAGAIN EAGAIN
#define WSAEINPROGRESS EINPROGRESS
#else
#define WSAEWOULDBLOCK EWOULDBLOCK
#define WSAEAGAIN EAGAIN
#define WSAEINPROGRESS EINPROGRESS
#endif /* __MAC__ */
#define WSAEINTR EINTR
#define GetLastError() (errno)
typedef struct {
    int dummy;
} WSADATA;

#else
/* WIN32 doesn't really have WSAEAGAIN */
#ifndef WSAEAGAIN
#define WSAEAGAIN WSAEWOULDBLOCK
#endif
#endif /* WIN32 */

#ifdef DEBUG
#define PERROR perror
#else
#define PERROR(x)
#endif /* DEBUG */

extern char *logFileName;
extern char **seFromHosts;
extern int *seFromPorts;
extern char **seToHosts;
extern int *seToPorts;
extern int logFormatCommon;
extern struct conn *conn;
extern int maxfd;
extern struct in_addr *seLocalAddrs;
extern unsigned short *seLocalPorts;

#endif
