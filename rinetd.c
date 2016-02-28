#define VERSION "0.62"

#ifdef WIN32
#include <windows.h>
#include <winsock.h>
#include "getopt.h"
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <getopt.h>
#include <sys/time.h>
#include <unistd.h>
#include <arpa/inet.h>
#endif /* WIN32 */

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>
#include "log.h"
#include "conn.h"
#include "rinetd.h"

#ifndef WIN32
int closesocket(int s)
{
    return close(s);
}
#else
#endif

/* We've got to get FIONBIO from somewhere. Try the Solaris location
   if it isn't defined yet by the above includes. */
#ifndef FIONBIO
#include <sys/filio.h>
#endif /* FIONBIO */

#include "match.h"

#define bufferSpace 1024

/* In network order, for network purposes */
/* configurations */
struct in_addr *seLocalAddrs = NULL;
unsigned short *seLocalPorts = NULL;

/* In ASCII and local byte order, for logging purposes */
char **seFromHosts;
int *seFromPorts;
char **seToHosts;
int *seToPorts;

/* Offsets into list of allow and deny rules. Any rules
   prior to globalAllowRules and globalDenyRules are global rules. */

int *seAllowRules = 0;
int *seAllowRulesTotal = 0;
int globalAllowRules = 0;
int *seDenyRules = 0;
int *seDenyRulesTotal = 0;
int globalDenyRules = 0;

SOCKET *seFds = 0;

char **allowRules = 0;
char **denyRules = 0;
int *denyRulesFor = 0;
int seTotal = 0;
int allowRulesTotal = 0;
int denyRulesTotal = 0;
int maxfd = 0;
char *logFileName = 0;
char *pidLogFileName = 0;
int logFormatCommon = 0;
int bufferSize = bufferSpace;    /* FIXME configurable */

struct conn *conn = NULL;
int coTotal = 0;

/* If 'newsize' bytes can be allocated, *data is set to point
   to them, the previous data is copied, and 1 is returned.
   If 'size' bytes cannot be allocated, *data is UNCHANGED,
   and 0 is returned. */	

#define SAFE_REALLOC(x, y, z) safeRealloc((void **) (x), (y), (z))

int safeRealloc(void **data, int oldsize, int newsize);

void readConfiguration();

/* Signal handlers */
void plumber(int s);
void hup(int s);
void term(int s);

void initArrays(void);
void RegisterPID(void);

void selectLoop(void);

int getAddress(char *host, struct in_addr *iaddr);

/* Option parsing */

typedef struct _rinetd_options RinetdOptions;
struct _rinetd_options
{
    char *conf_file;
};

RinetdOptions options = {
    "/etc/rinetd.conf"
};

int readArgs (int argc,
        char **argv,
        RinetdOptions *options);

int main(int argc, char *argv[])
{
    WSADATA wsaData;

    int result = WSAStartup(MAKEWORD(1, 1), &wsaData);
    if (result != 0) {
        fprintf(stderr, "Your computer was not connected "
                "to the Internet at the time that "
                "this program was launched, or you "
                "do not have a 32-bit "
                "connection to the Internet.");
        exit(1);
    }
    fprintf(stderr, "rinetd %s, refactored by whatacold.\n"
            "have a nice day :)\n", VERSION);

    readArgs(argc, argv, &options);

#ifndef WIN32
#ifndef DEBUG
    if (!fork()) {
        if (!fork()) {
#endif /* DEBUG */
            signal(SIGPIPE, plumber);
            signal(SIGHUP, hup);
#endif /* WIN32 */
            signal(SIGTERM, term);
            initArrays();
            readConfiguration();
            RegisterPID();
            selectLoop();
#ifndef WIN32
#ifndef DEBUG
        } else {
            exit(0);
        }
    } else {
        exit(0);
    }
#endif /* DEBUG */
#endif /* WIN32 */

    return 0;
}

int getConfLine(FILE *in, char *line, int space, int *lnum);

int patternBad(char *pattern);

void readConfiguration(void)
{
    FILE *in;
    char line[16384];
    int lnum = 0;
    int i;
    int ai;
    int di;

    if (seFds) {
        /* Close existing server sockets. */
        for (i = 0; (i < seTotal); i++) {
            if (seFds[i] != -1) {
                closesocket(seFds[i]);
                free(seFromHosts[i]);
                free(seToHosts[i]);
            }
        }	
        /* Free memory associated with previous set. */
        free(seFds);
        free(seLocalAddrs);
        free(seLocalPorts);
        free(seFromHosts);
        free(seFromPorts);
        free(seToHosts);
        free(seToPorts);
        free(seAllowRules);
        free(seDenyRules);
        free(seAllowRulesTotal);
        free(seDenyRulesTotal);
    }
    seTotal = 0;

    if (allowRules) {
        /* Forget existing allow rules. */
        for (i = 0; (i < allowRulesTotal); i++) {
            free(allowRules[i]);
        }	
        /* Free memory associated with previous set. */
        free(allowRules);
        globalAllowRules = 0;
    }
    allowRulesTotal = 0;

    if (denyRules) {
        /* Forget existing deny rules. */
        for (i = 0; (i < denyRulesTotal); i++) {
            free(denyRules[i]);
        }	
        /* Free memory associated with previous set. */
        free(denyRules);
        globalDenyRules = 0;
    }
    denyRulesTotal = 0;

    if (logFileName) {
        free(logFileName);
        logFileName = 0;
    }

    if (pidLogFileName) {
        free(pidLogFileName);
        pidLogFileName = 0;
    }

    /* 1. Count the non-comment lines of each type and
       allocate space for the data. */
    in = fopen(options.conf_file, "r");
    if (!in) {
        fprintf(stderr, "rinetd: can't open %s\n", options.conf_file);
        exit(1);
    }
    while (1) {
        char *t = 0;
        if (!getConfLine(in, line, sizeof(line), &lnum)) {
            break;
        }
        t = strtok(line, " \t\r\n");
        if (!strcmp(t, "logfile")) { 	
            continue;
        } else if (!strcmp(t, "pidlogfile")) { 	
            continue;
        } else if (!strcmp(t, "logcommon")) {
            continue;
        } else if (!strcmp(t, "allow")) {
            allowRulesTotal++;
        } else if (!strcmp(t, "deny")) {		
            denyRulesTotal++;
        } else {	
            /* A regular forwarding rule */
            seTotal++;	
        }
    }	
    fclose(in);

    seFds = (SOCKET *) malloc(sizeof(int) * seTotal);	
    if (!seFds) {
        goto lowMemory;
    }
    seLocalAddrs = (struct in_addr *) malloc(sizeof(struct in_addr) *
            seTotal);	
    if (!seLocalAddrs) {
        goto lowMemory;
    }
    seLocalPorts = (unsigned short *)
        malloc(sizeof(unsigned short) * seTotal);	
    if (!seLocalPorts) {
        goto lowMemory;
    }
    seFromHosts = (char **)
        malloc(sizeof(char *) * seTotal);
    if (!seFromHosts) {
        goto lowMemory;
    }
    seFromPorts = (int *)
        malloc(sizeof(int) * seTotal);	
    if (!seFromPorts) {
        goto lowMemory;
    }
    seToHosts = (char **)
        malloc(sizeof(char *) * seTotal);
    if (!seToHosts) {
        goto lowMemory;
    }
    seToPorts = (int *)
        malloc(sizeof(int) * seTotal);	
    if (!seToPorts) {
        goto lowMemory;
    }
    allowRules = (char **)
        malloc(sizeof(char *) * allowRulesTotal);
    if (!allowRules) {
        goto lowMemory;
    }
    denyRules = (char **)
        malloc(sizeof(char *) * denyRulesTotal);
    if (!denyRules) {
        goto lowMemory;
    }
    seAllowRules = (int *)
        malloc(sizeof(int) * seTotal);
    if (!seAllowRules) {
        goto lowMemory;
    }
    seAllowRulesTotal = (int *)
        malloc(sizeof(int) * seTotal);
    if (!seAllowRulesTotal) {
        goto lowMemory;
    }
    seDenyRules = (int *)
        malloc(sizeof(int) * seTotal);
    if (!seDenyRules) {
        goto lowMemory;
    }
    seDenyRulesTotal = (int *)
        malloc(sizeof(int) * seTotal);
    if (!seDenyRulesTotal) {
        goto lowMemory;
    }

    /* 2. Make a second pass to configure them. */	
    i = 0;
    ai = 0;
    di = 0;
    lnum = 0;
    in = fopen(options.conf_file, "r");
    if (!in) {
        goto lowMemory;
    }
    if (seTotal > 0) {
        seAllowRulesTotal[i] = 0;
        seDenyRulesTotal[i] = 0;
    }
    while (1) {
        char *bindAddress;
        unsigned short bindPort;
        char *connectAddress;
        char *bindPortS;
        char *connectPortS;
        unsigned short connectPort;
        struct in_addr iaddr;
        struct sockaddr_in saddr;
        struct servent *service;
        int j;
        if (!getConfLine(in, line, sizeof(line), &lnum)) {
            break;
        }
        bindAddress = strtok(line, " \t\r\n");
        if (!bindAddress) {
            fprintf(stderr, "rinetd: no bind address specified "
                    "on line %d.\n", lnum);	
            continue;
        }	
        if (!strcmp(bindAddress, "allow")) {
            char *pattern = strtok(0, " \t\r\n");
            if (!pattern) {
                fprintf(stderr, "rinetd: nothing to allow "
                        "specified on line %d.\n", lnum);	
                continue;
            }	
            if (patternBad(pattern)) {
                fprintf(stderr, "rinetd: illegal allow or "
                        "deny pattern. Only digits, ., and\n"
                        "the ? and * wild cards are allowed. "
                        "For performance reasons, rinetd\n"
                        "does not look up complete "
                        "host names.\n");
                continue;
            }

            allowRules[ai] = malloc(strlen(pattern) + 1);
            if (!allowRules[ai]) {
                goto lowMemory;
            }
            strcpy(allowRules[ai], pattern);
            if (i > 0) {
                if (seAllowRulesTotal[i - 1] == 0) {
                    seAllowRules[i - 1] = ai;
                }
                seAllowRulesTotal[i - 1]++;
            } else {
                globalAllowRules++;
            }
            ai++;
        } else if (!strcmp(bindAddress, "deny")) {
            char *pattern = strtok(0, " \t\r\n");
            if (!pattern) {
                fprintf(stderr, "rinetd: nothing to deny "
                        "specified on line %d.\n", lnum);	
                continue;
            }	
            denyRules[di] = malloc(strlen(pattern) + 1);
            if (!denyRules[di]) {
                goto lowMemory;
            }
            strcpy(denyRules[di], pattern);
            if (i > 0) {
                if (seDenyRulesTotal[i - 1] == 0) {
                    seDenyRules[i - 1] = di;
                }
                seDenyRulesTotal[i - 1]++;
            } else {
                globalDenyRules++;
            }
            di++;
        } else if (!strcmp(bindAddress, "logfile")) {
            char *nt = strtok(0, " \t\r\n");
            if (!nt) {
                fprintf(stderr, "rinetd: no log file name "
                        "specified on line %d.\n", lnum);	
                continue;
            }	
            logFileName = malloc(strlen(nt) + 1);
            if (!logFileName) {
                goto lowMemory;
            }
            strcpy(logFileName, nt);
        } else if (!strcmp(bindAddress, "pidlogfile")) {
            char *nt = strtok(0, " \t\r\n");
            if (!nt) {
                fprintf(stderr, "rinetd: no PID log file name "
                        "specified on line %d.\n", lnum);	
                continue;
            }	
            pidLogFileName = malloc(strlen(nt) + 1);
            if (!pidLogFileName) {
                goto lowMemory;
            }
            strcpy(pidLogFileName, nt);
        } else if (!strcmp(bindAddress, "logcommon")) {
            logFormatCommon = 1;
        } else {
            /* A regular forwarding rule. */
            bindPortS = strtok(0, " \t\r\n");
            if (!bindPortS) {
                fprintf(stderr, "rinetd: no bind port "
                        "specified on line %d.\n", lnum);	
                continue;
            }
            service = getservbyname(bindPortS, "tcp");	
            if (service) {
                bindPort = ntohs(service->s_port);
            } else {
                bindPort = atoi(bindPortS);
            }
            if ((bindPort == 0) || (bindPort >= 65536)) {
                fprintf(stderr, "rinetd: bind port missing "
                        "or out of range on line %d.\n", lnum);
                continue;
            }
            connectAddress = strtok(0, " \t\r\n");
            if (!connectAddress) {
                fprintf(stderr, "rinetd: no connect address "
                        "specified on line %d.\n", lnum);	
                continue;
            }	
            connectPortS = strtok(0, " \t\r\n");
            if (!connectPortS) {
                fprintf(stderr, "rinetd: no connect port "
                        "specified on line %d.\n", lnum);	
                continue;
            }
            service = getservbyname(connectPortS, "tcp");	
            if (service) {
                connectPort = ntohs(service->s_port);
            } else {
                connectPort = atoi(connectPortS);
            }
            if ((connectPort == 0) || (connectPort >= 65536)) {
                fprintf(stderr, "rinetd: bind port missing "
                        "or out of range on line %d.\n", lnum);
                continue;
            }
            /* Turn all of this stuff into reasonable addresses */
            if (!getAddress(bindAddress, &iaddr)) {
                fprintf(stderr, "rinetd: host %s could not be "
                        "resolved on line %d.\n",
                        bindAddress, lnum);
                continue;
            }	
            /* Make a server socket */
            seFds[i] = socket(PF_INET, SOCK_STREAM, 0);
            if (seFds[i] == INVALID_SOCKET) {
                fprintf(stderr, "rinetd: couldn't create "
                        "server socket!\n");
                seFds[i] = -1;
                continue;
            }
#ifndef WIN32
            if (seFds[i] > maxfd) {
                maxfd = seFds[i];
            }
#endif
            saddr.sin_family = AF_INET;
            memcpy(&saddr.sin_addr, &iaddr, sizeof(iaddr));
            saddr.sin_port = htons(bindPort);
            j = 1;
            setsockopt(seFds[i], SOL_SOCKET, SO_REUSEADDR,
                    (const char *) &j, sizeof(j));
            if (bind(seFds[i], (struct sockaddr *)
                        &saddr, sizeof(saddr)) == SOCKET_ERROR)
            {
                /* Warn -- don't exit. */
                fprintf(stderr, "rinetd: couldn't bind to "
                        "address %s port %d\n",
                        bindAddress, bindPort);	
                closesocket(seFds[i]);
                seFds[i] = INVALID_SOCKET;
                continue;
            }
            if (listen(seFds[i], 5) == SOCKET_ERROR) {
                /* Warn -- don't exit. */
                fprintf(stderr, "rinetd: couldn't listen to "
                        "address %s port %d\n",
                        bindAddress, bindPort);	
                closesocket(seFds[i]);
                seFds[i] = INVALID_SOCKET;
                continue;
            }
            ioctlsocket(seFds[i], FIONBIO, (void *)&j);
            if (!getAddress(connectAddress, &iaddr)) {
                /* Warn -- don't exit. */
                fprintf(stderr, "rinetd: host %s could not be "
                        "resolved on line %d.\n",
                        bindAddress, lnum);
                closesocket(seFds[i]);
                seFds[i] = INVALID_SOCKET;
                continue;
            }	
            seLocalAddrs[i] = iaddr;
            seLocalPorts[i] = htons(connectPort);
            seFromHosts[i] = malloc(strlen(bindAddress) + 1);
            if (!seFromHosts[i]) {
                goto lowMemory;
            }
            strcpy(seFromHosts[i], bindAddress);
            seFromPorts[i] = bindPort;
            seToHosts[i] = malloc(strlen(connectAddress) + 1);
            if (!seToHosts[i]) {
                goto lowMemory;
            }
            strcpy(seToHosts[i], connectAddress);
            seToPorts[i] = connectPort;
            i++;
            if (i < seTotal) {
                seAllowRulesTotal[i] = 0;
                seDenyRulesTotal[i] = 0;
            }
        }
    }
    /* Open the log file */
    if (logFileName) {
        if(rd_log_open(logFileName)) {
            fprintf(stderr, "rinetd: could not open %s to append.\n",
                    logFileName);
        }
    }
    fclose(in);
    return;

lowMemory:
    fprintf(stderr, "rinetd: not enough memory to start rinetd.\n");
    fclose(in);
    exit(1);
}

int getConfLine(FILE *in, char *line, int space, int *lnum)
{
    char *p;
    while (1) {
        if (!fgets(line, space, in)) {
            return 0;
        }
        p = line;
        while (isspace(*p)) {
            p++;
        }
        if (!(*p)) {
            /* Blank lines are OK */
            continue;
        }
        if (*p == '#') {
            /* Comment lines are also OK */
            continue;
        }
        (*lnum)++;
        return 1;
    }
}

/* Allocate memories used by connections and initialize them. */
void initArrays(void)
{
    int j;

    coTotal = NCONN_INITIAL;

    conn = (struct conn *)malloc(sizeof(struct conn) * coTotal);
    if(!conn) {
        goto outofmem;
    }
    for(j = 0; j < coTotal; j++) {
        conn[j].bufSize = bufferSize;
        conn[j].inputBuf = (char *)malloc(sizeof(char) * conn[j].bufSize);
        conn[j].outputBuf = (char *)malloc(sizeof(char) * conn[j].bufSize);
        if(!conn[j].inputBuf || !conn[j].outputBuf) {
            goto outofmem;
        }
        conn_init(conn + j);
    }

    return;

outofmem:
    fprintf(stderr, "rinetd: not enough memory to start rinetd.\n");
    exit(1);
}

void selectPass(void);

void selectLoop(void)
{
    while (1) {
        selectPass();
    }
}

void handleAccept(int se);

/* one pass of select() */
void selectPass(void)
{
    int i, rc;
    fd_set readfds, writefds;
    unsigned char state;
    struct conn *c;

    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    /* Server sockets */
    for (i = 0; (i < seTotal); i++) {
        if (seFds[i] != INVALID_SOCKET) {
            FD_SET(seFds[i], &readfds);
        }
    }
    /* Connection sockets */
    for (i = 0; (i < coTotal); i++) {
        c = conn + i;
        state = c->state;
        if(IS_CLOSED(c)) {
            continue;
        } else if(state & ST_CLOSED_LOCAL) {
            FD_SET(c->reFd, &writefds);
        } else if(state & ST_CLOSED_REMOTE) {
            FD_SET(c->loFd, &writefds);
        }
        if(!(state & ST_CLOSED_REMOTE)) {
            /* Get more input if we have room for it */
            if(c->inputRPos < c->bufSize) {
                FD_SET(c->reFd, &readfds);
            }
            /* Send more output if we have any */	
            if(c->outputWPos < c->outputRPos) {
                FD_SET(c->reFd, &writefds);
            }	
        }
        if(!(state & ST_CLOSED_LOCAL)) {
            /* Accept more output from the local
               server if there's room */
            if(c->outputRPos < c->bufSize) {
                FD_SET(c->loFd, &readfds);
            }
            /* Send more input to the local server
               if we have any */
            if(c->inputWPos < c->inputRPos) {
                FD_SET(c->loFd, &writefds);
            }	
        }
    }
    rc = select(maxfd + 1, &readfds, &writefds, NULL, NULL);
    if(rc <= 0) {
        return;
    }

    for (i = 0; (i < seTotal); i++) {
        if (seFds[i] != -1) {
            if (FD_ISSET(seFds[i], &readfds)) {
                handleAccept(i);
            }
        }
    }
    for (i = 0; (i < coTotal); i++) {
        c = conn + i;
        if(IS_CLOSED(c)) {
            continue;
        }
        if(!(c->state & ST_CLOSED_REMOTE)) {
            if (FD_ISSET(c->reFd, &readfds)) {
                handleRemoteRead(c);
            }
        }
        if(!(c->state & ST_CLOSED_REMOTE)) {             // would be closed inside previous if branch?
            if (FD_ISSET(c->reFd, &writefds)) {
                handleRemoteWrite(c);
            }
        }
        if(!(c->state & ST_CLOSED_LOCAL)) {
            if (FD_ISSET(c->loFd, &readfds)) {
                handleLocalRead(c);
            }
        }
        if(!(c->state & ST_CLOSED_LOCAL)) {
            if (FD_ISSET(c->loFd, &writefds)) {
                handleLocalWrite(c);
            }
        }
    }
}

void refuse(int index, int logCode);

/* accept */
void handleAccept(int i)
{
    struct sockaddr addr;
    struct sockaddr_in *sin;
    unsigned char address[4];
    char addressText[64];
    int j;
    int addrlen;
    int index;
    int o;
    SOCKET nfd;

    addrlen = sizeof(addr);
    nfd = accept(seFds[i], &addr, &addrlen);
    if (nfd == INVALID_SOCKET) {
        rd_log(NULL, i, logAcceptFailed);
        return;
    }
#ifndef WIN32
    if (nfd > maxfd) {
        maxfd = nfd;
    }
#endif /* WIN32 */

    j = 1;
    ioctlsocket(nfd, FIONBIO, (void *)&j);
    j = 0;
#ifndef WIN32
    setsockopt(nfd, SOL_SOCKET, SO_LINGER, &j, sizeof(j));
#endif

    index = -1;
    for (j = 0; (j < coTotal); j++) {	
        if (IS_CLOSED(conn + j)) {  /* find first empty connection slot */
            index = j;
            break;
        }
    }
    if (index == -1) {  /* expand as twice large as before */
        o = coTotal;
        coTotal *= 2;
        if(!SAFE_REALLOC(&conn, sizeof(struct conn) * o,
                    sizeof(struct conn) * coTotal))
        {
            goto shortage;
        }
        for(j = o; j < coTotal; j++) {
            conn[j].inputBuf = (char *)malloc(sizeof(char) * bufferSize);
            conn[j].outputBuf = (char *)malloc(sizeof(char) * bufferSize);
            conn[j].bufSize = bufferSize;
            if(NULL == conn[j].inputBuf ||
                    NULL == conn[j].outputBuf) {
                int k;
                for (k = o; (k < j); k++) {
                    free(conn[k].inputBuf);
                    free(conn[k].outputBuf);
                }
                goto shortage;
            }
            conn_init(conn +j);
        }
        index = o;
    }

    conn_init(conn + index);

    conn[index].reFd = nfd;     /* 'remote' denote the client who initiate the connection */
    conn[index].seFd = i;        /* Which server socket this connection belongs to. */

    sin = (struct sockaddr_in *) &addr;
    memcpy(address, &(sin->sin_addr.s_addr), 4);
    memcpy(conn[index].reAddress, address, 4);
    /* Now, do we want to accept this connection?
       Format it for comparison to a pattern. */
    sprintf(addressText, "%d.%d.%d.%d",
            address[0], address[1], address[2], address[3]);

    /* 1. Check global allow rules. If there are no
       global allow rules, it's presumed OK at
       this step. If there are any, and it doesn't
       match at least one, kick it out. */
    if (globalAllowRules) {
        int good = 0;
        for (j = 0; (j < globalAllowRules); j++) {
            if (match(addressText, allowRules[j])) {
                good = 1;
                break;
            }
        }
        if (!good) {
            refuse(index, logNotAllowed);
            return;
        }	
    }
    /* 2. Check global deny rules. If it matches
       any of the global deny rules, kick it out. */
    if (globalDenyRules) {			
        for (j = 0; (j < globalDenyRules); j++) {
            if (match(addressText, denyRules[j])) {
                refuse(index, logDenied);
            }
        }
    }
    /* 3. Check allow rules specific to this forwarding rule.
       If there are none, it's OK. If there are any,
       it must match at least one. */
    if (seAllowRulesTotal[i]) {
        int good = 0;
        for (j = 0; (j < seAllowRulesTotal[i]); j++) {
            if (match(addressText,
                        allowRules[seAllowRules[i] + j])) {
                good = 1;
                break;
            }
        }
        if (!good) {
            refuse(index, logNotAllowed);
            return;
        }	
    }
    /* 2. Check deny rules specific to this forwarding rule. If
       it matches any of the deny rules, kick it out. */
    if (seDenyRulesTotal[i]) {			
        for (j = 0; (j < seDenyRulesTotal[i]); j++) {
            if (match(addressText,
                        denyRules[seDenyRules[i] + j])) {
                refuse(index, logDenied);
            }
        }
    }
    /* Now open a connection to the local server.
       This, too, is nonblocking. Why wait
       for anything when you don't have to?! */
    openLocalFd(i, conn + index);	

    return;

shortage:
    fprintf(stderr, "rinetd: not enough memory to "
            "add slots. Currently %d slots.\n", o);
    /* Go back to the previous total number of slots */
    coTotal = o;	
}

int getAddress(char *host, struct in_addr *iaddr)
{
    char *p = host;
    int ishost = 0;
    while (*p) {
        if (!(isdigit(*p) || ((*p) == '.'))) {
            ishost = 1;
            break;
        }
        p++;
    }
    if (ishost) {
        struct hostent *h;
        h = gethostbyname(host);
        if (!h) {
            return 0;
        }
        memcpy(
                (void *) &iaddr->s_addr,
                (void *) h->h_addr,
                4);
        return 1;
    } else {
        iaddr->s_addr = inet_addr(host);
        return 1;
    }
}

#ifndef WIN32
void plumber(int s)
{
    /* Just reinstall */
    signal(SIGPIPE, plumber);
}

void hup(int s)
{
    /* Learn the new rules */
    readConfiguration();
    /* And reinstall the signal handler */
    signal(SIGHUP, hup);
}
#endif /* WIN32 */

int safeRealloc(void **data, int oldsize, int newsize)
{
    void *newData = malloc(newsize + 1);
    if (!newData) {
        return 0;
    }
    if (newsize < oldsize) {
        memcpy(newData, *data, newsize);
    } else {	
        memcpy(newData, *data, oldsize);
    }
    *data = newData;
    return 1;
}

void RegisterPID(void)
{
    FILE *pid_file;
    char *pid_file_name = "/var/run/rinetd.pid";

    if (pidLogFileName) {
        pid_file_name = pidLogFileName;
    }
    /* add other systems with wherever they register processes */
#if	defined(LINUX)
    pid_file = fopen(pid_file_name, "w");
    if (pid_file == NULL) {
        /* non-fatal, non-Linux may lack /var/run... */
        fprintf(stderr, "rinetd: Couldn't write to "
                "%s. PID was not logged.\n", pid_file_name);
    } else {
        /* error checking deliberately omitted */
        fprintf(pid_file, "%d\n", getpid());
        fclose(pid_file);
    }
#endif	/* LINUX */
}

int readArgs (int argc,
        char **argv,
        RinetdOptions *options)
{
    int c;

    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"conf-file",  1, 0, 'c'},
            {"help",       0, 0, 'h'},
            {"version",    0, 0, 'v'},
            {0, 0, 0, 0}
        };
        c = getopt_long (argc, argv, "c:shv",
                long_options, &option_index);
        if (c == -1) {
            break;
        }
        switch (c) {
        case 'c':
            options->conf_file = malloc(strlen(optarg) + 1);
            if (!options->conf_file) {
                fprintf(stderr, "Not enough memory to "
                        "launch rinetd.\n");
                exit(1);
            }
            strcpy(options->conf_file, optarg);
            break;
        case 'h':
            printf("Usage: rinetd [OPTION]\n"
                    "  -c, --conf-file FILE   read configuration "
                    "from FILE\n"
                    "  -h, --help             display this help\n"
                    "  -v, --version          display version "
                    "number\n\n");
            printf("Most options are controlled through the\n"
                    "configuration file. See the rinetd(8)\n"
                    "manpage for more information.\n");
            exit (0);
        case 'v':
            printf ("rinetd %s\n", VERSION);
            exit (0);
        case '?':
        default:
            exit (1);
        }
    }
    return 0;
}

int patternBad(char *pattern)
{
    const char *p = pattern;
    while (*p) {
        if (isdigit(*p) || ((*p) == '?') || ((*p) == '*') ||
                ((*p) == '.'))
        {
            p++;
        }
        return 0;
    }
    return 1;
}

void refuse(int index, int logCode)
{
    closesocket(conn[index].reFd);
    conn[index].state = ST_CLOSED_BOTH;
    rd_log(conn + index, conn[index].seFd, logCode);
}

void term(int s)
{
    /* Obey the request, but first flush the log */
    rd_log_close();
    exit(0);
}
