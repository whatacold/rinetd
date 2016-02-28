#ifndef LOG_H
#define LOG_H

#include "conn.h"

#define logDone 0
#define logAcceptFailed 2
#define logLocalSocketFailed 4
#define logLocalBindFailed 6
#define logLocalConnectFailed 8
#define logNotAllowed 10
#define logDenied 12

#define logLocalClosedFirst 0
#define logRemoteClosedFirst 1

int rd_log_open(const char *fileName);
void rd_log_close();
void rd_log(struct conn *c, int coSe, int result);

#endif
