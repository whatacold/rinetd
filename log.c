#include <time.h>
#include <stdio.h>
#include <assert.h>
#include "log.h"
#include "rinetd.h"

static char *logMessages[] = {
    "done-local-closed",
    "done-remote-closed",
    "accept-failed -",
    NULL,
    "local-socket-failed -",
    NULL,
    "local-bind-failed -",
    NULL,
    "local-connect-failed -",
    NULL,
    "not-allowed",
    NULL,
    "denied",
    NULL
};

static unsigned char nullAddress[4] = {0, 0, 0, 0};

static FILE *logFile = NULL;

static struct tm *get_gmtoff(int *tz);

/* get_gmtoff was borrowed from Apache. Thanks folks. */
static struct tm *get_gmtoff(int *tz)
{
    time_t tt = time(NULL);
    struct tm gmt;
    struct tm *t;
    int days, hours, minutes;

    /* Assume we are never more than 24 hours away. */
    gmt = *gmtime(&tt); /* remember gmtime/localtime return ptr to static */
    t = localtime(&tt); /* buffer... so be careful */
    days = t->tm_yday - gmt.tm_yday;
    hours = ((days < -1 ? 24 : 1 < days ? -24 : days * 24)
            + t->tm_hour - gmt.tm_hour);
    minutes = hours * 60 + t->tm_min - gmt.tm_min;
    *tz = minutes;
    return t;
}

int rd_log_open(const char *fileName)
{
    if(logFile)
        fclose(logFile);
    if(logFile = fopen(fileName, "a")) {
        /**
         * setlinebuf() is not C standard compatible.
         */
        setvbuf(logFile, NULL, _IOLBF, 0);
        return 0;
    }

    return 1;
}

void rd_log_close()
{
    assert(logFile);

    fclose(logFile);
    logFile = NULL;
}

void rd_log(struct conn *c, int coSe, int result)
{
    unsigned char *reAddress;
    int bytesOutput;
    int bytesInput;
    /* Bit of borrowing from Apache logging module here,
       thanks folks */
    int timz;
    struct tm *t;
    char tstr[1024];
    char sign;

    /**
     * There is situations when logs needed but not enabled in config.
     */
    /* assert(logFile); */
    if(NULL == logFile) {
        return;
    }

    t = get_gmtoff(&timz);
    sign = (timz < 0 ? '-' : '+');
    if (timz < 0) {
        timz = -timz;
    }
    strftime(tstr, sizeof(tstr), "%d/%b/%Y:%H:%M:%S ", t);

    if (c != NULL) {
        reAddress = c->reAddress;
        bytesOutput = c->bytesOutput;
        bytesInput = c->bytesInput;
    } else {
        reAddress = nullAddress;
        bytesOutput = 0;
        bytesInput = 0;
    }

    if (logFormatCommon) {
        /* Fake a common log format log file in a way that
           most web analyzers can do something interesting with.
           We lie and say the protocol is HTTP because we don't
           want the web analyzer to reject the line. We also
           lie and claim success (code 200) because we don't
           want the web analyzer to ignore the line as an
           error and not analyze the "URL." We put a result
           message into our "URL" instead. The last field
           is an extra, giving the number of input bytes,
           after several placeholders meant to fill the 
           positions frequently occupied by user agent, 
           referrer, and server name information. */
        fprintf(logFile, "%d.%d.%d.%d - - "
                "[%s %c%.2d%.2d] "
                "\"GET /rinetd-services/%s/%d/%s/%d/%s HTTP/1.0\" "
                "200 %d - - - %d\n",
                reAddress[0],
                reAddress[1],
                reAddress[2],
                reAddress[3],
                tstr,
                sign,
                timz / 60,
                timz % 60,
                seFromHosts[coSe], seFromPorts[coSe],
                seToHosts[coSe], seToPorts[coSe],
                logMessages[result],
                bytesOutput,
                bytesInput);
    } else {
        /* Write an rinetd-specific log entry with a
           less goofy format. */
        fprintf(logFile, "%s\t%d.%d.%d.%d\t%s\t%d\t%s\t%d\t%d"
                "\t%d\t%s\n",
                tstr,
                reAddress[0],
                reAddress[1],
                reAddress[2],
                reAddress[3],
                seFromHosts[coSe], seFromPorts[coSe],
                seToHosts[coSe], seToPorts[coSe],
                bytesInput,	
                bytesOutput,	
                logMessages[result]);
    }
}
