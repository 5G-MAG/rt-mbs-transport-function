/*
License: 5G-MAG Public License (v1.0)
Copyright: (C) 2024 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <ctype.h>
#include <time.h>

#include "Utilities.hh"

time_t str_to_time(const char *str_time)
{
    static time_t time;
    struct tm tm = {0};
    strptime(str_time, "%a, %d %b %Y %H:%M:%S %Z", &tm);
    time = mktime(&tm);
    return time;
}

const char *get_time(time_t time_epoch)
{
    struct tm *ts;
    static char buf[80];

    /* Format and print the time, "ddd yyyy-mm-dd hh:mm:ss zzz" */
    ts = localtime(&time_epoch);
    strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S %Z", ts);

    return buf;
}

time_t str_to_rfc3339_time(const char *str_time)
{
    static time_t time;
    struct tm tm = {0};
    //strptime(str_time, "%FT%T%z", &tm);
    strptime(str_time, "%Y-%m-%dT%H:%M:%S.%f%z", &tm);
    time = mktime(&tm);
    return time;
}


const char *get_current_time(const char *format) {

    time_t rawtime;
    struct tm * ts;
    static char buf[80];
    
    time (&rawtime);
    ts = localtime (&rawtime);

   // strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S %Z", ts);

    strftime(buf, sizeof(buf), format, ts);
    return buf;
}

char *ogs_time_to_string(ogs_time_t timestamp, const char *format)
{
    struct tm tm;
    char datetime[128];

    ogs_localtime(ogs_time_sec(timestamp), &tm);
    ogs_strftime(datetime, sizeof datetime, format, &tm);

    return ogs_msprintf("%s", datetime);
}

/*
char *ogs_time_to_string(ogs_time_t timestamp)
{
    struct tm tm;
    char datetime[128];

    ogs_localtime(ogs_time_sec(timestamp), &tm);
    ogs_strftime(datetime, sizeof datetime, "%a, %d %b %Y %H:%M:%S %Z", &tm);

    return ogs_msprintf("%s", datetime);
}
*/


char *read_file(const char *filename)
{
    FILE *f = NULL;
    long len = 0;
    char *data_json = NULL;

    /* open in read binary mode */
    f = fopen(filename, "rb");
    if (f == NULL) {
        ogs_error("Unable to open file with name [%s]: %s", filename, strerror(errno));
        return NULL;
    }
    /* get the length */
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fseek(f, 0, SEEK_SET);
    data_json = (char*)malloc(len + 1);

    fread(data_json, 1, len, f);
    data_json[len] = '\0';
    fclose(f);
    return data_json;

}

char *epoch_to_datetime(char *epoch) {
    struct tm tm;
    static char buf[255];
    char *epoch_to_convert;

    memset(&tm, 0, sizeof(struct tm));
    epoch_to_convert = ogs_msprintf("%.10s", epoch);

    strptime(epoch_to_convert, "%s", &tm);
    strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S %Z", &tm);
    ogs_free(epoch_to_convert);
    return buf;
}

ogs_time_t get_time_from_timespec(struct timespec *ts)
{
    return ogs_time_from_sec(ts->tv_sec) + ts->tv_nsec / 1000UL;
}


long int ascii_to_long(const char *str)
{
    char *endp = NULL;
    long int ret;

    ret = strtol(str, &endp, 10);
    if (endp == NULL || *endp != 0) {
        ogs_error("Failed to convert '%s' to an integer", str);
        ret = 0;
    }
    return ret;
}

uint16_t ascii_to_uint16(const char *str)
{
    long int ret;
    ret = ascii_to_long(str);
    if (ret > UINT16_MAX)
    {
        ogs_error("[%s] cannot be greater than [%d]", str, UINT16_MAX);
        ret = 0;
    }
    return ret;
}



extern char *check_http_content_type(ogs_sbi_http_message_t http, char *content_type)
{
    ogs_hash_index_t *hi;
    for (hi = ogs_hash_first(http.headers);
            hi; hi = ogs_hash_next(hi)) {
        if (!ogs_strcasecmp((const char*)ogs_hash_this_key(hi), OGS_SBI_CONTENT_TYPE)) {
            if (!ogs_strcasecmp((const char*)ogs_hash_this_val(hi), content_type)) {
                    return content_type;
            } else {
                const char *type;
                type = (const char *)ogs_hash_this_val(hi);
                ogs_error( "Unsupported Media Type: received type: %s, should have been %s", type, content_type);
                return NULL;
            }
        }
    }
    return NULL;
}


/* vim:ts=8:sts=4:sw=4:expandtab:
 */
