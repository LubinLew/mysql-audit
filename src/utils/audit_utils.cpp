/*  Copyright (C) 2024 LubinLew
    SPDX short identifier: MIT

Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the “Software”), to deal in 
the Software without restriction, including without limitation the rights to use, 
copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the 
Software, and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all 
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, 
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES 
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR 
OTHER DEALINGS IN THE SOFTWARE. */


#include "audit_utils.hpp"

/*
+-----------------------------------------------------------------------+
byte    |    byte 0     |    byte 1     |    byte 2     |    byte 3     |
bit     |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7|
+-------+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
word 0  |   year    | month |     day   |  hour   |   miniute | second  |
+-------+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
width   |  6 bit    | 4 bit |  5 bit    |  5 bit  |  6 bit    | 6 bit   |
*/

union audit_date_un {
    uint32_t date_i;
    struct _date_s {
        uint32_t second:6;
        uint32_t minute:6;
        uint32_t hour:5;
        uint32_t day:5;
        uint32_t month:4;
        uint32_t year:6;
    }date_s;
};

#define AUDIT_DATE_YEAR_OFFSET  120  //since year 2020 (120 = 2020 - 1900)

uint32_t audit_util_date_compress(time_t& t)
{
    audit_date_un cdate;

    struct tm result;
    localtime_r(&t, &result);

    cdate.date_s.year   = result.tm_year - AUDIT_DATE_YEAR_OFFSET;
    cdate.date_s.month  = result.tm_mon;
    cdate.date_s.day    = result.tm_mday;
    cdate.date_s.hour   = result.tm_hour;
    cdate.date_s.minute = result.tm_min;
    cdate.date_s.second = result.tm_sec;

    return cdate.date_i;
}


time_t audit_util_date_decompress(uint32_t date)
{
    audit_date_un cdate;

    cdate.date_i = date;

    struct tm result;
    result.tm_year =     cdate.date_s.year + AUDIT_DATE_YEAR_OFFSET;
    result.tm_mon  =     cdate.date_s.month;
    result.tm_mday =     cdate.date_s.day;
    result.tm_hour =     cdate.date_s.hour;
    result.tm_min  =     cdate.date_s.minute;
    result.tm_sec  =     cdate.date_s.second;

    return mktime(&result);
}

/*
struct timespec {
    time_t   tv_sec;        //seconds
    long     tv_nsec;       // nanoseconds
};
*/
audit_str_t audit_util_time_diff_from_now(struct timespec& start)
{
    struct timespec end;
    timespec_get(&end, TIME_UTC);

    uint64_t nsec = 0;
    time_t sec = end.tv_sec - start.tv_sec;
    if (end.tv_nsec < start.tv_nsec) {
        --sec;
        nsec = 1000000000UL - start.tv_nsec + end.tv_nsec;
    } else {
        nsec = end.tv_nsec - start.tv_nsec;
    }

    double dsec = (double)nsec / 1000000000UL;
    char buf[32] = {0};
    snprintf(buf, 31, "%.8f", dsec + (double)sec);

    return audit_str_t(buf);
}


audit_str_t audit_util_time_get(struct timespec& start)
{
    return std::to_string(start.tv_sec);
}


audit_str_t audit_util_time_get_now(void)
{
    struct timespec time;

    timespec_get(&time, TIME_UTC);

    return std::to_string(time.tv_sec);
}


