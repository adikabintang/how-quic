#include "util.h"

long long get_current_msec()
{
    struct timeval tv;

    gettimeofday(&tv, NULL);

    long long current_ms =
        (long long)(tv.tv_sec) * 1000 +
        (long long)(tv.tv_usec) / 1000;

    return current_ms;
}

long long get_current_usec()
{
    struct timeval timer_usec;
    long long int timestamp_usec;

    if (!gettimeofday(&timer_usec, NULL))
    {
        timestamp_usec = ((long long int)timer_usec.tv_sec) *
                             1000000ll +
                         (long long int)timer_usec.tv_usec;
    }
    else
    {
        timestamp_usec = -1;
    }

    return timestamp_usec;
}