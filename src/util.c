#include "util.h"

long long int get_current_msec()
{
    long long int timestamp_msec;
    struct timeb timer_msec;

    if (!ftime(&timer_msec))
    {
        timestamp_msec = ((long long int)timer_msec.time) * 1000ll +
                         (long long int)timer_msec.millitm;
    }
    else
    {
        timestamp_msec = -1;
    }

    return timestamp_msec;
}

long long int get_current_usec()
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