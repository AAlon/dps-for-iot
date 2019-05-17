/*
 *******************************************************************
 *
 * Copyright 2019 Intel Corporation All rights reserved.
 *
 *-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 */

#include <posix/time.h>
#include <errno.h>
#include <dps/private/timer.h>

struct _DPS_Timer {
    DPS_TimeoutCallback cb;
    void* data;
};

DPS_Timer* DPS_TimerSet(uint16_t timeout, DPS_TimeoutCallback cb, void* data)
{
    return NULL;
}

DPS_Status DPS_TimerReset(DPS_Timer* timer, uint16_t timeout)
{
    if (!timer) {
        return DPS_ERR_NULL;
    }
    return DPS_OK;
}

DPS_Status DPS_TimerCancel(DPS_Timer* timer)
{
    if (!timer) {
        return DPS_ERR_NULL;
    }
    return DPS_OK;
}

int _gettimeofday(struct timeval *tv, const void *tz)
{
    struct timespec ts;
    if (!tv) {
        errno = EFAULT;
        return -1;
    }
    clock_gettime(CLOCK_REALTIME, &ts);
    tv->tv_sec = ts.tv_sec;
    tv->tv_usec = ts.tv_nsec / 1000;
    return 0;
}
