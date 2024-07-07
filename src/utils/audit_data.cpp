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


#include <sstream>
#include <algorithm>
#include <cinttypes>

#include <arpa/inet.h>

#include "audit_data.hpp"
#include "audit_debug.hpp"

using namespace std;

/*****************************************************************************/

#ifdef _STRICT_DATA_CHECK
#define _AUDIT_REMAIN_DATA_LEN_CHK(_start, _end, _datalen, _error)  {         \
  if (_end <= *_start) {                                                      \
        audit_debug_err("STRICT CHECK FAILED at %s:%d,start:%p,end:%p,len:%u",\
        __FILE__, __LINE__, *_start, _end, _datalen);                         \
        return (_error);                                                      \
  } else {                                                                    \
    size_t _remain = _end -*_start;                                           \
    if (_remain < _datalen) {                                                 \
        audit_debug_err("STRICT CHECK FAILED at %s:%d,_remain:%u,_datalen:%u",\
        __FILE__, __LINE__, _remain, _datalen);                               \
        return (_error);                                                      \
    }                                                                         \
  }                                                                           \
}
#else /* _STRICT_DATA_CHECK */
#warning _STRICT_DATA_CHECK macro is disabled
#define _AUDIT_REMAIN_DATA_LEN_CHK(_start, _end, _datalen, _error)
#endif /* _STRICT_DATA_CHECK */

#define _AUDIT_GET_REMAIN_LEN(_start, _end)   \
    _end > (*_start) ? _end - (*_start) : 0

/*****************************************************************************/

int8_t audit_data_get_sint8(uint8_t** start, uint8_t* end)
{
    _AUDIT_REMAIN_DATA_LEN_CHK(start, end, 1, 0);

    int8_t* data  = (int8_t*)(*start);
    *start = *start + 1;

    return *data;
}


uint8_t audit_data_get_uint8(uint8_t** start, uint8_t* end)
{
    _AUDIT_REMAIN_DATA_LEN_CHK(start, end, 1, 0);

    uint8_t* data  = *start;
    *start = *start + 1;

    return *data;
}


int16_t audit_data_get_sint16(uint8_t **start, uint8_t *end)
{
    _AUDIT_REMAIN_DATA_LEN_CHK(start, end, 2, 0);

    int16_t* data  = (int16_t*)(*start);
    *start = *start + 2;
    return *data;
}


uint16_t audit_data_get_uint16(uint8_t **start, uint8_t *end)
{
    _AUDIT_REMAIN_DATA_LEN_CHK(start, end, 2, 0);

    uint16_t* data  = (uint16_t*)(*start);
    *start = *start + 2;
    return *data;
}


uint16_t audit_data_get_uint16_be(uint8_t **start, uint8_t *end)
{
    _AUDIT_REMAIN_DATA_LEN_CHK(start, end, 2, 0);
#if 0
    uint8_t* data  = *start;
    *start = *start + 2;

    uint32_t a = data[1];
    uint32_t b = data[0];

    uint16_t result  = (uint16_t)((b << 8) + a);
    return result;
#else
    uint16_t* data  = (uint16_t*)(*start);
    *start = *start + 2;
    return ntohs(*data);
#endif
}


uint32_t audit_data_get_uint24(uint8_t **start, uint8_t *end)
{
    _AUDIT_REMAIN_DATA_LEN_CHK(start, end, 3, 0);

    uint8_t* data = *start;

    uint32_t a = data[0];
    uint32_t b = data[1];
    uint32_t c = data[2];

    uint32_t result  = (c << 16) + (b << 8) + a;
    *start = *start + 3;
    return result;
}


uint32_t audit_data_get_uint24_be(uint8_t **start, uint8_t *end)
{
    _AUDIT_REMAIN_DATA_LEN_CHK(start, end, 3, 0);

    uint8_t* data = *start;

    uint32_t a = data[2];
    uint32_t b = data[1];
    uint32_t c = data[0];

    uint32_t result  = (c << 16) + (b << 8) + a;
    *start = *start + 3;
    return result;
}


int32_t audit_data_get_sint32(uint8_t **start, uint8_t *end)
{
    _AUDIT_REMAIN_DATA_LEN_CHK(start, end, 4, 0);

    int32_t* data  = (int32_t*)(*start);
    *start = *start + 4;
    return *data;
}


uint32_t audit_data_get_uint32(uint8_t **start, uint8_t *end)
{
    _AUDIT_REMAIN_DATA_LEN_CHK(start, end, 4, 0);

    uint32_t* data  = (uint32_t*)(*start);
    *start = *start + 4;
    return *data;
}


uint32_t audit_data_get_uint32_be(uint8_t **start, uint8_t *end)
{
    _AUDIT_REMAIN_DATA_LEN_CHK(start, end, 4, 0);
#if 0
    uint8_t* data = *start;
    *start = *start + 4;

    uint32_t a = data[3];
    uint32_t b = data[2];
    uint32_t c = data[1];
    uint32_t d = data[0];

    uint32_t result  = (d << 24) + (c << 16) + (b << 8) + a;
    return result;
#else
    uint32_t* data  = (uint32_t*)(*start);
    *start = *start + 4;
    return ntohl(*data);
#endif
}


int64_t audit_data_get_sint64(uint8_t **start, uint8_t *end)
{
    _AUDIT_REMAIN_DATA_LEN_CHK(start, end, 8, 0);

    int64_t* data  = (int64_t*)(*start);
    *start = *start + 8;
    return *data;
}


uint64_t audit_data_get_uint64(uint8_t **start, uint8_t *end)
{
    _AUDIT_REMAIN_DATA_LEN_CHK(start, end, 8, 0);

    uint64_t* data  = (uint64_t*)(*start);
    *start = *start + 8;
    return *data;
}


float audit_data_get_float(uint8_t **start, uint8_t *end)
{
    _AUDIT_REMAIN_DATA_LEN_CHK(start, end, sizeof(float), 0);

    float* data = (float*)(*start);
    *start = *start + 4;
    return *data;
}


double audit_data_get_double(uint8_t **start, uint8_t *end)
{
    _AUDIT_REMAIN_DATA_LEN_CHK(start, end, sizeof(double), 0);

    double* data = (double*)(*start);
    *start = *start + 8;
    return *data;
}


uint8_t* audit_data_get_string_nul(uint8_t** start, uint8_t* end, size_t* len)
{
    _AUDIT_REMAIN_DATA_LEN_CHK(start, end, 1, nullptr);

    uint8_t* data  = *start;
    uint8_t* sta   = *start;

    while (sta < end) {
        if (*sta == 0x00) {
            *start = sta + 1;
            if (len) {
                *len = sta - data;
            }
            break;
        }
        ++sta;
    }
    if (sta >= end) {
        return nullptr;
    }

    return data;
}


audit_str_t audit_data_get_string(uint8_t **start, uint8_t *end)
{
    size_t length = 0;
    uint8_t *target = audit_data_get_string_nul(start, end, &length);
    if (target) {
        return std::string((char*)target, length);
    }

    return "";
}



size_t audit_data_get_eof_bytes(uint8_t **start, uint8_t *end, audit_bytes_t &bytes)
{
    _AUDIT_REMAIN_DATA_LEN_CHK(start, end, 0, 0);

    size_t len = _AUDIT_GET_REMAIN_LEN(start, end);
    for (size_t i = 0; i < len; i++) {
        bytes.push_back(*(*start + i));
    }
    *start = end;

    return len;
}


audit_str_t audit_data_get_eof_string(uint8_t **start, uint8_t *end)
{
    _AUDIT_REMAIN_DATA_LEN_CHK(start, end, 0, "");

    uint8_t* new_start = *start;
    size_t   len = _AUDIT_GET_REMAIN_LEN(start, end);

    *start = end;

    return audit_str_t((char*)new_start, len);
}



size_t audit_data_skip_bytes(uint8_t **start, uint8_t *end, size_t len)
{
    _AUDIT_REMAIN_DATA_LEN_CHK(start, end, len, 0);

    uint8_t* new_end = *start + len;
    if (new_end <= end) {
        *start = *start + len;
        return len;
    }

    return 0;
}


size_t audit_data_get_bytes(uint8_t **start, uint8_t *end, audit_bytes_t &bytes, size_t len)
{
    _AUDIT_REMAIN_DATA_LEN_CHK(start, end, len, 0);

    uint8_t *new_end = *start + len;
    if (new_end <= end) {
        for (size_t i = 0; i < len; i++) {
            bytes.push_back(*(*start + i));
        }
        *start = *start + len;
        return len;
    }

    return 0;
}


audit_str_t audit_data_get_fixed_string(uint8_t **start, uint8_t *end, size_t len)
{
    _AUDIT_REMAIN_DATA_LEN_CHK(start, end, len, "");

    const char* s = (const char*)(*start);
    *start = *start + len;
    return audit_str_t(s, len);
}

/* string endwith CRLF, this is for Redis */
audit_str_t audit_data_get_crlf_string(uint8_t **start, uint8_t *end)
{
    _AUDIT_REMAIN_DATA_LEN_CHK(start, end, 3, "");

    for (uint8_t* s = *start; s < end - 1; s++) {
        if (s[0] == '\r' && s[1] == '\n') {
            auto result = audit_str_t(*start, s);
            *start = s + 2;
            return result;
        }
    }

    return "";
}



size_t audit_data_get_remain_length(uint8_t** start, uint8_t* end)
{
    return _AUDIT_GET_REMAIN_LEN(start, end);
}


uint32_t audit_data_make_word(uint16_t upper, uint16_t lower)
{
    uint32_t new_upper = upper;
    uint32_t new_lower = lower;

    return (new_upper << 16) + new_lower;
}

/*****************************************************************************/

