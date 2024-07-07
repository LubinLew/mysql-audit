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

#include "mysql_utils.hpp"
#include "mysql_debug.hpp"

using namespace std;


/*****************************************************************************/

const static size_t _MYSQL_MAX_STRING_LENGTH = 200;

/*****************************************************************************/

#ifdef _STRICT_DATA_CHECK
#define _MYSQL_REMAIN_DATA_LEN_CHK(_start, _end, _datalen, _error)  {         \
  if (_end <= *_start) {                                                      \
        audit_debug_err("STRICT CHECK FAILED at %s:%d,start:%p,end:%p,len:%u",\
        __FILE__, __LINE__, *_start, _end, _datalen);                         \
        return (_error);                                                      \
  } else {                                                                    \
    size_t _remain = _end -*_start;                                           \
    if (_remain < _datalen) {                                                 \
        return (_error);                                                      \
    }                                                                         \
  }                                                                           \
}
#else /* _STRICT_DATA_CHECK */
#warning _STRICT_DATA_CHECK macro is disabled
#define _MYSQL_REMAIN_DATA_LEN_CHK(_start, _end, _datalen, _error)
#endif /* _STRICT_DATA_CHECK */

#define _MYSQL_GET_REMAIN_LEN(_start, _end)   \
    _end > (*_start) ? _end - (*_start) : 0


/*****************************************************************************/

/* This is for COM_QUERY with long statement, I had seen the statement over 48000 bytes
 * statement maybe contain BLOB(binary) data, json will throw exception, so we need valid UTF8
 */
audit_str_t mysql_util_get_eof_query_string(uint8_t **start, uint8_t *end)
{
    _MYSQL_REMAIN_DATA_LEN_CHK(start, end, 0, "");

    uint8_t* new_start = *start;
    size_t   org_len = _MYSQL_GET_REMAIN_LEN(start, end);
    size_t   tru_len = org_len; //truncate length
    *start = end;

    if (org_len > _MYSQL_MAX_STRING_LENGTH) {
        tru_len = std::min(org_len, _MYSQL_MAX_STRING_LENGTH);
    }

    auto size = mysql_util_valid_utf8(new_start, tru_len);

    audit_str_t eof_str = audit_str_t((char*)new_start, size);

    if (org_len > _MYSQL_MAX_STRING_LENGTH) {
        eof_str += ("...(omit " + to_string(org_len - tru_len) + " bytes)");
    }

    return eof_str;
}


uint64_t mysql_util_get_encode_uint(uint8_t** start, uint8_t* end)
{
    _MYSQL_REMAIN_DATA_LEN_CHK(start, end, 1, 0);

    uint64_t result = 0;
    uint8_t flag = audit_data_get_uint8(start, end);
    if (flag < 0xFB) {//Integer value is this 1 byte integer
        return flag;
    } else if (flag == 0xFB) {//NULL value
        return 0;
    } else if (flag == 0xFC) {//Integer value is encoded in the next 2 bytes (3 bytes total)
        result = audit_data_get_uint16(start, end);
    } else if (flag == 0xFD) {//Integer value is encoded in the next 3 bytes (4 bytes total)
        result = audit_data_get_uint24(start, end);
    } else if (flag == 0xFE) {//Integer value is encoded in the next 8 bytes (9 bytes total)
        result = audit_data_get_uint64(start, end);
    }

    return result;
}


size_t mysql_util_get_encode_bytes(uint8_t **start, uint8_t *end, audit_bytes_t &bytes)
{
    _MYSQL_REMAIN_DATA_LEN_CHK(start, end, 1, 0);

    size_t length = mysql_util_get_encode_uint(start, end);
    size_t remain = _MYSQL_GET_REMAIN_LEN(start, end);
    if (length > remain) {
        *start = end;
        audit_debug_err("length=%u, remain=%u", length, remain);
        return 0;
    }

    if (length) {
        audit_data_get_bytes(start, end, bytes, length);
    }

    return length;
}


audit_str_t mysql_util_get_encode_string(uint8_t **start, uint8_t *end)
{
    _MYSQL_REMAIN_DATA_LEN_CHK(start, end, 1, "");

    size_t length = mysql_util_get_encode_uint(start, end);
    size_t remain = _MYSQL_GET_REMAIN_LEN(start, end);
    if (length > remain) {
        *start = end;
        audit_debug_err("length=%u, remain=%u", length, remain);
        return "{nul}";
    }

    if (length) {
        auto result = std::string((char*)*start, length);
        *start = *start + length;
        return result;
    }

    return "{nul}";
}


/* index start from 0
 * NULL-bitmap-byte = ((field-pos + offset) / 8)
 * NULL-bitmap-bit  = ((field-pos + offset) % 8)
 */
bool mysql_util_get_bitmap_null(audit_bytes_t& bitmap, uint32_t index)
{
    uint32_t null_bitmap_byte = (index + 2) / 8;
    uint32_t null_bitmap_bit  = (index + 2) % 8;

    uint32_t bitmap_byte = bitmap[null_bitmap_byte];
    uint32_t bitmap_flag = 1U << null_bitmap_bit;

    return bitmap_byte & bitmap_flag;
}


/*
 * Character Number Range   UTF-8 octet sequence
 * 0000 0000 0000 007F      0xxxxxxx
 * 0000 0080 0000 07FF      110xxxxx 10xxxxxx
 * 0000 0800 0000 FFFF      1110xxxx 10xxxxxx 10xxxxxx
 * 0001 0000 0010 FFFF      11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
*/
size_t mysql_util_valid_utf8(uint8_t *start, size_t len)
{
    int count = 0;
    size_t i = 0;

    for (; i < len; i++) {
        uint32_t byte = start[i];
        if (0 == count) {
            if unlikely(byte & 0b10000000) {/* first bit is 1 */
                if unlikely((byte >> 5) ^ 0b00000110) {
                    if unlikely((byte >> 4) ^ 0b00001110) {
                        if unlikely((byte >> 5) ^ 0b00011110) {
                            break;
                        } else {
                            count = 3; /* (11110xxx) 10xxxxxx 10xxxxxx 10xxxxxx */
                        }
                    } else {
                        count = 2; /* (1110xxxx) 10xxxxxx 10xxxxxx */
                    }
                } else {
                    count = 1; /* (110xxxxx) 10xxxxxx */
                }
            }
        } else {
            if unlikely((byte >> 6) ^ 0b00000010) {
                i -= (count + 1);
                break;
            } else {
                --count;
            }
        }
    }

    if (i != len) {
        audit_debug_warn("found invalid utf8 charset");
    }

    return i;
}

audit_str_t mysql_util_get_binary_data(uint8_t** start, uint8_t* end, uint16_t type)
{
    audit_str_t data_str;

    /*
     * The type of each parameter is made up of two bytes:
     * - the type as in enum_field_types
     * - a flag byte which has the highest bit set if the type is unsigned
     */
    uint32_t real_type   = type & 0x00FF;
    uint32_t is_unsigned = type >> 8;

    switch (real_type) {
    case MYSQL_TYPE_VARCHAR:   // found in test
    case MYSQL_TYPE_STRING:    // offical docs
    case MYSQL_TYPE_VAR_STRING:// guess
        data_str = mysql_util_get_encode_string(start, end);
        break;

    case MYSQL_TYPE_LONGLONG: 
        if (is_unsigned) {
            data_str = std::to_string(audit_data_get_uint64(start, end));
        } else {
            data_str = std::to_string(audit_data_get_sint64(start, end));
        }
        break;

    case MYSQL_TYPE_LONG:
    case MYSQL_TYPE_INT24:
        if (is_unsigned) {
            data_str = std::to_string(audit_data_get_uint32(start, end));
        } else {
            data_str = std::to_string(audit_data_get_sint32(start, end));
        }
        break;

    case MYSQL_TYPE_SHORT:
    case MYSQL_TYPE_YEAR:
        if (is_unsigned) {
            data_str = std::to_string(audit_data_get_uint16(start, end));
        } else {
            data_str = std::to_string(audit_data_get_sint16(start, end));
        }
        break;

    case MYSQL_TYPE_TINY:
        if (is_unsigned) {
            data_str = std::to_string(audit_data_get_uint8(start, end));
        } else {
            data_str = std::to_string(audit_data_get_sint8(start, end));
        }
        break;

    case MYSQL_TYPE_DOUBLE:
        data_str = std::to_string(audit_data_get_double(start, end));
        break;
 
    case MYSQL_TYPE_FLOAT:
        data_str = std::to_string(audit_data_get_float(start, end));
        break;

    case MYSQL_TYPE_DATE:
    case MYSQL_TYPE_DATETIME:
    case MYSQL_TYPE_TIMESTAMP: {
        auto length = audit_data_get_uint8(start, end);
        uint16_t year        = 0;
        uint8_t  month       = 0;
        uint8_t  day         = 0;
        uint8_t  hour        = 0;
        uint8_t  minute      = 0;
        uint8_t  second      = 0;
        uint32_t microsecond = 0;

        if (length >= 4) {
            year   = audit_data_get_uint16(start, end);
            month  = audit_data_get_uint8(start, end);
            day    = audit_data_get_uint8(start, end);
        }
        if (length >= 7) {
            hour   = audit_data_get_uint8(start, end);
            minute = audit_data_get_uint8(start, end);
            second = audit_data_get_uint8(start, end);
        }
        if (length == 11) {
            microsecond = audit_data_get_uint32(start, end);
        }
        char buf[1024] = {0};
        snprintf(buf, 1023, "%d-%02d-%02d %02d:%02d:%02d.%u", year, month, day, hour, minute, second, microsecond);
        data_str = audit_str_t(buf);
        } break;

    case MYSQL_TYPE_TIME: {
        auto length = audit_data_get_uint8(start, end); //(valid values: 0, 8, 12)
        uint8_t  is_negative = 0;
        uint32_t days        = 0;
        uint8_t  hour        = 0;
        uint8_t  minute      = 0;
        uint8_t  second      = 0;
        uint32_t microsecond = 0;

        if (length >= 8) {
            is_negative = audit_data_get_uint8(start, end);
            days        = audit_data_get_uint32(start, end);
            hour        = audit_data_get_uint8(start, end);
            minute      = audit_data_get_uint8(start, end);
            second      = audit_data_get_uint8(start, end);
        }

        if (length == 12) {
            microsecond = audit_data_get_uint32(start, end);
        }

        char buf[1024] = {0};
        snprintf(buf, 1023, "%s%dd %02d:%02d:%02d.%u", is_negative ? "-" : "", days, hour, minute, second, microsecond);
        data_str = audit_str_t(buf);
        } break;

    default:
        audit_debug_err("unknown data type %#02x", real_type);
        data_str = "{unknown data type}";
        break;
    }

    return data_str;
}

/*****************************************************************************/

