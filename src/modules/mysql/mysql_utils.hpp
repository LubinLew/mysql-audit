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


#ifndef __MYSQL_UTILS_H__
#define __MYSQL_UTILS_H__
/*****************************************************************************/

#include <unistd.h>
#include <audit_data.hpp>

/*****************************************************************************/

/* for all functions, data is in [start, end), end is not a valid address to access */

audit_str_t mysql_util_get_encode_string(uint8_t **start, uint8_t *end);

audit_str_t mysql_util_get_eof_query_string(uint8_t **start, uint8_t *end);

audit_str_t mysql_util_get_binary_data(uint8_t** start, uint8_t* end, uint16_t type);

uint64_t mysql_util_get_encode_uint(uint8_t** start, uint8_t* end);

size_t mysql_util_get_encode_bytes(uint8_t **start, uint8_t *end, audit_bytes_t &bytes);

bool   mysql_util_get_bitmap_null(audit_bytes_t& bitmap, uint32_t index);

size_t mysql_util_valid_utf8(uint8_t *start, size_t len);

/*****************************************************************************/
#endif /* __MYSQL_UTILS_H__ */

