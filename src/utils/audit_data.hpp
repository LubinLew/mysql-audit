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


#ifndef __AUDIT_DATA_H__
#define __AUDIT_DATA_H__
/*****************************************************************************/

#include <unistd.h>
#include "audit_types.hpp"

/*****************************************************************************/

/* for all functions, data is in [start, end), end is not a valid address to access */

int8_t   audit_data_get_sint8(uint8_t** start, uint8_t* end);
uint8_t  audit_data_get_uint8(uint8_t** start, uint8_t* end);

int16_t  audit_data_get_sint16(uint8_t **start, uint8_t *end);
uint16_t audit_data_get_uint16(uint8_t **start, uint8_t *end);
uint16_t audit_data_get_uint16_be(uint8_t **start, uint8_t *end);

uint32_t audit_data_get_uint24(uint8_t **start, uint8_t *end);
uint32_t audit_data_get_uint24_be(uint8_t **start, uint8_t *end);

int32_t  audit_data_get_sint32(uint8_t **start, uint8_t *end);
uint32_t audit_data_get_uint32(uint8_t **start, uint8_t *end);
uint32_t audit_data_get_uint32_be(uint8_t **start, uint8_t *end);

int64_t  audit_data_get_sint64(uint8_t **start, uint8_t *end);
uint64_t audit_data_get_uint64(uint8_t** start, uint8_t* end);

float    audit_data_get_float(uint8_t **start, uint8_t *end);
double   audit_data_get_double(uint8_t **start, uint8_t *end);

uint32_t audit_data_make_word(uint16_t upper, uint16_t lower);

audit_str_t audit_data_get_string(uint8_t **start, uint8_t *end);
audit_str_t audit_data_get_eof_string(uint8_t **start, uint8_t *end);
audit_str_t audit_data_get_fixed_string(uint8_t **start, uint8_t *end, size_t len);
audit_str_t audit_data_get_crlf_string(uint8_t **start, uint8_t *end);

size_t audit_data_skip_bytes(uint8_t **start, uint8_t *end, size_t len);
size_t audit_data_get_bytes(uint8_t **start, uint8_t *end, audit_bytes_t &bytes, size_t len);
size_t audit_data_get_eof_bytes(uint8_t **start, uint8_t *end, audit_bytes_t &bytes);

size_t audit_data_get_remain_length(uint8_t** start, uint8_t* end);

/*****************************************************************************/
#endif /* __AUDIT_DATA_H__ */

