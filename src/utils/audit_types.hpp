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


#ifndef __AUDIT_TYPES_H__
#define __AUDIT_TYPES_H__
/*****************************************************************************/

#include <map>
#include <vector>
#include <memory>
#include <iostream>

#include <stdint.h>

/*****************************************************************************/

using audit_byte_t       = uint8_t;
using audit_bytes_t = std::vector<uint8_t>;

using audit_str_t      = std::string;
using audit_str_arr_t  = std::vector<std::string>;
using audit_str_map_t  = std::map<std::string, std::string>;


#define likely(x)       (__builtin_expect((x),1))
#define unlikely(x)     (__builtin_expect((x),0))


/*****************************************************************************/

enum audit_ret_t {
    RET_OK,
    RET_NG, //error occurred
    RET_ES, //exit session
};

struct audit_tuple_t {
    bool is_v6;

    audit_str_t saddr;
    audit_str_t daddr;

    uint16_t sport;
    uint16_t dport;
};

struct audit_conf_t {
    audit_str_t module_name;

    /* Interface and Port */
    audit_str_t if_name;
    int port;

    /* TLS RSA Private Key */
    audit_str_t rsa_key_path;
    audit_str_t rsa_key_pass;

    /* audit log path(json format) */
    audit_str_t audit_log_path;
};

enum audit_flow_direction_t {
    AUDIT_FLOW_DIR_C2S,
    AUDIT_FLOW_DIR_S2C
};

/*****************************************************************************/
#endif /* __AUDIT_TYPES_H__ */

