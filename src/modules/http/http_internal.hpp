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


#ifndef __HTTP_INTERNAL_HPP__
#define __HTTP_INTERNAL_HPP__
/*****************************************************************************/

#include <time.h>

#include <tls/tls.hpp>

#include <audit_types.hpp>

/*****************************************************************************/

struct http_tuple_t {
    bool is_v6;

    audit_str_t saddr;
    audit_str_t daddr;

    uint16_t sport;
    uint16_t dport;
};


struct http_sess_t {
    bool             is_first_pack;
    bool             is_ssl;
    tls_sess_t*      tls;

    http_tuple_t     tuple;

    struct timespec  sess_start_time;
    struct timespec  req_start_time;      /* request start time */

    audit_str_map_t  req_header; /* request header */
    bool             is_req_body;

    audit_str_map_t  res_header; /* response headers */
    bool             is_res_body;
    bool             is_res_body_chunked;
    bool             is_res_body_gzip;
    bool             is_res_body_deflate;
};

struct http_sess_userdata_t {
    http_sess_t* sess_data;
};

/*****************************************************************************/
#endif /* __HTTP_INTERNAL_HPP__ */

