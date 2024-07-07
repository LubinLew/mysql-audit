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


#ifndef __TLS_EXTERNAL__
#define __TLS_EXTERNAL__
/*****************************************************************************/

#include <iostream>
#include <vector>
#include <stdint.h>

/*****************************************************************************/

struct tls_sess_t;

using tls_bytes_t = std::vector<uint8_t>;

enum tls_conn_end_t {
    TLS_CONN_END_CLIENT,
    TLS_CONN_END_SERVER
};

/*****************************************************************************/

bool tls_init(std::string& private_key_path, std::string& private_key_pass);
void tls_free(void);


tls_sess_t* tls_create_session(void);
void tls_destroy_session(tls_sess_t* sess);


bool tls_decrypt(tls_sess_t* sess, tls_bytes_t& data, tls_conn_end_t endpoint);


/* is there any application data avaliable */
bool tls_client_empty(tls_sess_t* sess);
bool tls_server_empty(tls_sess_t* sess);

/* get application data */
tls_bytes_t& tls_client_payload(tls_sess_t* sess);
tls_bytes_t& tls_server_payload(tls_sess_t* sess);


/*****************************************************************************/
#endif /* __TLS_EXTERNAL__ */

