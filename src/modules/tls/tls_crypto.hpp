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


#ifndef __TLS_CRYPTO_HPP__
#define __TLS_CRYPTO_HPP__
/*****************************************************************************/

#include "tls_internal.hpp"

/*****************************************************************************/

struct tls_md_mgr_t;
struct tls_hmac_mgr_t;

/*****************************************************************************/

tls_md_mgr_t* tls_md_init(int algo);
void tls_md_update(tls_md_mgr_t* mgr, tls_bytes_t& data);
void tls_md_final(tls_md_mgr_t* mgr, tls_bytes_t& result);
void tls_md_reset(tls_md_mgr_t* mgr);
void tls_md_cleanup(tls_md_mgr_t* mgr);

tls_hmac_mgr_t* tls_hmac_init(int algo);
bool tls_hmac_setkey(tls_hmac_mgr_t* mgr, tls_bytes_t& data);
void tls_hmac_update(tls_hmac_mgr_t* mgr, tls_bytes_t& data);
bool tls_hmac_final(tls_hmac_mgr_t* mgr, tls_bytes_t& result);
void tls_hmac_reset(tls_hmac_mgr_t* mgr);
void tls_hmac_cleanup(tls_hmac_mgr_t* mgr);

/*****************************************************************************/
#endif /* __TLS_CRYPTO_HPP__ */

