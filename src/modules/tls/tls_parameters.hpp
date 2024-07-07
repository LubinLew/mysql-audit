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


#ifndef __TLS_PARAMETERS__
#define __TLS_PARAMETERS__
/*****************************************************************************/

#include "tls.hpp"

/*****************************************************************************/

//https://www.rfc-editor.org/rfc/rfc5246#appendix-A.6
struct tls_security_parameters_t {
    int          prf_algorithm;  //SHA256, SHA384, SM3
    int          bulk_cipher_algorithm; //rc4, 3des, aes
    int          cipher_type;    // stream, block, aead
    uint8_t      enc_key_length;
    uint8_t      block_length;
    uint8_t      fixed_iv_length;
    uint8_t      record_iv_length;
    int          mac_algorithm; // hmac_md5, hmac_sha1, hmac_sha256, hmac_sha384, hmac_sha512
    uint8_t      mac_length;
    uint8_t      mac_key_length;
    uint8_t      compression_algorithm; // null or DEFALTE
    tls_bytes_t  master_secret; // 48 bytes
    tls_bytes_t  client_random; // 32 bytes
    tls_bytes_t  server_random; // 32 bytes
};


struct tls_record_header_t {
    uint8_t   type;
    uint16_t  version; //The version of the protocol being employed.
    uint16_t  length;  //The length (in bytes) of the following payload
    uint8_t*  payload;
};

#define tls_record_header_size (5)

/*****************************************************************************/
#endif /* __TLS_PARAMETERS__ */