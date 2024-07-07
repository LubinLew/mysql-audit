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


#ifndef _TLS_DECODER_HPP__
#define _TLS_DECODER_HPP__
/*****************************************************************************/

#include <any>
#include "tls_parameters.hpp"

/*****************************************************************************/

class tls_record_decorder {

public:
    tls_record_decorder(void);
    ~tls_record_decorder(void);

    bool init(int cipher, int mode, tls_bytes_t& key, tls_bytes_t& iv, tls_security_parameters_t& parameter, bool encrypt_then_mac, int version);
    bool decrypt(tls_record_header_t& record, tls_bytes_t& dec);

private:
    bool                       m_init;
    std::any                   m_cipher_handler; //C++17, avoid to include <gcrypt.h>

    int                        m_version; //tls version
    bool                       m_encrypt_then_mac;
    tls_security_parameters_t* m_parameters;
};

/*****************************************************************************/
#endif /* _TLS_DECODER_HPP__ */

