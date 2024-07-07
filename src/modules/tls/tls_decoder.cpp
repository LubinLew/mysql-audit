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


#include <gcrypt.h>

#include "tls_internal.hpp"

#include <audit_data.hpp>
#include <audit_debug.hpp>

#include <memory>
/*****************************************************************************/

tls_record_decorder::tls_record_decorder(void)
{
    m_init = false;
    m_cipher_handler = nullptr;
    m_encrypt_then_mac = false;
    m_version = TLS_VER_1_2;
}

tls_record_decorder::~tls_record_decorder(void)
{
    if (m_init) {
        gcry_cipher_hd_t hd = std::any_cast<gcry_cipher_hd_t>(m_cipher_handler);
        gcry_cipher_close(hd);
        m_cipher_handler.reset();
        m_init = false;
        m_encrypt_then_mac = false;
    }
}

bool tls_record_decorder::init(int cipher, int mode, tls_bytes_t& key, tls_bytes_t& iv, tls_security_parameters_t& parameter, bool encrypt_then_mac, int version)
{
    //gcry_cipher_hd_t is pointer type
    gcry_cipher_hd_t hd = nullptr;

//    audit_debug_dbg("cipher:%s", gcry_cipher_algo_name(cipher));

    auto err = gcry_cipher_open(&hd, cipher, mode, 0);
    if (err) {
        audit_debug_err("gcry_cipher_open() failed, %s", gcry_strerror(err));
        return false;
    }

    err = gcry_cipher_setkey(hd, key.data(), gcry_cipher_get_algo_keylen(cipher));
    if (err) {
        audit_debug_err("gcry_cipher_setkey() failed, %s", gcry_strerror(err));
        gcry_cipher_close(hd);
        return false;
    }
    
    if (!iv.empty()) {
        err = gcry_cipher_setiv(hd, iv.data(), gcry_cipher_get_algo_blklen(cipher));
        if (err) {
            audit_debug_err("gcry_cipher_setiv() failed, %s", gcry_strerror(err));
            gcry_cipher_close(hd);
            return false;
        }
    }

    m_cipher_handler = hd;
    m_encrypt_then_mac = encrypt_then_mac;
    m_parameters = &parameter;
    m_version = version;
    m_init = true;

    return true;
}


// encrypt( data || pad ) || MAC , rfc7366 encrypt_then_mac
// encrypt( data || MAC || pad )
bool tls_record_decorder::decrypt(tls_record_header_t& record, tls_bytes_t& dec)
{
    if (!m_init) {
        return false;
    }

    /* decrypt record layer */
    gcry_cipher_hd_t hd = std::any_cast<gcry_cipher_hd_t>(m_cipher_handler);

    size_t out_size = record.length;
    if (m_encrypt_then_mac) {
        out_size -= m_parameters->mac_length;
    }
    std::unique_ptr<uint8_t[]>outbuff = std::make_unique<uint8_t[]>(out_size);
    uint8_t* out = outbuff.get();

    gcry_error_t err = gcry_cipher_decrypt(hd, out, out_size, record.payload, out_size);
    if (err) {
        audit_debug_err("gcry_cipher_decrypt(%u) failed, %s", out_size, gcry_strerror(err));
        return false;
    }

    dec.assign(out, out + out_size);
    audit_debug_byte_dump(dec, "decrypt encrypted data");

    /* get real data */
    if (GCRY_CIPHER_MODE_STREAM == m_parameters->cipher_type) {
        /* struct {
             opaque content[TLSCompressed.length];
             opaque MAC[tls_security_parameters_t.mac_length];
          } GenericStreamCipher;
        */
        if (!m_encrypt_then_mac) {
            size_t no_mac_size = dec.size() - m_parameters->mac_length;
            dec.resize(no_mac_size);
        }
    } else {
        /* struct {
               opaque IV[tls_security_parameters_t.record_iv_length];
               block-ciphered struct {
                   opaque content[TLSCompressed.length];
                   opaque MAC[tls_security_parameters_t.mac_length];
                   uint8 padding[GenericBlockCipher.padding_length];
                   uint8 padding_length;
               };
           } GenericBlockCipher;
        */

        uint8_t padding_length = dec.back();
        if (padding_length >= dec.size()) {
            audit_debug_err("padding_length(%d) >= decrypt_length(%ld)", padding_length, dec.size());
            return false;
        }
        size_t no_padding_size = dec.size() - padding_length - 1;
        audit_debug_pkg("delete(tail) padding size: %d", padding_length + 1);
        dec.resize(no_padding_size);

        if (!m_encrypt_then_mac) {
            if (m_parameters->mac_length > dec.size()) {
                audit_debug_err("mac_length(%d) > decrypt_length(%ld)", m_parameters->mac_length, dec.size());
                return false;
            }
            size_t no_mac_size = dec.size() - m_parameters->mac_length;
            audit_debug_pkg("delete(tail) mac size: %d", m_parameters->mac_length);
            dec.resize(no_mac_size);
        }

        /* delete IV */
        if (TLS_VER_1_2 == m_version) {
            if (m_parameters->record_iv_length >= dec.size()) {
                audit_debug_err("record_iv_length(%d) >= decrypt_length(%ld)", m_parameters->record_iv_length, dec.size());
                return false;
            }
            audit_debug_pkg("delete(head) IV size: %d", m_parameters->record_iv_length);
            dec.erase(dec.begin(), dec.begin() + m_parameters->record_iv_length);
        }
    }

    return true;
}

