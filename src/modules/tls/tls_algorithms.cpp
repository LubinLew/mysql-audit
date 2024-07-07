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

#include <audit_data.hpp>
#include <audit_debug.hpp>

#include "tls_prf.hpp"
#include "tls_crypto.hpp"
/*****************************************************************************/

/* 
 * https://wiki.mozilla.org/Security/Cipher_Suites
 * https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
 */

static const tls_cipher_suite_t g_cipher_suites[] = {
    { 0x002f, GCRY_CIPHER_AES128,      GCRY_CIPHER_MODE_CBC, GCRY_MAC_HMAC_SHA1,   "TLS_RSA_WITH_AES_128_CBC_SHA"         },
    { 0x0035, GCRY_CIPHER_AES256,      GCRY_CIPHER_MODE_CBC, GCRY_MAC_HMAC_SHA1,   "TLS_RSA_WITH_AES_256_CBC_SHA"         },
    { 0x003c, GCRY_CIPHER_AES128,      GCRY_CIPHER_MODE_CBC, GCRY_MAC_HMAC_SHA256, "TLS_RSA_WITH_AES_128_CBC_SHA256"      },
    { 0x003d, GCRY_CIPHER_AES256,      GCRY_CIPHER_MODE_CBC, GCRY_MAC_HMAC_SHA256, "TLS_RSA_WITH_AES_256_CBC_SHA256"      },
    { 0x0041, GCRY_CIPHER_CAMELLIA128, GCRY_CIPHER_MODE_CBC, GCRY_MAC_HMAC_SHA1,   "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"    },
    { 0x0084, GCRY_CIPHER_CAMELLIA256, GCRY_CIPHER_MODE_CBC, GCRY_MAC_HMAC_SHA1,   "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"    },
    { 0x0096, GCRY_CIPHER_SEED,        GCRY_CIPHER_MODE_CBC, GCRY_MAC_HMAC_SHA1,   "TLS_RSA_WITH_SEED_CBC_SHA"            },
    { 0x009c, GCRY_CIPHER_AES128,      GCRY_CIPHER_MODE_GCM, GCRY_MAC_HMAC_SHA256, "TLS_RSA_WITH_AES_128_GCM_SHA256"      },
    { 0x009d, GCRY_CIPHER_AES128,      GCRY_CIPHER_MODE_CBC, GCRY_MAC_HMAC_SHA384, "TLS_RSA_WITH_AES_256_GCM_SHA384"      },
    { 0x00ba, GCRY_CIPHER_CAMELLIA128, GCRY_CIPHER_MODE_CBC, GCRY_MAC_HMAC_SHA256, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x00c0, GCRY_CIPHER_CAMELLIA256, GCRY_CIPHER_MODE_CBC, GCRY_MAC_HMAC_SHA256, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0xc07a, GCRY_CIPHER_CAMELLIA128, GCRY_CIPHER_MODE_GCM, GCRY_MAC_HMAC_SHA256, "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xc07b, GCRY_CIPHER_CAMELLIA256, GCRY_CIPHER_MODE_GCM, GCRY_MAC_HMAC_SHA384, "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
};


bool tls_search_cipher_suite(tls_sess_t& sess, uint16_t number)
{
    tls_security_parameters_t& parameters = sess.paramters;

    for (size_t i = 0; i < sizeof(g_cipher_suites)/sizeof(tls_cipher_suite_t); i++) {
        if (g_cipher_suites[i].number == (uint32_t)number) {
            parameters.bulk_cipher_algorithm = g_cipher_suites[i].encryption_type;
            parameters.cipher_type = g_cipher_suites[i].encryption_mode;
            parameters.mac_algorithm = g_cipher_suites[i].hmac_type;
            if (sess.version > TLS_VER_1_1) {
                /* RFC TLSv1.2
                 * New cipher suites MUST explicitly specify a PRF and, in general, 
                 * SHOULD use the TLS PRF with SHA-256 or a stronger standard hash function. 
                */
                switch (parameters.mac_algorithm) {
                case GCRY_MAC_HMAC_SHA384:
                case GCRY_MAC_HMAC_SM3:
                case GCRY_MAC_POLY1305:
                    parameters.prf_algorithm = parameters.mac_algorithm;
                    break;
                default:
                    parameters.prf_algorithm = GCRY_MAC_HMAC_SHA256;
                    break;
                }
            } else {
                parameters.prf_algorithm = g_cipher_suites[i].hmac_type;
            }

            audit_debug_dbg("cipher_suite: %s", g_cipher_suites[i].name);
            return true;
        }
    }

    return false;
}


/* https://www.rfc-editor.org/rfc/rfc5246#appendix-C
 *
 * MAC       Algorithm    mac_length  mac_key_length
 * --------  -----------  ----------  --------------
 * NULL      N/A              0             0
 * MD5       HMAC-MD5        16            16
 * SHA       HMAC-SHA1       20            20
 * SHA256    HMAC-SHA256     32            32
 * SHA384    HMAC-SHA384     48            ?
 * SM3       HMAC_SM3        32            ?

 * mac_length == gcry_mac_get_algo_maclen(HMAC_Algorithm)
 *
 * mac_key_length != gcry_mac_get_algo_keylen(HMAC_Algorithm)
 * gcry_mac_get_algo_keylen() returns length of the key for the specified MAC algorithm. 
 * If the algorithm supports multiple key lengths, the default supported key length is returned
 */
struct tls_mac_keylen_t {
    int hmac_algorithm;
    int mac_key_length;
};

static int tls_get_mac_key_length(int hmac)
{
    static tls_mac_keylen_t _tbl[] = {
        {GCRY_MAC_NONE,        0 },
        {GCRY_MAC_HMAC_MD5,    16},
        {GCRY_MAC_HMAC_SHA1,   20},
        {GCRY_MAC_HMAC_SM3,    32},
        {GCRY_MAC_HMAC_SHA256, 32},
        {GCRY_MAC_HMAC_SHA384, 48}
    };

    for (size_t i = 0; i < sizeof(_tbl)/sizeof(_tbl[0]); i++) {
        if (_tbl[i].hmac_algorithm == hmac) {
            return _tbl[i].mac_key_length;
        }
    }

    return -1;
}

/*
extended_master_secret = PRF(pre_master_secret, "extended master secret", session_hash)

When a full TLS handshake takes place, we define
     session_hash = Hash(handshake_messages)
where "handshake_messages" refers to all handshake messages sent or received, 
starting at the ClientHello up to and including the ClientKeyExchange message, 
including the type and length fields of the handshake messages.

For TLS 1.2, the "Hash" function is the one defined in Section 7.4.9
of [RFC5246] for the Finished message computation.  For all previous
versions of TLS, the "Hash" function computes the concatenation of
MD5 and SHA1.

There is no "session_hash" for resumed handshakes, as they do not
lead to the creation of a new session.

master_secret = PRF(pre_master_secret, "master secret", ClientHello.random + ServerHello.random)


key_block = PRF(tls_security_parameters_t.master_secret,
                   "key expansion",
                   tls_security_parameters_t.server_random +
                   tls_security_parameters_t.client_random);

iv_block = PRF("", "IV block", tls_security_parameters_t.client_random +
               tls_security_parameters_t.server_random);

*/

bool tls_generate_keyring_material(tls_sess_t& sess)
{
    bool ret = false;
    tls_security_parameters_t& paramters = sess.paramters;

    // 1.master secure
    if (sess.client_extended_master_secret && sess.server_extended_master_secret) {
        /* RFC 7627 (Session Hash and Extended Master Secret Extension)
         * If both the ClientHello and ServerHello contain the `extended_master_secret` extension,
         * the new session uses the extended master secret computation.
         */
        audit_str_t usage("extended master secret");
        tls_bytes_t empty = {};
        ret = prf(sess, sess.pre_master_secure, usage, sess.session_hash, empty,  paramters.master_secret, TLS_MASTER_SECRET_LENGTH);
        audit_debug_byte_array(paramters.master_secret, "extended master secret");
    } else {
        audit_str_t usage("master secret");
        ret = prf(sess, sess.pre_master_secure, usage, paramters.client_random, paramters.server_random, paramters.master_secret, TLS_MASTER_SECRET_LENGTH);
        audit_debug_byte_array(paramters.master_secret, "master secret");
    }

    int write_mackey_len = tls_get_mac_key_length(paramters.mac_algorithm);

    int write_key_len = gcry_cipher_get_algo_keylen(paramters.bulk_cipher_algorithm);

    int write_iv_len = 0;

    switch (paramters.cipher_type) {
    case GCRY_CIPHER_MODE_CBC:
        write_iv_len = gcry_cipher_get_algo_blklen(paramters.bulk_cipher_algorithm);
        break;

    case GCRY_CIPHER_MODE_GCM:
        /* account for a four-byte salt for client and server side (from client_write_IV and server_write_IV), 
         * see GCMNonce (RFC 5288, AES Galois Counter Mode (GCM) Cipher Suites for TLS)
         * RFC 6367, Addition of the Camellia Cipher Suites to Transport Layer Security (TLS) */
        write_iv_len = 4;
        break;

    case GCRY_CIPHER_MODE_CCM:
        /* RFC 6655: The salt length (tls_security_parameters_t.fixed_iv_length) is 4 octets */
        write_iv_len = 4;
        break;

    case GCRY_CIPHER_MODE_POLY1305:
        /* RFC 7905: tls_security_parameters_t.fixed_iv_length is 12 bytes */
        write_iv_len = 12;
        break;

    default:
        write_iv_len = 0;
    }


    /* https://www.ietf.org/rfc/rfc2246.html#section-6.3
      client_write_MAC_key[tls_security_parameters_t.mac_key_length]
      server_write_MAC_key[tls_security_parameters_t.mac_key_length]
      client_write_key[tls_security_parameters_t.enc_key_length]
      server_write_key[tls_security_parameters_t.enc_key_length]
      client_write_IV[tls_security_parameters_t.fixed_iv_length]
      server_write_IV[tls_security_parameters_t.fixed_iv_length]
    */
    int needed = 0;
    needed += 2 * write_mackey_len;   /* client_write_MAC_key and server_write_MAC_key */
    needed += 2 * write_key_len;      /* encryption key, server and client */
    needed += 2 * write_iv_len;       /* write IV, server and client */

    tls_bytes_t key_expansion = {};
    audit_str_t usage("key expansion");
    ret = prf(sess, paramters.master_secret, usage, paramters.server_random, paramters.client_random, key_expansion, needed);
    size_t offset = 0;
    sess.client_write_MAC_key.assign(key_expansion.begin() + offset, key_expansion.begin() + offset + write_mackey_len);
    offset += write_mackey_len;
    sess.server_write_MAC_key.assign(key_expansion.begin() + offset, key_expansion.begin() + offset + write_mackey_len);
    offset += write_mackey_len;
    sess.client_write_key.assign(key_expansion.begin() + offset, key_expansion.begin() + offset + write_key_len);
    offset += write_key_len;
    sess.server_write_key.assign(key_expansion.begin() + offset, key_expansion.begin() + offset + write_key_len);
    if (write_iv_len) {
        offset += write_key_len;
        sess.client_write_IV_key.assign(key_expansion.begin() + offset, key_expansion.begin() + offset + write_iv_len);
        offset += write_iv_len;
        sess.server_write_IV_key.assign(key_expansion.begin() + offset, key_expansion.begin() + offset + write_iv_len);
    }

    paramters.fixed_iv_length  = write_iv_len;
    paramters.mac_key_length   = write_mackey_len;
    paramters.enc_key_length   = write_key_len;
    paramters.block_length     = gcry_cipher_get_algo_blklen(paramters.bulk_cipher_algorithm);
    paramters.mac_length       = gcry_mac_get_algo_maclen(paramters.mac_algorithm);
    paramters.record_iv_length = paramters.block_length;

    audit_debug_pkg("block_length    :%d", paramters.block_length);
    audit_debug_pkg("record_iv_length:%d", paramters.record_iv_length);
    audit_debug_pkg("fixed_iv_length :%d", paramters.fixed_iv_length);
    audit_debug_pkg("mac_key_length  :%d", paramters.mac_key_length);
    audit_debug_pkg("mac_length      :%d", paramters.mac_length);
    audit_debug_pkg("enc_key_length  :%d", paramters.enc_key_length);

    audit_debug_byte_array(sess.client_write_MAC_key, "client_write_MAC_key");
    audit_debug_byte_array(sess.server_write_MAC_key, "server_write_MAC_key");
    audit_debug_byte_array(sess.client_write_key,     "client_write_key    ");
    audit_debug_byte_array(sess.server_write_key,     "server_write_key    ");
    audit_debug_byte_array(sess.client_write_IV_key,  "client_write_IV_key ");
    audit_debug_byte_array(sess.server_write_IV_key,  "server_write_IV_key ");

    bool encrypt_then_mac = sess.client_encrypt_then_mac && sess.server_encrypt_then_mac;
    sess.client_decorder.init(paramters.bulk_cipher_algorithm, paramters.cipher_type, sess.client_write_key, sess.client_write_IV_key, sess.paramters, encrypt_then_mac, sess.version);
    sess.server_decorder.init(paramters.bulk_cipher_algorithm, paramters.cipher_type, sess.server_write_key, sess.server_write_IV_key, sess.paramters, encrypt_then_mac, sess.version);

    return ret;
}



bool tls_finished_msg_verify(tls_sess_t& sess, audit_str_t& lable, audit_bytes_t& data)
{
    tls_security_parameters_t& params = sess.paramters;
    tls_bytes_t empty  {};
    tls_bytes_t result {};
    size_t length = data.size();

    bool ok = prf(sess, params.master_secret, lable, sess.session_hash, empty, result, length);
    if (!ok) {
        return false;
    }

    audit_debug_byte_array(result, "%s    calc prf", lable.c_str());

    /* compare */
    if (data != result) {
        audit_debug_err("tls_finished_msg_verify failed");
        return false;
    }

    return true;
}

