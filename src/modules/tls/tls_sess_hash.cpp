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


#include <audit_debug.hpp>

#include "tls_internal.hpp"
#include "tls_crypto.hpp"

#include <gcrypt.h>
/*****************************************************************************/

static bool tls_handshake_hash(tls_sess_t& sess, tls_bytes_t& out)
{
    tls_bytes_t md5hash = {};
    tls_md_mgr_t* md5 = tls_md_init(GCRY_MAC_HMAC_MD5);
    tls_md_update(md5, sess.handshake_message);
    tls_md_final(md5, md5hash);
    tls_md_cleanup(md5);

    tls_bytes_t sha1hash = {};
    tls_md_mgr_t* sha = tls_md_init(GCRY_MAC_HMAC_SHA1);
    tls_md_update(sha,sess.handshake_message);
    tls_md_final(sha, sha1hash);
    tls_md_cleanup(sha);

    out.clear();
    out.insert(out.end(), md5hash.begin(),   md5hash.end());
    out.insert(out.end(), sha1hash.begin(), sha1hash.end());

    return true;
}

static bool tls12_handshake_hash(tls_sess_t& sess, int md, tls_bytes_t& out)
{
    tls_md_mgr_t* hd = tls_md_init(md);
    if (hd) {
        tls_md_update(hd, sess.handshake_message);
        tls_md_final(hd, out);
        tls_md_cleanup(hd);
        return true;
    }

    return false;
}

/*
When a full TLS handshake takes place, we define

       session_hash = Hash(handshake_messages)

 where "handshake_messages" refers to all handshake messages sent or received, 
 starting at the ClientHello up to and including the ClientKeyExchange message, 
 including the type and length fields of the handshake messages.
*/
static bool tls_session_hash(tls_sess_t& sess, tls_bytes_t& out)
{
    bool ret = true;

    switch (sess.version) {
    case TLS_VER_1_0:
    case TLS_VER_1_1:
         ret = tls_handshake_hash(sess, out);
        break;

    case TLS_VER_1_2:
        ret = tls12_handshake_hash(sess, sess.paramters.prf_algorithm, out);
        break;

    default:
        audit_debug_err("Unsupported Protocol Version %#x", sess.version);
        ret = false;
        break;
    }

    return ret;
}


bool tls_handshake_messages_push(tls_sess_t& sess, uint8_t type, uint8_t* start, uint8_t* end)
{
    if (sess.session_hash_finished) {
        return true;
    }

//    audit_debug_pkg("pushd length : %d", end - start);

    bool ret = true;

    switch (type) {
    case hello_request: /* not include this */
        break;

    case client_key_exchange: /* session hash for extend master secure, include this */
        sess.handshake_message.insert(sess.handshake_message.end(), start, end);
        if (sess.client_extended_master_secret && sess.server_extended_master_secret) {
            ret = tls_session_hash(sess, sess.session_hash);
            audit_debug_byte_array(sess.session_hash, "client_key_exchange sess hash");
        }
        break;

    case finished: /* session hash for finished msg verify, not include this */
        if (TLS_CONN_END_CLIENT == sess.endpoint) {
            ret = tls_session_hash(sess, sess.session_hash);
            audit_debug_byte_array(sess.session_hash, "client finished sess hash");
            sess.handshake_message.insert(sess.handshake_message.end(), start, end);
        } else {
            ret = tls_session_hash(sess, sess.session_hash);
            audit_debug_byte_array(sess.session_hash, "server finished sess hash");
            sess.session_hash_finished = true;
            sess.handshake_message.clear();
        }
        break;
 
    default:
        sess.handshake_message.insert(sess.handshake_message.end(), start, end);
        break;
    }

//    audit_debug_pkg("total length : %ld", sess.handshake_message.size());
    return ret;
}


