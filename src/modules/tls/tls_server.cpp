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


#include <audit_data.hpp>
#include <audit_debug.hpp>

#include "tls_debug.hpp"
#include "tls_internal.hpp"

#include <gcrypt.h>

/*****************************************************************************/

bool tls_search_cipher_suite(tls_sess_t& sess, uint16_t number);
bool tls_finished_msg_verify(tls_sess_t& sess, audit_str_t& lable, audit_bytes_t& data);
bool tls_handshake_messages_push(tls_sess_t& sess, uint8_t type, uint8_t* start, uint8_t* end);

/*****************************************************************************/

/*
struct {
    ProtocolVersion server_version;
    Random random;
    SessionID session_id;
    CipherSuite cipher_suite;
    CompressionMethod compression_method;
    select (extensions_present) {
        case false:
            struct {};
        case true:
            Extension extensions<0..2^16-1>;
    };
} ServerHello;
*/
bool tls_handshake_server_hello(tls_sess_t& sess, uint8_t* start, uint8_t* end)
{
    ServerHello hello = {};

    hello.version = audit_data_get_uint16_be(&start, end);

    sess.version = hello.version;

    audit_data_get_bytes(&start, end, sess.paramters.server_random, 32);

    hello.session_id_length = audit_data_get_uint8(&start, end);
    if (hello.session_id_length) {/* session resumption(by SESSION ID) */
        audit_data_get_bytes(&start, end, sess.session_id, hello.session_id_length);
    }

    hello.cipher_suite = audit_data_get_uint16_be(&start, end);
    bool found = tls_search_cipher_suite(sess, hello.cipher_suite);
    if (!found) {
        audit_debug_err("cipher_suite[%#x] not supported", hello.cipher_suite);
        return false;
    }

#if 0
    /* Key Exchange Check */
    if (tls.cipher_suite.kex != KEX_RSA) {
        audit_debug_err("Key Exchange Althm is Not RSA, %u", tls.cipher_suite.kex);
        return RET_NG;
    }
#endif

    sess.paramters.compression_algorithm = audit_data_get_uint8(&start, end);

    //extensions
    if (audit_data_get_remain_length(&start, end) < 2) {/* no extensions */
        return true;
    }

    audit_data_skip_bytes(&start, end, 2); //extensions length
    while (start < end) {
        uint16_t type   = audit_data_get_uint16_be(&start, end);
        uint16_t length = audit_data_get_uint16_be(&start, end);
        switch (type) {
        case encrypt_then_mac:
            sess.server_encrypt_then_mac = true;
            audit_debug_dbg("ServerHello support encrypt_then_mac");
            break;
        case extended_master_secret:
            sess.server_extended_master_secret = true;
            audit_debug_dbg("ServerHello support extended_master_secret");
            break;
        default:
            audit_data_skip_bytes(&start, end, length);
            break;
        }
    }

    return true;
}

/* https://www.rfc-editor.org/rfc/rfc8446#section-4.6.1
 */
static bool tls_handshake_new_session_ticket(tls_sess_t& sess, uint8_t* start, uint8_t* end)
{
    NewSessionTicket ticket = {};

    ticket.ticket_lifetime = audit_data_get_uint32_be(&start, end);
//    ticket.ticket_age_add  = audit_data_get_uint32_be(&start, end);
    ticket.ticket_length   = audit_data_get_uint16_be(&start, end);
    audit_data_get_bytes(&start, end, ticket.ticket_data, ticket.ticket_length);

    return true;
}

static bool tls_handshake_certificate(tls_sess_t& sess, uint8_t* start, uint8_t* end)
{
    return true;
}

static bool tls_handshake_certificate_request(tls_sess_t& sess, uint8_t* start, uint8_t* end)
{
    return true;
}

static bool tls_handshake_server_key_exchange(tls_sess_t& sess, uint8_t* start, uint8_t* end)
{
    return true;
}

static bool tls_handshake_server_hello_done(tls_sess_t& sess, uint8_t* start, uint8_t* end)
{
    return true;
}


static bool tls_handshake_finished(tls_sess_t& sess, uint8_t* start, uint8_t* end)
{
    audit_bytes_t verify_data(start, end); 
    audit_debug_byte_array(verify_data, "server finished verify_data");
    audit_str_t finished_label("server finished");
    return tls_finished_msg_verify(sess, finished_label, verify_data);
}


bool tls_record_handshake_server(tls_sess_t& sess, tls_record_header_t& record)
{
    uint8_t* start = record.payload;
    uint8_t* end   = start + record.length;

    bool ret = true;

    if (sess.server_change_cipher_spec_sent) { //Encrypted Handshake Message
        audit_debug_dbg("Encrypted Server Handshake Message");
        tls_bytes_t decrypted_record = {};
        bool ok = sess.server_decorder.decrypt(record, decrypted_record);
        if (!ok) {
            return false;
        }
        start = decrypted_record.data();
        end   = start + decrypted_record.size();
    }

    while (start < end) { /* one record may contain multipe handshake msg */
        uint8_t* msg_start = start;
        uint8_t  msg_type  = audit_data_get_uint8(&start, end);
        uint32_t length    = audit_data_get_uint24_be(&start, end);
        uint8_t* msg_end   = start + length;
        uint32_t left_size = end - start;
  
        audit_debug_dbg("<Handshake: %s> length: %lu", tls_info_handshake_type(msg_type), length);
        tls_handshake_messages_push(sess, msg_type, msg_start, msg_end);

        if (length > left_size) {
            audit_debug_err("handshake msg spec length:%u, but only %u left", length, left_size);
            return false;
        }

        switch(msg_type) {
        case server_hello:
            ret = tls_handshake_server_hello(sess, start, end);
            break;

        case new_session_ticket:
            ret = tls_handshake_new_session_ticket(sess, start, end);
            break;

        case certificate:
            ret = tls_handshake_certificate(sess, start, end);
            break;

        case server_key_exchange:
            ret = tls_handshake_server_key_exchange(sess, start, end);
            break;

        case certificate_request:
            ret = tls_handshake_certificate_request(sess, start, end);
            break;

        case server_hello_done:
            ret = tls_handshake_server_hello_done(sess, start, end);
            break;

        case finished:
            ret = tls_handshake_finished(sess, start, end);
            break;

        default: /* Ignore */
            break;
        }

        if (!ret) {
            return false;
        }

        start += length;
    }

    return ret;
}

/*****************************************************************************/

bool tls_record_application_data_server(tls_sess_t& sess, tls_record_header_t& record)
{
    tls_bytes_t dec = {};

    bool ok = sess.server_decorder.decrypt(record, dec);
    if (ok) {
        tls_bytes_t& payload = sess.ssl_server_payload;
        payload.insert(payload.end(), dec.begin(), dec.end());
    }

    return ok;
}

/*****************************************************************************/

bool tls_record_change_cipher_spec_server(tls_sess_t& sess, tls_record_header_t& record)
{
    sess.server_change_cipher_spec_sent = true;

    return true;
}

/*****************************************************************************/

bool tls_record_alert_server(tls_sess_t& sess, tls_record_header_t& record)
{
    return true;
}

/*****************************************************************************/

