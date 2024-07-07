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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/*****************************************************************************/

using TLS_RECORD_FUNC = bool (*)( tls_sess_t& sess, tls_record_header_t& record);

struct tls_record_handler_t {
    TLS_RECORD_FUNC func_change_cipher_spec;
    TLS_RECORD_FUNC func_alert;
    TLS_RECORD_FUNC func_handshake;
    TLS_RECORD_FUNC func_application_data;
};

bool tls_record_change_cipher_spec_client(tls_sess_t& sess, tls_record_header_t& record);
bool tls_record_alert_client(tls_sess_t& sess, tls_record_header_t& record);
bool tls_record_handshake_client(tls_sess_t& sess, tls_record_header_t& record);
bool tls_record_application_data_client(tls_sess_t& sess, tls_record_header_t& record);

static tls_record_handler_t g_record_client_funcs = {
    tls_record_change_cipher_spec_client,
    tls_record_alert_client,
    tls_record_handshake_client,
    tls_record_application_data_client
};

bool tls_record_change_cipher_spec_server(tls_sess_t& sess, tls_record_header_t& record);
bool tls_record_alert_server(tls_sess_t& sess, tls_record_header_t& record);
bool tls_record_handshake_server(tls_sess_t& sess, tls_record_header_t& record);
bool tls_record_application_data_server(tls_sess_t& sess, tls_record_header_t& record);

static tls_record_handler_t g_record_server_funcs = {
    tls_record_change_cipher_spec_server,
    tls_record_alert_server,
    tls_record_handshake_server,
    tls_record_application_data_server
};

bool tls_key_init(std::string& private_key_path, std::string& private_key_pass);
void tls_key_free(void);
void tls_crypto_init(void);
/*****************************************************************************/

bool tls_decrypt(tls_sess_t* sess, tls_bytes_t& data, tls_conn_end_t endpoint)
{
    uint8_t* start = data.data();
    uint8_t* end   = start + data.size();

    size_t   payload_size = data.size();
    size_t   proc_size = 0;

    tls_record_handler_t& handler = (endpoint == TLS_CONN_END_CLIENT ? g_record_client_funcs : g_record_server_funcs);

    bool ret = true;
    tls_record_header_t record = {};

    sess->endpoint = endpoint;

    while (1) {
        if (payload_size < tls_record_header_size) {
            if (proc_size) {
                 data.erase(data.begin(), data.begin() + proc_size);
            }
            break;
        }

        record.type    = audit_data_get_uint8(&start, end);
        record.version = audit_data_get_uint16_be(&start, end);
        record.length  = audit_data_get_uint16_be(&start, end);
        record.payload = start;

        audit_debug_dbg("[%s]<Record:%s> version: %s, length: %d", \
            tls_info_endpoint(endpoint), \
            tls_info_record_type(record.type), \
            tls_info_version(record.version), record.length);

        if (record.length > payload_size) {//no enough data
            if (proc_size) {
                 data.erase(data.begin(), data.begin() + proc_size);
            }
            break;
        }

        switch (record.type) {
        case change_cipher_spec:
            ret = handler.func_change_cipher_spec(*sess, record);
            break;

        case alert:
            ret = handler.func_alert(*sess, record);
            break;

        case handshake:
            ret = handler.func_handshake(*sess, record);
            break;

        case application_data:
            ret = handler.func_application_data(*sess, record);
            break;

        default:
            break;
        }

        if (!ret) {
            data.clear();
            return false;
        }

        /* next record */
        start = record.payload + record.length;
        payload_size -= (tls_record_header_size + record.length); //skip record header
        proc_size += (tls_record_header_size + record.length);
    }

    return ret;
}

bool tls_client_empty(tls_sess_t* sess)
{
    return sess->ssl_client_payload.empty();
}


bool tls_server_empty(tls_sess_t* sess)
{
    return sess->ssl_server_payload.empty();
}

tls_bytes_t& tls_client_payload(tls_sess_t* sess)
{
    return sess->ssl_client_payload;
}

tls_bytes_t& tls_server_payload(tls_sess_t* sess)
{
    return sess->ssl_server_payload;
}

tls_sess_t* tls_create_session(void)
{
    tls_sess_t* sess = new tls_sess_t();
    return sess;
}

void tls_destroy_session(tls_sess_t* sess)
{
    if (sess) {
        delete sess;
    }
}


bool tls_init(std::string& private_key_path, std::string& private_key_pass)
{    
   tls_crypto_init();

    return tls_key_init(private_key_path, private_key_pass);
}


void tls_free(void)
{
    tls_key_free();
}


