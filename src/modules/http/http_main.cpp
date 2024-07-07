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


#include <stdint.h>
#include <iostream>

#include "http_internal.hpp"

/* libtins */
#include <tins/tcp_ip/stream.h>
#include <tins/network_interface.h>
#include <tins/tcp_ip/stream_follower.h>
#include <tins/sniffer.h>

#include <audit_data.hpp>
#include <audit_module.hpp>

/*****************************************************************************/

using Tins::PDU;
using Tins::Sniffer;
using Tins::SnifferConfiguration;
using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;

/*****************************************************************************/

static uint16_t g_dest_port = 80;

/*****************************************************************************/

audit_ret_t http_dissect_create_session(Stream& stream)
{
    uint16_t dst_port = stream.server_port();
    if (dst_port != g_dest_port) {/* Server to Other MySQL */
        return RET_ES;
    }

    http_sess_userdata_t& userdata = stream.user_data<http_sess_userdata_t>();
    userdata.sess_data = new http_sess_t();
    http_sess_t& sess = *userdata.sess_data;

    sess.is_first_pack = true;
    sess.is_ssl = false;

    /* tcp/ip tuple */
    sess.tuple.is_v6 = stream.is_v6();
    if (sess.tuple.is_v6) {
        sess.tuple.saddr = stream.client_addr_v6().to_string();
        sess.tuple.daddr = stream.server_addr_v6().to_string();
    } else {
        sess.tuple.saddr = stream.client_addr_v4().to_string();
        sess.tuple.daddr = stream.server_addr_v4().to_string();
    }

    sess.tuple.sport = stream.client_port();
    sess.tuple.dport = stream.server_port();

    timespec_get(&sess.sess_start_time, TIME_UTC);

    return RET_OK;
}


void http_create_tls_session(http_sess_t& sess)
{
    sess.tls = tls_create_session();
    if (sess.tls) {
        sess.is_ssl = true;
    } else {
        std::cerr << "tls_create_session() failed" << std::endl;
    }
}

void http_destroy_tls_session(http_sess_t& sess)
{
    if (sess.tls) {
        tls_destroy_session(sess.tls);
    }
}


http_sess_t& http_dissect_get_session(Stream& stream)
{
    http_sess_userdata_t &userdata = stream.user_data<http_sess_userdata_t>();
    return *userdata.sess_data;
}


void http_dissect_destroy_session(Stream& stream)
{
    http_sess_userdata_t &userdata = stream.user_data<http_sess_userdata_t>();
    if (userdata.sess_data) {
        http_sess_t& sess = *userdata.sess_data;

        /* cleanup */
        if (sess.is_ssl) {
            http_destroy_tls_session(sess);
        }
        delete userdata.sess_data;
        userdata.sess_data = nullptr;
    }

    stream.ignore_client_data();
    stream.ignore_server_data();
}


void http_dissect_exit_session(Stream& stream)
{
    http_sess_userdata_t &userdata = stream.user_data<http_sess_userdata_t>();
    if (userdata.sess_data) {
        http_sess_t& sess = *userdata.sess_data;
        if (sess.is_ssl) {
            http_destroy_tls_session(sess);
        }

        delete userdata.sess_data;
        userdata.sess_data = nullptr;
    }

    /* ingore data */
    stream.ignore_client_data();
    stream.ignore_server_data();
    stream.auto_cleanup_payloads(true);

    /* reset callbacks */
    stream.client_data_callback(nullptr);
    stream.server_data_callback(nullptr);
    stream.stream_closed_callback(nullptr);
}

/* TODO
Transfer-Encoding: chunked
Content-Encoding: gzip
*/
static void http_dissect_client_packet(Stream& stream, http_sess_t& sess, Stream::payload_type& payload)
{
    uint8_t* payload_ptr  = (uint8_t*)payload.data();
    size_t   payload_size = payload.size();

    if (sess.is_req_body) {

    }

    for (size_t i = 0; i < payload_size; i++) {
        std::cout << *(payload_ptr + i);
    }

    payload.clear();
}

static void http_dissect_server_packet(Stream& stream, http_sess_t& sess, Stream::payload_type& payload)
{
    uint8_t* payload_ptr  = (uint8_t*)payload.data();
    size_t   payload_size = payload.size();

    if (sess.is_res_body) {
        if (sess.is_res_body_chunked) {

        }

        if (sess.is_res_body_gzip) {

        } else if (sess.is_res_body_deflate) {

        } else {/* plaintext */

        }
    }

    for (size_t i = 0; i < payload_size; i++) {
        std::cout << *(payload_ptr + i);
    }

    payload.clear();
}


static bool http_is_client_hello(Stream::payload_type& payload)
{
    uint8_t* start  = payload.data();
    uint8_t* end    = start + payload.size();

    uint8_t type = audit_data_get_uint8(&start, end);
    if (type != 0x16) {// Handshake
        return false;
    }

    uint16_t version = audit_data_get_uint16_be(&start, end);
    switch (version) {
    case 0x0301: /* TLSv1.0 */
    case 0x0302: /* TLSv1.1 */
    case 0x0303: /* TLSv1.2 */
    case 0x0304: /* TLSv1.3 */
        break;
    default:
        return false;
    }
    audit_data_skip_bytes(&start, end, 2); //skip length

    type = audit_data_get_uint8(&start, end);
    if (type != 0x01) {// ClientHello
        return false;
    }

    audit_data_skip_bytes(&start, end, 3); //skip length

    version = audit_data_get_uint16_be(&start, end);
       switch (version) {
       case 0x0301: /* TLSv1.0 */
       case 0x0302: /* TLSv1.1 */
       case 0x0303: /* TLSv1.2 */
       case 0x0304: /* TLSv1.3 */
           break;
       default:
           return false;
       }

    return true;
}


static void http_dissect_client_data(Stream& stream)
{
    http_sess_t &sess = http_dissect_get_session(stream);

    if unlikely(sess.is_first_pack) {
        sess.is_ssl = http_is_client_hello(stream.client_payload());
        http_create_tls_session(sess);
        sess.is_first_pack = false;
    }
 
    /* is it a SSL session ? */
    if (sess.is_ssl) {
        tls_sess_t* tls = sess.tls;
        bool ret = tls_decrypt(tls, stream.client_payload(), TLS_CONN_END_CLIENT);
        if (!ret) {
            http_dissect_exit_session(stream);
            return;
        }

        if (tls_client_empty(tls)) {/* handshake, no data */
            return;
        }
        http_dissect_client_packet(stream, sess, tls_client_payload(tls));
    } else {
        http_dissect_client_packet(stream, sess, stream.client_payload());
    }
}



static void http_dissect_server_data(Stream& stream)
{
    http_sess_t &sess = http_dissect_get_session(stream);

    /* is it a SSL session ? */
    if (sess.is_ssl) {
        tls_sess_t* tls = sess.tls;
        bool ret = tls_decrypt(tls, stream.server_payload(), TLS_CONN_END_SERVER);
        if (!ret) {
            http_dissect_exit_session(stream);
            return;
        }

        if (tls_server_empty(tls)) {/* handshake, no data */
            return;
        }
        http_dissect_server_packet(stream, sess, tls_server_payload(tls));
    } else {
        http_dissect_server_packet(stream, sess, stream.server_payload());
    }
}



static void on_new_connection(Stream& stream)
{
    if (stream.is_partial_stream()) {
        stream.auto_cleanup_payloads(true);
    } else {
        stream.auto_cleanup_payloads(false);
        if (http_dissect_create_session(stream) != RET_OK) {
            stream.auto_cleanup_payloads(true);
            return;
        }

        stream.client_data_callback(http_dissect_client_data);
        stream.server_data_callback(http_dissect_server_data);
        stream.stream_closed_callback(http_dissect_destroy_session);
    }
}


static void http_dissect(audit_conf_t& conf)
{
    bool is_key = false;

    if (!conf.rsa_key_path.empty()) {
        is_key = true;
    }

    if (is_key) {
        std::string pass {};
        bool ok = tls_init(conf.rsa_key_path, conf.rsa_key_pass);
        if (!ok) {
            is_key = false;
        }
    }

    g_dest_port = (uint16_t)conf.port;

    // Construct the sniffer configuration object
    SnifferConfiguration config;
    // Get packets as quickly as possible
    config.set_immediate_mode(true);

    // Only capture TCP traffic sent from/to port X
    std::string filter = "tcp port " + std::to_string(conf.port);
    config.set_filter(filter);

    // Construct the sniffer we'll use
    Sniffer sniffer(conf.if_name, config);
    
    // Now construct the stream follower
    StreamFollower follower;
    // We just need to specify the callback to be executed when a new 
    // stream is captured. In this stream, you should define which callbacks
    // will be executed whenever new data is sent on that stream 
    // (see on_new_connection)
    follower.new_stream_callback(&on_new_connection);
    // Now start capturing. Every time there's a new packet, call 
    // follower.process_packet
    sniffer.sniff_loop([&](PDU& packet) {
        follower.process_packet(packet);
        return true;
    });

    if (is_key) {
        tls_free();
    }
}

void http_module_register(void)
{
    audit_module_t module {"http", http_dissect, 80, ""};
    audit_module_register(module);
}

