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
#include <stdint.h>
#include <iostream>     // std::cout

/* libtins */
#include <tins/tcp_ip/stream.h>
#include <tins/tcp_ip/stream_follower.h>
#include <tins/network_interface.h>
#include <tins/sniffer.h>

#include <audit_utils.hpp>
#include <audit_module.hpp>

#include "mysql.hpp"
#include "mysql_debug.hpp"
#include "mysql_internal.hpp"
#include "mysql_compress.hpp"
#include "mysql_audit.hpp"

/*****************************************************************************/

using Tins::PDU;
using Tins::Sniffer;
using Tins::SnifferConfiguration;
using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;

/*****************************************************************************/

static uint16_t g_dest_port = 3306;
static bool     g_tls_status = false;

/*****************************************************************************/

using DATA_PROC_FN = audit_ret_t (*)(Stream& stream, mysql_sess_t& sess, mysql_packet_t* packet);
audit_ret_t server_one_packet_proc(Stream& stream, mysql_sess_t& sess, mysql_packet_t* packet);
audit_ret_t client_one_packet_proc(Stream& stream, mysql_sess_t& sess, mysql_packet_t* packet);

/*****************************************************************************/

audit_ret_t mysql_dissect_create_session(Stream& stream)
{
    uint16_t dst_port = stream.server_port();
    if (dst_port != g_dest_port) {/* Server to Other MySQL */
        return RET_ES;
    }

    mysql_sess_userdata_t& userdata = stream.user_data<mysql_sess_userdata_t>();
    userdata.sess_data = new mysql_sess_t();
    mysql_sess_t& sess = *userdata.sess_data;

    sess.is_ssl = false;
    sess.state = MYSQL_STATE_HANDSHAKE_REQUEST;
    sess.phase = MYSQL_SESS_PHASE_HANDSHAKE;
    sess.user  = "(none)";
    sess.database = "(none)";

    sess.compress_type = MYSQL_COMPRESS_NONE;
    sess.is_compressed = false;
    sess.packet_header_size = 4; /* sizeof(mysql_packet_t) */

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

    //unique id, DATE + MYSQL_SESSION_ID
    std::ostringstream oss;
    oss << std::hex << std::uppercase << audit_util_date_compress(sess.sess_start_time.tv_sec) << "-" << std::dec;
    sess.id = oss.str();

    mysql_debug_start_session(sess);

    return RET_OK;
}


bool mysql_create_tls_session(mysql_sess_t& sess)
{
    if (g_tls_status) {
        sess.tls = tls_create_session();
        sess.is_ssl = true;
    }

    return g_tls_status;
}

void mysql_destroy_tls_session(mysql_sess_t& sess)
{
    if (sess.tls) {
        tls_destroy_session(sess.tls);
    }
}


mysql_sess_t& mysql_dissect_get_session(Stream& stream)
{
    mysql_sess_userdata_t &userdata = stream.user_data<mysql_sess_userdata_t>();
    return *userdata.sess_data;
}


void mysql_dissect_destroy_session(Stream& stream)
{
    mysql_sess_userdata_t &userdata = stream.user_data<mysql_sess_userdata_t>();
    if (userdata.sess_data) {
        mysql_sess_t& sess = *userdata.sess_data;
        mysql_debug_end_session(sess);

        /* log COM_QUIT */
        if (sess.state == MYSQL_STATE_CLOSED) {
            mysql_audit_log(sess, true, nullptr);
            sess.command_is_logd = false;
        }

        /* log SESSION end */
        sess.phase = MYSQL_SESS_PHASE_END;
        mysql_audit_log(sess, true, nullptr);

        /* cleanup */
        if (sess.is_ssl) {
            mysql_destroy_tls_session(sess);
        }
        delete userdata.sess_data;
        userdata.sess_data = nullptr;
    }

    stream.ignore_client_data();
    stream.ignore_server_data();
}


void mysql_dissect_exit_session(Stream& stream)
{
    mysql_sess_userdata_t &userdata = stream.user_data<mysql_sess_userdata_t>();
    if (userdata.sess_data) {
        mysql_sess_t& sess = *userdata.sess_data;
        mysql_debug_exit_session(sess);

        if (sess.is_ssl) {
            mysql_destroy_tls_session(sess);
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


bool mysql_dissect_check_capabilities(mysql_sess_t& sess, uint32_t flag)
{
    return (sess.capabilities & flag);
}

mysql_compress_type_t mysql_dissect_get_compress_kind(mysql_sess_t& sess)
{
    uint32_t capabilities = sess.capabilities;

    if (capabilities & CLIENT_ZSTD_COMPRESSION_ALGORITHM) {
        return MYSQL_COMPRESS_ZSTD;
    }

    if (capabilities & CLIENT_COMPRESS) {
        return MYSQL_COMPRESS_ZLIB;
    }

    return MYSQL_COMPRESS_NONE;
}


static audit_ret_t mysql_dissect_packet(Stream &stream, mysql_sess_t& sess, mysql_packet_t* packet, DATA_PROC_FN fn)
{
    if (!sess.is_compressed) {
        return fn(stream, sess, packet);
    }

    audit_debug_dbg("dissect compress packet");

    bool ok = mysql_uncompress_packet(sess, packet);
    if (!ok) { /* uncompress failed */
        return fn(stream, sess, packet);
    }

    audit_ret_t ret = RET_NG;
    
    /* The payload can be anything from a piece of a MySQL Packet to several MySQL Packets. 
     * The client or server may bundle several MySQL packets, 
     * compress it and send it as one compressed packet.
     */
    while (packet) {
        packet = mysql_uncompress_get_packet(sess);
        if (packet == nullptr) {
            break;
        }

        ret = fn(stream, sess, packet);
        if (ret != RET_OK) {
            audit_debug_err("fn failed");
            break;
        }
    }

    return ret;
}



static void mysql_dissect_data(Stream& stream, mysql_sess_t& sess, Stream::payload_type& payload, DATA_PROC_FN fn)
{
    uint8_t* payload_ptr  = (uint8_t*)payload.data();
    size_t   payload_size = payload.size();
    size_t   payload_proc = 0; /* the byte has been parsed */

    audit_ret_t ret = RET_OK;

    while (1) {
        if (payload_size < 4) {
            if (payload_proc) {
                payload.erase(payload.begin(), payload.begin() + payload_proc);
                payload_proc = 0;
            }
            break;
        }
        mysql_packet_t *packet = (mysql_packet_t *)payload_ptr;
        mysql_debug_print_packet(sess, packet, payload_size);
//        mysql_debug_packet(packet);
        /* skip header(mysql_packet_t) */
        payload_size -= 4;
        payload_ptr  += 4;
        if (payload_size < packet->payload_length) {
            if (payload_proc) {
                payload.erase(payload.begin(), payload.begin() + payload_proc);
                payload_proc = 0;
            }
            break;
        }
        else if (payload_size == packet->payload_length) {
            ret = mysql_dissect_packet(stream, sess, packet, fn);
            payload.clear();
            payload_proc = 0;
            break;
        } else { /* mutil packet */
            ret = mysql_dissect_packet(stream, sess, packet, fn);
            payload_proc += (sess.packet_header_size + packet->payload_length);
            payload_size -= packet->payload_length;
            payload_ptr  += packet->payload_length;
            if (ret == RET_ES) {
                break;
            }
        }
    }

    if (ret == RET_ES) {
        mysql_dissect_exit_session(stream);
        return;
    }

    audit_debug_dbg("data reamin size: %ld", payload.size());
}



static void mysql_dissect_client_data(Stream& stream)
{
    mysql_sess_t &sess = mysql_dissect_get_session(stream);
    sess.data_dir = MYSQL_DATA_DIR_C2S;

    mysql_debug_data_coming(sess, sess.data_dir, stream.client_payload().size());

    /* is it a SSL session ? */
    if (sess.is_ssl) {
        tls_sess_t* tls = sess.tls;
        bool ret = tls_decrypt(tls, stream.client_payload(), TLS_CONN_END_CLIENT);
        if (!ret) {
            mysql_dissect_exit_session(stream);
            return;
        }

        if (tls_client_empty(tls)) {/* handshake, no data */
            return;
        }
        mysql_dissect_data(stream, sess, tls_client_payload(tls), client_one_packet_proc);
    } else {
        mysql_dissect_data(stream, sess, stream.client_payload(), client_one_packet_proc);
    }
}



static void mysql_dissect_server_data(Stream& stream)
{
    mysql_sess_t &sess = mysql_dissect_get_session(stream);
    sess.data_dir = MYSQL_DATA_DIR_S2C;

    mysql_debug_data_coming(sess, sess.data_dir, stream.server_payload().size());

    /* is it a SSL session ? */
    if (sess.is_ssl) {
        tls_sess_t* tls = sess.tls;
        bool ret = tls_decrypt(tls, stream.server_payload(), TLS_CONN_END_SERVER);
        if (!ret) {
            mysql_dissect_exit_session(stream);
            return;
        }

        if (tls_server_empty(tls)) {/* handshake, no data */
            return;
        }
        mysql_dissect_data(stream, sess, tls_server_payload(tls), server_one_packet_proc);
    } else {
        mysql_dissect_data(stream, sess, stream.server_payload(), server_one_packet_proc);
    }
}



static void on_new_connection(Stream& stream)
{
    if unlikely(stream.is_partial_stream()) {
        stream.auto_cleanup_payloads(true);
    } else {
        if (mysql_dissect_create_session(stream) != RET_OK) {
            stream.auto_cleanup_payloads(true);
            return;
        }

        stream.auto_cleanup_payloads(false);
        stream.client_data_callback(mysql_dissect_client_data);
        stream.server_data_callback(mysql_dissect_server_data);
        stream.stream_closed_callback(mysql_dissect_destroy_session);
    }
}


static void mysql_dissect(audit_conf_t& conf)
{
    g_tls_status = tls_init(conf.rsa_key_path, conf.rsa_key_pass);

    g_dest_port = (uint16_t)conf.port;
    mysql_audit_init(conf.audit_log_path);

    // Construct the sniffer configuration object
    SnifferConfiguration config;
    // Get packets as quickly as possible
    config.set_immediate_mode(false);

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

    tls_free();
}

void mysql_module_register(void)
{
    audit_module_t module {"mysql", mysql_dissect, 3306, "/var/lib/mysql/server-key.pem"};
    audit_module_register(module);
}

