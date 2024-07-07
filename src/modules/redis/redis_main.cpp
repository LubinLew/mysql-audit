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
#include <regex>

/* libtins */
#include <tins/tcp_ip/stream.h>
#include <tins/tcp_ip/stream_follower.h>
#include <tins/network_interface.h>
#include <tins/sniffer.h>

#include <audit_data.hpp>
#include <audit_utils.hpp>
#include <audit_module.hpp>

#include "redis.hpp"
#include "redis_internal.hpp"
#include "redis_data.hpp"
#include "redis_audit.hpp"
#include "redis_debug.hpp"

#include "redis_statement.hpp"

/*****************************************************************************/

using Tins::PDU;
using Tins::Sniffer;
using Tins::SnifferConfiguration;
using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;

/*****************************************************************************/

static uint16_t g_dest_port = 6379;
static bool     g_tls_status = false;

/*****************************************************************************/

audit_ret_t redis_dissect_create_session(Stream& stream)
{
    static int sess_id = 1;

    uint16_t dst_port = stream.server_port();
    if (dst_port != g_dest_port) {/* Server to Other redis */
        return RET_ES;
    }


    redis_sess_userdata_t& userdata = stream.user_data<redis_sess_userdata_t>();
    userdata.sess_data = new redis_sess_t();
    redis_sess_t& sess = *userdata.sess_data;

    timespec_get(&sess.sess_start_time, TIME_UTC);

    sess.user  = "(none)";
    sess.database = "(none)";
    sess.phase = REDIS_PHASE_STA;
    sess.is_ssl = false;
    sess.is_ssl_testd = false;
    sess.is_error = false;

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

    //unique id, DATE + index
    std::ostringstream oss;
    oss << std::hex << std::uppercase << audit_util_date_compress(sess.sess_start_time.tv_sec) << "-" << std::to_string(++sess_id) << std::dec;
    sess.id = oss.str();

    redis_debug_start_session(sess);

    return RET_OK;
}


bool redis_create_tls_session(redis_sess_t& sess)
{
    if (g_tls_status) {
        sess.tls = tls_create_session();
        sess.is_ssl = true;
    }

    return g_tls_status;
}

void redis_destroy_tls_session(redis_sess_t& sess)
{
    if (sess.tls) {
        tls_destroy_session(sess.tls);
    }
}


redis_sess_t& redis_dissect_get_session(Stream& stream)
{
    redis_sess_userdata_t &userdata = stream.user_data<redis_sess_userdata_t>();
    return *userdata.sess_data;
}


void redis_dissect_destroy_session(Stream& stream)
{
    redis_sess_userdata_t &userdata = stream.user_data<redis_sess_userdata_t>();
    if (userdata.sess_data) {
        redis_sess_t& sess = *userdata.sess_data;
        redis_debug_end_session(sess);

        if (sess.phase == REDIS_PHASE_CMD) {
            sess.phase = REDIS_PHASE_END;
            redis_audit_log(sess, nullptr);
        }

        /* cleanup */
        if (sess.is_ssl) {
            redis_destroy_tls_session(sess);
        }
        delete userdata.sess_data;
        userdata.sess_data = nullptr;
    }

    stream.ignore_client_data();
    stream.ignore_server_data();
}


void redis_dissect_exit_session(Stream& stream)
{
    redis_sess_userdata_t &userdata = stream.user_data<redis_sess_userdata_t>();
    if (userdata.sess_data) {
        redis_sess_t& sess = *userdata.sess_data;
        redis_debug_exit_session(sess);

        if (sess.is_ssl) {
            redis_destroy_tls_session(sess);
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

void redis_dissect_auth_get_user(redis_sess_t& sess, audit_str_t& auth)
{
    std::regex pattern("auth\\s+(.+?)\\s+(.+)", std::regex::icase);
    std::smatch match;

    auto ok = std::regex_match(auth, match, pattern);
    if (ok) {
        std::ssub_match sub_match = match[1];
        sess.user = sub_match.str();
        sub_match = match[2];
        sess.passwd = sub_match.str();
    } else {
        sess.user = "-";
        sess.passwd = "-";
    }
}


void redis_dissect_select_db(redis_sess_t& sess, audit_str_t& auth)
{
    std::regex pattern("select\\s+(.+)", std::regex::icase);
    std::smatch match;

    auto ok = std::regex_match(auth, match, pattern);
    if (ok) {
        std::ssub_match sub_match = match[1];
        sess.database = sub_match.str();
    } else {
        sess.database = "-";
    }
}


static audit_ret_t redis_dissect_string(redis_sess_t& sess, audit_str_t& str)
{
    if (sess.direction ==  AUDIT_FLOW_DIR_S2C) {
        if (sess.is_error) {
            sess.error_msg = str;
        }

        redis_statement_t& sts = sess.statements.front();

        switch (sts.statement_type) {
        case REDIS_CMD_TYPE_AUTH:
            redis_audit_log(sess, &sts);
            if (sess.is_error) {
                return RET_ES;
            }
            sess.phase = REDIS_PHASE_CMD;
            break;
        case REDIS_CMD_TYPE_PING:
            break;
        default:
            redis_audit_log(sess, &sts);
            break;
        }

        sess.statements.pop();
    } else {
        auto info = redis_statement_analysis(str);
        redis_statement_t sts;
        sts.statement_string = str;
        if unlikely(nullptr == info) {
            sts.statement_category = "OTHER";
            sts.statement_type = REDIS_CMD_TYPE_OTHER;
        } else {
            sts.statement_category = info->category;
            sts.statement_type = (redis_cmd_type_t)info->cgy_id;
        }

        switch (sts.statement_type) {
        case REDIS_CMD_TYPE_AUTH:
            redis_dissect_auth_get_user(sess, str);
            break;
        case REDIS_CMD_TYPE_SELECT:
            redis_dissect_select_db(sess, str);
            break;
        default:
            break;
        }

        sess.statements.push(sts);
    }

    return RET_OK;
}

static void redis_dissect_data(Stream& stream, redis_sess_t& sess, Stream::payload_type& payload)
{
    uint8_t* start  = (uint8_t*)payload.data();
    size_t  payload_size = payload.size();
    uint8_t* end    =  start + payload_size;

    audit_debug_pkg(">>>>>>>>>>>>>>>>[%s] size: %u", (sess.direction == AUDIT_FLOW_DIR_C2S ? "C->S" : "S->C"), payload.size());

    if unlikely(payload_size < 5) { /* not enouth data */
        return;
    }

    uint8_t* last2 = end - 2;
    if likely((last2[0] != '\r') || (last2[1] != '\n')) { /* not enouth data */
        return;
    }

    audit_str_t result = redis_data_proc(sess, &start, end);
    auto ret = redis_dissect_string(sess, result);
    if unlikely(ret == RET_ES) {
        redis_dissect_exit_session(stream);
        return;
    }

    audit_debug_dbg("%s: %s", (sess.direction ==  AUDIT_FLOW_DIR_C2S ? "Request" : "Response"), result.c_str());

    /* statistics */
    if (sess.direction ==  AUDIT_FLOW_DIR_C2S) {
        sess.statistics_command_client =  payload_size;
        sess.statistics_session_client += payload_size;
    } else {
        sess.statistics_command_server =  payload_size;
        sess.statistics_session_server += payload_size;
    }

    /* clear the msgs handled */
    payload.clear();
}

static bool redis_dissect_tls_client_hello(tls_bytes_t& data)
{
    uint8_t* start = data.data();
    size_t   size  = data.size();
    uint8_t* end   = start + size;

    uint8_t record_type = audit_data_get_uint8(&start, end);
    if (record_type != 22) { /* not handshake */
        return false;
    }
    
    uint16_t record_version = audit_data_get_uint16_be(&start, end);
    if ((record_version != 0x0301) && (record_version != 0x0302) && (record_version != 0x0303)) {
        /* not TLSv1.0, TLSv1.1, TLSv1.2 */
        return false;
    }

    /* skip record length */
    audit_data_skip_bytes(&start, end, 2);

    uint8_t handshake_type = audit_data_get_uint8(&start, end);
    if (handshake_type != 1) { /* not client hello */
        return false;
    }

    audit_debug_dbg("found TLS connection");
    return true;
}

static void redis_dissect_client_data(Stream& stream)
{
    redis_sess_t &sess = redis_dissect_get_session(stream);
    sess.direction = AUDIT_FLOW_DIR_C2S;
    timespec_get(&sess.cmd_start_time, TIME_UTC);

    if unlikely(!sess.is_ssl_testd) {
        sess.is_ssl_testd = true;
        auto ok = redis_dissect_tls_client_hello(stream.client_payload());
        if (ok) {/* SSL session */
            ok = redis_create_tls_session(sess);
            if (!ok) {/* SSL init failed */
                redis_dissect_destroy_session(stream);
                return;
            }
        }
    }

    /* is it a SSL session ? */
    if (sess.is_ssl) {
        tls_sess_t* tls = sess.tls;
        bool ret = tls_decrypt(tls, stream.client_payload(), TLS_CONN_END_CLIENT);
        if (!ret) {
            redis_dissect_exit_session(stream);
            return;
        }

        if (tls_client_empty(tls)) {/* handshake, no data */
            return;
        }
        redis_dissect_data(stream, sess, tls_client_payload(tls));
    } else {
        redis_dissect_data(stream, sess, stream.client_payload());
    }
}

static void redis_dissect_server_data(Stream& stream)
{
    redis_sess_t &sess = redis_dissect_get_session(stream);
    sess.direction = AUDIT_FLOW_DIR_S2C;

//    redis_debug_data_coming(sess, sess.data_dir, stream.server_payload().size());

    /* is it a SSL session ? */
    if (sess.is_ssl) {
        tls_sess_t* tls = sess.tls;
        bool ret = tls_decrypt(tls, stream.server_payload(), TLS_CONN_END_SERVER);
        if (!ret) {
            redis_dissect_exit_session(stream);
            return;
        }

        if (tls_server_empty(tls)) {/* handshake, no data */
            return;
        }
        redis_dissect_data(stream, sess, tls_server_payload(tls));
    } else {
        redis_dissect_data(stream, sess, stream.server_payload());
    }
}




static void on_new_connection(Stream& stream)
{
    if unlikely(stream.is_partial_stream()) {
        stream.auto_cleanup_payloads(true);
    } else {
        if (redis_dissect_create_session(stream) != RET_OK) {
            stream.auto_cleanup_payloads(true);
            return;
        }

        stream.auto_cleanup_payloads(false);
        stream.client_data_callback(redis_dissect_client_data);
        stream.server_data_callback(redis_dissect_server_data);
        stream.stream_closed_callback(redis_dissect_destroy_session);
    }
}


static void redis_dissect(audit_conf_t& conf)
{

    g_tls_status = tls_init(conf.rsa_key_path, conf.rsa_key_pass);

    g_dest_port = (uint16_t)conf.port;

    redis_audit_init(conf.audit_log_path);

    redis_statement_init();

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

void redis_module_register(void)
{
    audit_module_t module {"redis", redis_dissect, 6379, ""};
    audit_module_register(module);
}

