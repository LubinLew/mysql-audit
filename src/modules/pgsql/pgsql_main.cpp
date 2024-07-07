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

#include <audit_data.hpp>
#include <audit_utils.hpp>
#include <audit_module.hpp>

#include "pgsql.hpp"
#include "pgsql_internal.hpp"
#include "pgsql_audit.hpp"
#include "pgsql_debug.hpp"


/*****************************************************************************/

using Tins::PDU;
using Tins::Sniffer;
using Tins::SnifferConfiguration;
using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;

/*****************************************************************************/

static uint16_t g_dest_port = 5432;
static bool     g_tls_status = false;

/*****************************************************************************/

using DATA_PROC_FN = audit_ret_t (*)(Stream& stream, pgsql_sess_t& sess, pgsql_msg_t& msg);
audit_ret_t pgsql_server_msg_proc(Stream& stream, pgsql_sess_t& sess, pgsql_msg_t& msg);
audit_ret_t pgsql_client_msg_proc(Stream& stream, pgsql_sess_t& sess, pgsql_msg_t& msg);

/*****************************************************************************/

audit_ret_t pgsql_dissect_create_session(Stream& stream)
{
    static int sess_id = 1;

    uint16_t dst_port = stream.server_port();
    if (dst_port != g_dest_port) {/* Server to Other pgsql */
        return RET_ES;
    }


    pgsql_sess_userdata_t& userdata = stream.user_data<pgsql_sess_userdata_t>();
    userdata.sess_data = new pgsql_sess_t();
    pgsql_sess_t& sess = *userdata.sess_data;

    timespec_get(&sess.sess_start_time, TIME_UTC);

    sess.user  = "(none)";
    sess.database = "(none)";
    sess.phase = PGSQL_PHASE_STA;
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

    //unique id, DATE + index
    std::ostringstream oss;
    oss << std::hex << std::uppercase << audit_util_date_compress(sess.sess_start_time.tv_sec) << "-" << std::to_string(++sess_id) << std::dec;
    sess.id = oss.str();

//    pgsql_debug_start_session(sess);

    return RET_OK;
}


bool pgsql_create_tls_session(pgsql_sess_t& sess)
{
    if (g_tls_status) {
        sess.tls = tls_create_session();
        sess.is_ssl = true;
    }

    return g_tls_status;
}

void pgsql_destroy_tls_session(pgsql_sess_t& sess)
{
    if (sess.tls) {
        tls_destroy_session(sess.tls);
    }
}


pgsql_sess_t& pgsql_dissect_get_session(Stream& stream)
{
    pgsql_sess_userdata_t &userdata = stream.user_data<pgsql_sess_userdata_t>();
    return *userdata.sess_data;
}


void pgsql_dissect_destroy_session(Stream& stream)
{
    pgsql_sess_userdata_t &userdata = stream.user_data<pgsql_sess_userdata_t>();
    if (userdata.sess_data) {
        pgsql_sess_t& sess = *userdata.sess_data;

        sess.phase = PGSQL_PHASE_END;
        pgsql_audit_log(sess, true, nullptr);

        /* cleanup */
        if (sess.is_ssl) {
            pgsql_destroy_tls_session(sess);
        }
        delete userdata.sess_data;
        userdata.sess_data = nullptr;
    }

    stream.ignore_client_data();
    stream.ignore_server_data();
}


void pgsql_dissect_exit_session(Stream& stream)
{
    pgsql_sess_userdata_t &userdata = stream.user_data<pgsql_sess_userdata_t>();
    if (userdata.sess_data) {
        pgsql_sess_t& sess = *userdata.sess_data;

        if (sess.is_ssl) {
            pgsql_destroy_tls_session(sess);
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


static  pgsql_msg_detail_t* pgsql_get_msg_type_detail(uint8_t type, pgsql_data_direction_t dir)
{
    /* frontend msg table */
    static pgsql_msg_detail_t _fe_tbl[] {
    
        { PGSQL_MSG_TYPE_CANCELREQUEST, "Cancel Request"   },
        { PGSQL_MSG_TYPE_GSSENCREQUEST, "GSSENC Request"   },
        { PGSQL_MSG_TYPE_SSL_REQUEST,   "SSL Request"      },
        { PGSQL_MSG_TYPE_STARTUP,       "Startup Messgage" },
        { 'p', "Authentication message" },
        { 'Q', "Simple query"           },
        { 'P', "Parse"                  },
        { 'B', "Bind"                   },
        { 'E', "Execute"                },
        { 'D', "Describe"               },
        { 'C', "Close"                  },
        { 'H', "Flush"                  },
        { 'S', "Sync"                   },
        { 'F', "Function call"          },
        { 'd', "Copy data"              },
        { 'c', "Copy completion"        },
        { 'f', "Copy failure"           },
        { 'X', "Termination"            },
    };

    /* backend msg table */
    static pgsql_msg_detail_t _be_tbl[] {
        { PGSQL_MSG_TYPE_SSL_RESPONSE, "SSL Response"     },
        { 'R', "Authentication request"    },
        { 'K', "Backend key data"          },
        { 'S', "Parameter status"          },
        { '1', "Parse completion"          },
        { '2', "Bind completion"           },
        { '3', "Close completion"          },
        { 'C', "Command completion"        },
        { 't', "Parameter description"     },
        { 'T', "Row description"           },
        { 'D', "Data row"                  },
        { 'I', "Empty query"               },
        { 'n', "No data"                   },
        { 'E', "Error"                     },
        { 'N', "Notice"                    },
        { 's', "Portal suspended"          },
        { 'Z', "Ready for query"           },
        { 'A', "Notification"              },
        { 'V', "Function call response"    },
        { 'G', "CopyIn response"           },
        { 'H', "CopyOut response"          },
        { 'd', "Copy data"                 },
        { 'c', "Copy completion"           },
        { 'v', "Negotiate protocol version"},
    };

    pgsql_msg_detail_t* _tbl = _fe_tbl;
    size_t tbl_size = sizeof(_fe_tbl)/sizeof(pgsql_msg_detail_t);

    if (dir == PGSQL_DATA_DIR_S2C) {
        _tbl = _be_tbl;
        tbl_size = sizeof(_be_tbl)/sizeof(pgsql_msg_detail_t);
    }

    for (size_t i = 0; i < tbl_size; i++) {
        if (_tbl[i].type == type) {
            return &_tbl[i];
        }
    }

    return nullptr;
}

static void pgsql_dissect_data(Stream& stream, pgsql_sess_t& sess, Stream::payload_type& payload, DATA_PROC_FN fn)
{
    uint8_t* start  = (uint8_t*)payload.data();
    size_t   payload_size = payload.size();
    uint8_t* end    =  start + payload_size;
 
    audit_ret_t ret = RET_OK;

    /* proc msg */
    while (start < end) {
        pgsql_msg_t msg = {};

        msg.type = audit_data_get_uint8(&start, end);

        if (sess.direction == PGSQL_DATA_DIR_C2S) { /* frontend */
            if (msg.type == 0) { /* msg without type */
                --start; /* no type filed */
                msg.length = audit_data_get_uint32_be(&start, end);
                uint32_t tag = audit_data_get_uint32_be(&start, end);
                start -= 4; /* tag is part of msg data */

                switch (msg.length) {
                case 8:
                    if (PGSQL_MSG_TAG_SSLREQUEST == tag) {
                        msg.type = PGSQL_MSG_TYPE_SSL_REQUEST;
                    } else if (PGSQL_MSG_TAG_GSSENCREQUEST == tag) {
                        msg.type = PGSQL_MSG_TYPE_GSSENCREQUEST;
                    } else {
                        audit_debug_err("unknown-1 tag %#x", tag);
                    }
                    break;
                case 16:
                    if (PGSQL_MSG_TAG_CANCELREQUEST == tag) {
                        msg.type = PGSQL_MSG_TYPE_CANCELREQUEST;
                    } else {
                        audit_debug_err("unknown-2 tag %#x", tag);
                    }
                default:
                    msg.type = PGSQL_MSG_TYPE_STARTUP;
                    break;
                }
            } else { /* msg with type */
                msg.length = audit_data_get_uint32_be(&start, end);
            }
        }else { /* backend */
            if (payload_size >= 4) {
                msg.length = audit_data_get_uint32_be(&start, end);
            } else {
                if (payload_size == 1) {
                    --start; /* no type filed */
                    msg.length = 5;
                    msg.type = PGSQL_MSG_TYPE_SSL_RESPONSE;
                }
            }
        }

        msg.length -= 4; /* skip length */
        sess.msg_type = pgsql_msg_type_t(msg.type);
        sess.current_msg_info = pgsql_get_msg_type_detail(msg.type, sess.direction);
        if (nullptr == sess.current_msg_info) {/* unknown msg */
            audit_debug_err("unknown msg type:%d", msg.type);
            payload.clear();
            return;
        }

        msg.body = start; //start pointer to msg body now
        start = start + msg.length; /* next message if avaliable */

        pgsql_debug_msg(sess, msg);

        ret = fn(stream, sess, msg);
        if (ret == RET_ES) {
            pgsql_dissect_destroy_session(stream);
            return;
        }
    }

    /* clear the msgs handled */
    payload.clear();
}



static void pgsql_dissect_client_data(Stream& stream)
{
    pgsql_sess_t &sess = pgsql_dissect_get_session(stream);
    sess.direction = PGSQL_DATA_DIR_C2S;

//    pgsql_debug_data_coming(sess, sess.direction, stream.client_payload().size());

    /* is it a SSL session ? */
    if (sess.is_ssl) {
        tls_sess_t* tls = sess.tls;
        bool ret = tls_decrypt(tls, stream.client_payload(), TLS_CONN_END_CLIENT);
        if (!ret) {
            pgsql_dissect_exit_session(stream);
            return;
        }

        if (tls_client_empty(tls)) {/* handshake, no data */
            return;
        }
        pgsql_dissect_data(stream, sess, tls_client_payload(tls), pgsql_client_msg_proc);
    } else {
        pgsql_dissect_data(stream, sess, stream.client_payload(), pgsql_client_msg_proc);
    }
}

static void pgsql_dissect_server_data(Stream& stream)
{
    pgsql_sess_t &sess = pgsql_dissect_get_session(stream);
    sess.direction = PGSQL_DATA_DIR_S2C;

//    pgsql_debug_data_coming(sess, sess.data_dir, stream.server_payload().size());

    /* is it a SSL session ? */
    if (sess.is_ssl) {
        tls_sess_t* tls = sess.tls;
        bool ret = tls_decrypt(tls, stream.server_payload(), TLS_CONN_END_SERVER);
        if (!ret) {
            pgsql_dissect_exit_session(stream);
            return;
        }

        if (tls_server_empty(tls)) {/* handshake, no data */
            return;
        }
        pgsql_dissect_data(stream, sess, tls_server_payload(tls), pgsql_server_msg_proc);
    } else {
        pgsql_dissect_data(stream, sess, stream.server_payload(), pgsql_server_msg_proc);
    }
}




static void on_new_connection(Stream& stream)
{
    if unlikely(stream.is_partial_stream()) {
        stream.auto_cleanup_payloads(true);
    } else {
        if (pgsql_dissect_create_session(stream) != RET_OK) {
            stream.auto_cleanup_payloads(true);
            return;
        }

        stream.auto_cleanup_payloads(false);
        stream.client_data_callback(pgsql_dissect_client_data);
        stream.server_data_callback(pgsql_dissect_server_data);
        stream.stream_closed_callback(pgsql_dissect_destroy_session);
    }
}


static void pgsql_dissect(audit_conf_t& conf)
{

    g_tls_status = tls_init(conf.rsa_key_path, conf.rsa_key_pass);

    g_dest_port = (uint16_t)conf.port;
    pgsql_audit_init(conf.audit_log_path);

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

void pgsql_module_register(void)
{
    audit_module_t module {"pgsql", pgsql_dissect, 5432, ""};
    audit_module_register(module);
}

