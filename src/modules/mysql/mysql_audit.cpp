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


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <stdexcept>
#include <nlohmann/json.hpp>

#include "mysql_info.hpp"
#include "mysql_debug.hpp"
#include "mysql_statement.hpp"
#include "mysql_audit.hpp"

#include <audit_utils.hpp>

/*****************************************************************************/

using nlohmann::json;

static int g_audit_fd;
static audit_hs_hdl_t* g_hs_handler = nullptr;
static audit_str_t     g_log_path;

/*****************************************************************************/

bool mysql_audit_init(audit_str_t& path)
{
    g_audit_fd  = open(path.c_str(), O_WRONLY|O_CREAT|O_APPEND, 0644);
    if (g_audit_fd < 0) {
        audit_debug_err("open(%s) failed, %s", path.c_str(), strerror(errno));
        return false;
    }

    g_hs_handler = mysql_statement_init();
    if (nullptr == g_hs_handler) {
        return false;
    }

    g_log_path = path;
    return true;
}

bool mysql_audit_reopen(void)
{
    if (g_audit_fd > 0) {
        close(g_audit_fd);
    }

    g_audit_fd = open(g_log_path.c_str(), O_WRONLY|O_CREAT|O_APPEND, 0644);
    if (g_audit_fd < 0) {
        audit_debug_err("reopen(%s) failed, %s", g_log_path.c_str(), strerror(errno));
        return false;
    }

    return true;
}

static void mysql_json_write(int fd, json& j)
{
    try {
        auto str = j.dump();
        str.push_back('\n');
        ssize_t ret = write(fd, str.c_str(), str.size());
        if (ret < 0) {
            audit_debug_err("write(%d) failed, %s", fd, strerror(errno));
        }
    }
    catch (std::exception &ex) {
        audit_debug_err("%s", ex.what());
        //go on
    }
}

static void mysql_json_query_analysis(json& j, audit_str_t& query)
{
    if (nullptr == g_hs_handler) {
        j["category"] = "other";
        return;
    }

    const char* data = query.c_str();
    size_t len = query.size();

    const audit_hs_data_t* match_data = mysql_statement_analysis(g_hs_handler, data, len);
    if (nullptr == match_data) {
        j["category"] = "OTHER";
        return;
    }

    j["category"] = match_data->category;

}


void mysql_audit_log(mysql_sess_t& sess, bool isok, uint8_t* data)
{
    if (sess.command_is_logd) {
        return;
    } else {
        sess.command_is_logd = true;
    }

    json j;
    mysql_err_packet_t& err = *(mysql_err_packet_t*)data;

    j["id"]        = sess.id;
    j["user"]      = sess.user;
    j["database"]  = sess.database;

    if (isok) {
        j["code"] = 0;
        j["msg"]  = "success";
    } else {
        j["code"] = err.error_code;
        j["msg"]  = err.error_message;
    }

    switch (sess.phase) {
    case MYSQL_SESS_PHASE_HANDSHAKE:
        j["type"]  = "HANDSHAKE";
        j["timestamp"] = audit_util_time_get(sess.sess_start_time);
        j["elapse"]    = audit_util_time_diff_from_now(sess.sess_start_time);
        j["server_attrs"]["variant"]   = mysql_info_get_variant(sess.variant);
        j["server_attrs"]["version"]   = sess.handshake_request.server_version;

        for (const auto& it : sess.handshake_respone.client_attr) {
            j["client_attrs"][it.first] = it.second;
        }
        break;

    case MYSQL_SESS_PHASE_CMD:
        j["timestamp"] = audit_util_time_get(sess.cmd_start_time);  /* command start time */
        j["elapse"]    = audit_util_time_diff_from_now(sess.cmd_start_time);

        j["type"]    = "COMMAND";
        j["command"] = mysql_info_get_cmd(sess.command);
        if (sess.command == COM_QUERY) {
            j["statement"] = sess.statement;
            mysql_json_query_analysis(j, sess.statement);
        } else {
            j["info"]  = sess.statement;
        }
        audit_debug_dbg("[%s] output to json", mysql_info_get_cmd(sess.command).c_str());
        break;

    case MYSQL_SESS_PHASE_END:
        j["timestamp"] = audit_util_time_get_now();                           /* right now */
        j["elapse"]    = audit_util_time_diff_from_now(sess.sess_start_time); /* whole session */
        j["type"] = "END";
        break;

    default:
        break;
    }

    j["affected_rows"] = sess.affected_rows;

    j["tcp"]["saddr"] = sess.tuple.saddr;
    j["tcp"]["daddr"] = sess.tuple.daddr;
    j["tcp"]["sport"] = sess.tuple.sport;
    j["tcp"]["dport"] = sess.tuple.dport;

    j["statistics"]["client_sess_sent_bytes"] = sess.statistics_session_client;
    j["statistics"]["server_sess_sent_bytes"] = sess.statistics_session_server;
    j["statistics"]["client_cmd_sent_bytes"]  = sess.statistics_command_client;
    j["statistics"]["server_cmd_sent_bytes"]  = sess.statistics_command_server;

    mysql_json_write(g_audit_fd, j);
}

/*****************************************************************************/

