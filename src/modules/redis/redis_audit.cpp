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

#include "redis_debug.hpp"
#include "redis_audit.hpp"

#include <audit_utils.hpp>

/*****************************************************************************/

using nlohmann::json;

static int g_audit_fd;
static audit_str_t g_log_path;

/*****************************************************************************/

bool redis_audit_init(audit_str_t& path)
{
    g_audit_fd  = open(path.c_str(), O_WRONLY|O_CREAT|O_APPEND, 0644);
    if (g_audit_fd < 0) {
        audit_debug_err("open(%s) failed, %s", path.c_str(), strerror(errno));
        return false;
    }

    g_log_path = path;
    return true;
}

bool redis_audit_reopen(void)
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


static void redis_audit_log_write(int fd, json& j)
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

void redis_audit_log(redis_sess_t& sess, redis_statement_t* sts)
{
    json j;

    j["id"]        = sess.id;
    j["user"]      = sess.user;
    j["database"]  = sess.database;

    if (!sess.is_error) {
        j["code"] = 0;
        j["msg"]  = "success";
    } else {
        j["code"] = -1;
        j["msg"]  = sess.error_msg;
    }

    switch (sess.phase) {
    case REDIS_PHASE_STA:
        j["type"]  = "HANDSHAKE";
        j["timestamp"] = audit_util_time_get(sess.sess_start_time);
        j["elapse"]    = audit_util_time_diff_from_now(sess.sess_start_time);
        j["server_attrs"]["variant"]   = "Redis";
        j["server_attrs"]["version"]   = sess.server_version;
        break;

    case REDIS_PHASE_CMD:
        j["timestamp"] = audit_util_time_get(sess.cmd_start_time);  /* command start time */
        j["elapse"]    = audit_util_time_diff_from_now(sess.cmd_start_time);
        j["type"]    = "COMMAND";
        j["command"] = "COM_QUERY";
        j["statement"] = sts->statement_string;
        j["category"] = sts->statement_category;
        break;

    case REDIS_PHASE_END:
        j["timestamp"] = audit_util_time_get_now();                           /* right now */
        j["elapse"]    = audit_util_time_diff_from_now(sess.sess_start_time); /* whole session */
        j["type"] = "END";
        break;

    default:
        break;
    }

    j["affected_rows"] = 0;

    j["tcp"]["saddr"] = sess.tuple.saddr;
    j["tcp"]["daddr"] = sess.tuple.daddr;
    j["tcp"]["sport"] = sess.tuple.sport;
    j["tcp"]["dport"] = sess.tuple.dport;

    j["statistics"]["client_sess_sent_bytes"] = sess.statistics_session_client;
    j["statistics"]["server_sess_sent_bytes"] = sess.statistics_session_server;
    j["statistics"]["client_cmd_sent_bytes"]  = sess.statistics_command_client;
    j["statistics"]["server_cmd_sent_bytes"]  = sess.statistics_command_server;

    redis_audit_log_write(g_audit_fd, j);
}

/*****************************************************************************/


