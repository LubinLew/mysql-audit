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


#include "mysql_info.hpp"

/*****************************************************************************/

const audit_str_t& mysql_info_get_variant(mysql_variant_t type)
{
    const static audit_str_t _g_variant_tbl[] = {
        "MySQL",
        "MariaDB",
        "Percona"
    };

    return _g_variant_tbl[type];
}


const audit_str_t& mysql_info_get_cmd(enum_server_command cmd)
{
    const static audit_str_t _g_cmdname_tbl[] = {
    "COM_SLEEP",
    "COM_QUIT",
    "COM_INIT_DB",
    "COM_QUERY",
    "COM_FIELD_LIST",
    "COM_CREATE_DB",
    "COM_DROP_DB",
    "COM_REFRESH",
    "COM_SHUTDOWN",
    "COM_STATISTICS",
    "COM_PROCESS_INFO",
    "COM_CONNECT",      /* Currently refused by the server. */
    "COM_PROCESS_KILL", /* Deprecated. */
    "COM_DEBUG",
    "COM_PING",
    "COM_TIME",           /* Currently refused by the server. */
    "COM_DELAYED_INSERT", /* Functionality removed. */
    "COM_CHANGE_USER",
    "COM_BINLOG_DUMP",
    "COM_TABLE_DUMP",
    "COM_CONNECT_OUT",
    "COM_REGISTER_SLAVE",
    "COM_STMT_PREPARE",
    "COM_STMT_EXECUTE",
    "COM_STMT_SEND_LONG_DATA",
    "COM_STMT_CLOSE",
    "COM_STMT_RESET",
    "COM_SET_OPTION",
    "COM_STMT_FETCH",
    "COM_DAEMON",
    "COM_BINLOG_DUMP_GTID",
    "COM_RESET_CONNECTION",
    "COM_CLONE",
    "COM_SUBSCRIBE_GROUP_REPLICATION_STREAM"
    };

    const static audit_str_t _g_cmdname_tbl2[] = {
        "COM_MDB_GAP_END",
        "COM_STMT_BULK_EXECUTE",
        "COM_SLAVE_WORKER",
        "COM_SLAVE_IO",
        "COM_SLAVE_SQL",
        "COM_RESERVED_1",
    };

    const static audit_str_t _g_unknown("UNKNOWN_CMD");

    if (cmd >= COM_MDB_GAP_END) {
        return _g_cmdname_tbl2[cmd - COM_MDB_GAP_END];
    }

    if (cmd <= COM_SUBSCRIBE_GROUP_REPLICATION_STREAM) {
        return _g_cmdname_tbl[cmd];
    }

    return _g_unknown;
}

const audit_str_t& mysql_info_get_state(mysql_state_t state)
{
    const static audit_str_t _state_name_tbl[] = {
    "MYSQL_STATE_HANDSHAKE_REQUEST",     /* Server -> Client */
    "MYSQL_STATE_HANDSHAKE_RESPONSE",    /* Client -> Server */
    "MYSQL_STATE_AUTH_SWITCH_REQUEST",   /* Server -> Client */
    "MYSQL_STATE_AUTH_SWITCH_RESPONSE",  /* Client -> Server */
    "MYSQL_STATE_AUTH_MOREDATA",
    "MYSQL_STATE_GENGRIC_RQUEST",
    "MYSQL_STATE_GENGRIC_RESPONSE",
    "MYSQL_STATE_COLUMN_DEFINITION",     /* Server -> Client */
    "MYSQL_STATE_TEXT_RESULTSET_ROW_PACKET",
    "MYSQL_STATE_BINARY_RESULTSET_ROW_PACKET",
    "MYSQL_STATE_LOCAL_INFILE_RESPONSE", /* Client -> Server */
    "MYSQL_STATE_CMD_QUERY_RESPONSE",
    "MYSQL_STATE_CMD_FIELDLIST_RESPONSE",
    "MYSQL_STATE_CMD_STATISTICS_RESPONSE",
    "MYSQL_STATE_CMD_PROCESS_INFO_RESPONSE",
    "MYSQL_STATE_CMD_SMST_PREPARE_RESPONSE",
    "MYSQL_STATE_CMD_SMST_EXECTUTE_RESPONSE",
    "MYSQL_STATE_CMD_SMST_FETCH_RESPONSE",
    "MYSQL_STATE_CMD_BINLOG_DUMP_RESPONSE",
    "MYSQL_STATE_CMD_END", /* command end, this is for Multi-Statement */
    "MYSQL_STATE_CLOSED"
    };

    return _state_name_tbl[state];
}

const audit_str_t& mysql_info_get_packet_type(mysql_packet_type_t type)
{

    const static audit_str_t _g_packet_type_tbl[] = {
    "Response_OK_____________",
    "Response_ERR____________",
    "Response_EOF____________",
    "Handshake_Request_______",
    "Handshake_Response______",
    "SSLRequest______________",
    "AuthSwitchRequest_______",
    "AuthSwitchResponse______",
    "AuthMoreData____________",
    "AuthNextFactor__________",
    "Local_INFILE_Request____",
    "Local_INFILE_Response___",
    "Column_Count____________",
    "Column_Definition_______",
    "Text_Resultset_Row______",
    "Binary Resultset Row____",
    "CMD:_SLEEP______________",
    "CMD:_QUIT_______________",
    "CMD:_INIT_DB____________",
    "CMD:_QUERY______________",
    "CMD:_FIELD_LIST_________",
    "CMD:_CREATE_DB__________",
    "CMD:_DROP_DB____________",
    "CMD:_REFRESH____________",
    "CMD:_SHUTDOWN___________",
    "CMD:_STATISTICS_________",
    "CMD:_PROCESS_INFO_______",
    "CMD:_CONNECT____________",
    "CMD:_PROCESS_KILL_______",
    "CMD:_DEBUG______________",
    "CMD:_PING_______________",
    "CMD:_TIME_______________",
    "CMD:_DELAYED_INSERT_____",
    "CMD:_CHANGE_USER________",
    "CMD:_BINLOG_DUMP________",
    "CMD:_TABLE_DUMP_________",
    "CMD:_CONNECT_OUT________",
    "CMD:_REGISTER_SLAVE_____",
    "CMD:_STMT_PREPARE_______",
    "Response STMT_PREPARE OK",
    "CMD:_STMT_EXECUTE_______",
    "CMD:_STMT_SEND_LONG_DATA",
    "CMD:_STMT_CLOSE_________",
    "CMD:_STMT_RESET_________",
    "CMD:_SET_OPTION_________",
    "CMD:_STMT_FETCH_________",
    "CMD:_DAEMON_____________",
    "CMD:_BINLOG_DUMP_GTID___",
    "CMD:_RESET_CONNECTION___",
    "CMD:_CLONE______________",
    "CMD:_SUBSCRIBE_STREAM___",
    "CMD:_STMT_BULK_EXECUTE__"
    };

    return _g_packet_type_tbl[type];
}

/*****************************************************************************/

