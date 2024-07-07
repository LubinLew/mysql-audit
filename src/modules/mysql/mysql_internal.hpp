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


#ifndef __MYSQL_INTERNAL_HPP__
#define __MYSQL_INTERNAL_HPP__
/*****************************************************************************/

#include <time.h>

#include <tls/tls.hpp>

#include "mysql_types.hpp"

/*****************************************************************************/

enum mysql_state_t {
    MYSQL_STATE_HANDSHAKE_REQUEST,     /* Server -> Client */
    MYSQL_STATE_HANDSHAKE_RESPONSE,    /* Client -> Server */
    MYSQL_STATE_AUTH_SWITCH_REQUEST,   /* Server -> Client */
    MYSQL_STATE_AUTH_SWITCH_RESPONSE,  /* Client -> Server */
    MYSQL_STATE_AUTH_MOREDATA,
    MYSQL_STATE_GENGRIC_RQUEST,
    MYSQL_STATE_GENGRIC_RESPONSE,
    MYSQL_STATE_COLUMN_DEFINITION,     /* Server -> Client */
    MYSQL_STATE_TEXT_RESULTSET_ROW_PACKET,
    MYSQL_STATE_BINARY_RESULTSET_ROW_PACKET,
    MYSQL_STATE_LOCAL_INFILE_RESPONSE, /* Client -> Server */
    MYSQL_STATE_CMD_QUERY_RESPONSE,
    MYSQL_STATE_CMD_FIELDLIST_RESPONSE,
    MYSQL_STATE_CMD_STATISTICS_RESPONSE,
    MYSQL_STATE_CMD_PROCESS_INFO_RESPONSE,
    MYSQL_STATE_CMD_SMST_PREPARE_RESPONSE,
    MYSQL_STATE_CMD_SMST_EXECUTE_RESPONSE,
    MYSQL_STATE_CMD_SMST_FETCH_RESPONSE,
    MYSQL_STATE_CMD_BINLOG_DUMP_RESPONSE,
    MYSQL_STATE_CMD_END, /* command end, this is for Multi-Statement */
    MYSQL_STATE_CLOSED
};

struct mysql_binary_param_t {
    uint16_t    parameter_type;
    audit_str_t parameter_name;
    audit_str_t parameter_value;
 };

using mysql_bin_params_t = std::vector<mysql_binary_param_t>;

/*
 *https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html
 */
struct mysql_handshake_request_t {
    /* mysql server greeting */
    uint8_t        server_protocol;        /* always 10. when version < 3.21.0, it's 9 */
    audit_str_t    server_version;
    uint32_t       connection_id;           /* thread id */
    audit_bytes_t auth_plugin_data1;       /* auth-plugin-data-part-1 */
    /* skip 1 byte(filter) must be 0x00 */
    uint16_t       capability_lower; /* capability_flags_1 */
    uint8_t        server_character_set;
    uint16_t       server_status_flags;
    uint16_t       capability_upper; /* capability_flags_2 */
    uint8_t        auth_plugin_data_len;
    /* skip 10 byte(reserved) must be 0x00 */
    audit_bytes_t  auth_plugin_data2;       /* auth-plugin-data-part-2 */
    audit_str_t    auth_plugin_name;

    //Management Data
    uint32_t       server_capabilities;
};


struct mysql_handshake_respone_t {
    uint32_t        client_capabilities; //client_flag;
    uint32_t        max_packet_size;
    uint8_t         character_set;
    /* skip 23 bytes(filter) */
    audit_str_t     username;
    uint64_t        auth_response_length;
    audit_bytes_t   auth_response;
    audit_str_t     database;
    audit_str_t     client_plugin_name;
    uint64_t        client_attr_length;
    uint8_t         client_attr_count;
    audit_str_map_t client_attr;
    uint8_t         zstd_compression_level;
};

struct mysql_auth_more_data_t {
    uint8_t       header;
    audit_bytes_t data;
};

struct mysql_auth_switch_request_t {
    uint8_t status_flag;
    audit_str_t plugin_name;
    audit_bytes_t plugin_data;
};


struct mysql_auth_switch_response_t {
    audit_bytes_t data;
};


/*****************************************************************************/

/* OK_Packet
 *
 * An OK packet is sent from the server to the client to signal successful completion of a command.
 *
 * https://mariadb.com/kb/en/ok_packet/
 * https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_ok_packet.html
 *
 */
struct mysql_ok_packet_t {
    uint8_t        header;
    uint64_t       affected_rows;
    uint64_t       last_insert_id;
    uint16_t       status_flags;
    uint16_t       warnings;
    audit_str_t    info;
    audit_bytes_t  session_state_info;
};

/*****************************************************************************/

/* EOF_Packet
 *
 * The eof packet marks the end of a resultset and returns status and warnings.
 * As of MySQL 5.7.5, OK packets are also used to indicate EOF, and EOF packets are deprecated.
 *
 * https://mariadb.com/kb/en/eof_packet/
 * https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_eof_packet.html
 *
   | Type   | Name          | Description              | MariaDB | MySQL
 * +--------+---------------+--------------------------+---------+----------------------------------
 * | int<1> | header        | 0xFE EOF packet header   | YES     | YES
 * | int<2> | warnings　    | number of warnings       | YES     | capabilities & CLIENT_PROTOCOL_41
 * | int<2> | status_flags　| SERVER_STATUS<1>         | YES     | capabilities & CLIENT_PROTOCOL_41
 *
 * <1>SERVER_STATUS
 * - https://mariadb.com/kb/en/ok_packet/#server-status-flag
 * - https://dev.mysql.com/doc/dev/mysql-server/latest/mysql__com_8h.html#a1d854e841086925be1883e4d7b4e8cad
 *
 * <2>Note
 * - MySQL: You must check whether the packet length is less than 9 to make sure that it is a EOF_Packet packet.
 * - MariaDB: When testing for an EOF packet, the packet size must be less than 9 bytes in length. 
 *   Resultset can send data that begins with a 0xfe byte, but then the packet length will be greater than 9.
 */
struct mysql_eof_packet_t {
    uint8_t  header;
    uint16_t warnings;
    uint16_t status_flags;
};


/*****************************************************************************/


/* ERR_Packet
 * 
 * This packet signals that an error occurred.
 *
 * https://mariadb.com/kb/en/err_packet/
 * https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_err_packet.html
 */
struct mysql_err_packet_t {
    uint8_t        header;
    uint16_t       error_code;
    audit_str_t    sql_state_marker;
    audit_str_t    sql_state;
    audit_str_t    error_message;
};


/*****************************************************************************/


struct mysql_date_t {
    uint8_t  length; // number of bytes following (valid values: 0, 4, 7, 11)
    uint16_t year;
    uint8_t  month;
    uint8_t  day;
    uint8_t  hour;
    uint8_t  minute;
    uint8_t  second;
    uint32_t microsecond;
};


struct mysql_time_t {
    uint8_t  length; //  number of bytes following (valid values: 0, 8, 12)
    uint8_t  is_negative; // 1 if minus, 0 for plus
    uint32_t days;
    uint8_t  hour;
    uint8_t  minute;
    uint8_t  second;
    uint32_t microsecond;
};

/* 
 * https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query.html
 */

struct mysql_cmd_query_t {
    uint8_t  command;
    uint64_t parameter_count;
    uint64_t parameter_set_count; /* Number of parameter sets. Currently always 1 */
    audit_bytes_t null_bitmap;
    uint8_t new_params_bind_flag;
    mysql_bin_params_t parameters;
    audit_str_t query;
};

struct mysql_column_count_t {
    uint8_t  metadata_follows;
    uint64_t column_count;
};

struct mysql_text_resultset_row_packet_t {
    audit_str_arr_t texts;
};

struct mysql_binary_resultset_row_packet_t {
    uint8_t packet_header;
    audit_bytes_t null_bitmap;
    audit_bytes_t values;
};


struct mysql_infile_request_t {
    audit_str_t filename;
};

struct mysql_infile_response_t {
    audit_bytes_t raw_data;
};

/*****************************************************************************/


/* COM_QUIT
 *
 * Tells the server that the client wants it to close the connection.
 *
 * https://mariadb.com/kb/en/com_quit/
 * https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_quit.html
 *
 * | Type   | Name          | Description              | MariaDB | MySQL
 * +--------+---------------+--------------------------+---------+-------
 * | int<1> | command       | 0x01: COM_QUIT           | YES     | YES
 *
 */
struct mysql_cmd_quit_t {
    uint8_t command;
};


/*****************************************************************************/


/* COM_INIT_DB
 *
 * Change the default schema of the connection
 *
 * https://mariadb.com/kb/en/com_init_db/
 * https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_init_db.html
 *
 * | Type   | Name          | Description                     | MariaDB | MySQL
 * +--------+---------------+---------------------------------+---------+-------
 * | int<1> | command       | 0x02: COM_INIT_DB               | YES     | YES
 * | int<1> | schema name   | name of the schema to change to | YES     | YES
 *
 */
struct mysql_cmd_initdb_t {
    uint8_t command;
    audit_str_t schema_name;
};


/*****************************************************************************/


/* COM_FIELD_LIST
 *
 * displays information about the columns in a given table
 *
 * https://mariadb.com/kb/en/com_field_list/
 * https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_field_list.html
 *
 * | Type        | Name       | Description                     | MariaDB    | MySQL
 * +-------------+------------+---------------------------------+------------+-------
 * | int<1>      | command    | 0x03: COM_FIELD_LIST            | deprecated | YES
 * | string<NUL> | table      | table name                      | deprecated | YES
 * | string<EOF> | wildcard   | field wildcard                  | deprecated | YES
 *
 */
struct mysql_cmd_field_list_t {
    uint8_t command;
    audit_str_t table;
    audit_str_t wildcard;
};


/*****************************************************************************/


/* COM_REFRESH
 *
 * displays information about the columns in a given table
 *
 * https://mariadb.com/kb/en/com_field_list/
 * https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_refresh.html
 *
 * | Type        | Name        | Description         | MariaDB    | MySQL
 * +-------------+-------------+---------------------+------------+----------------
 * | int<1>      | command     | 0x04: COM_REFRESH   | deprecated | YES, deprecated 
 * | int<1>      | sub_command | Flags               | deprecated | YES, deprecated 
 *
 */
struct mysql_cmd_refresh_t {
    uint8_t command;
    uint8_t sub_command;
};


/*****************************************************************************/


/* COM_STATISTICS
 *
 * Get a human readable string of some internal status vars.
 *
 * https://mariadb.com/kb/en/com_statistics/
 * https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_statistics.html
 *
 * | Type        | Name        | Description         | MariaDB    | MySQL
 * +-------------+-------------+---------------------+------------+----------------
 * | int<1>      | command     | COM_STATISTICS      | deprecated | YES, deprecated 
 *
 * Notes:
 * - MySQL   : 0x08
 * - MariaDB : 0x09
 */
struct mysql_cmd_statistics_t {
    audit_str_t statistics;
};


/*****************************************************************************/


/* COM_PROCESS_INFO
 *
 * Get a list of active threads
 *
 * https://mariadb.com/kb/en/com_processlist/
 * https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_process_info.html
 *
 * | Type   | Name          | Description              | MariaDB | MySQL
 * +--------+---------------+--------------------------+---------+-------
 * | int<1> | command       | 0x0A: COM_PROCESS_INFO   | YES     | YES
 *
 */
struct mysql_cmd_process_info_t {
    uint8_t  command;
};


/*****************************************************************************/


/* COM_PROCESS_KILL
 *
 * Forces the server to terminate a specified connection.
 *
 * https://mariadb.com/kb/en/com_process_kill/
 * https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_process_kill.html
 *
 * | Type   | Name          | Description              | MariaDB    | MySQL
 * +--------+---------------+--------------------------+------------+-------
 * | int<1> | command       | 0x0C: COM_PROCESS_KILL   | deprecated | YES
 * | int<4> | connection_id | The connection to kill   | YES     | YES, deprecated 
 *
*/
struct mysql_cmd_process_kill_t {
    uint8_t  command;
    uint32_t connection_id;
};


/*****************************************************************************/


/* COM_DEBUG
 *
 * Forces the server to terminate a specified connection.
 *
 * https://mariadb.com/kb/en/com_debug/
 * https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_debug.html
 *
 * | Type   | Name          | Description              | MariaDB | MySQL
 * +--------+---------------+--------------------------+---------+-------
 * | int<1> | command       | 0x0D: COM_DEBUG          | YES     | YES
 *
*/
struct mysql_cmd_debug_t {
    uint8_t command;
};


/*****************************************************************************/


/* COM_PING
 *
 * Forces the server to terminate a specified connection.
 *
 * https://mariadb.com/kb/en/com_ping/
 * https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_ping.html
 *
 * | Type   | Name          | Description              | MariaDB | MySQL
 * +--------+---------------+--------------------------+---------+-------
 * | int<1> | command       | 0x0E: COM_PING           | YES     | YES
 *
*/
struct mysql_cmd_ping_t {
    uint8_t command;
};


/*****************************************************************************/


/* COM_CHANGE_USER
 *
 * Changes the user of the current connection.
 *
 * https://mariadb.com/kb/en/com_change_user/
 * https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_change_user.html
 *
 * | Type        | Name                         | Description                                               | MariaDB | MySQL
 * +-------------+------------------------------+-----------------------------------------------------------+---------+-----------------------------------------
 * | int<1>      | command                      | 0x11: COM_CHANGE_USER                                     | YES     | YES
 * | string<NUL> | user    　                   | user name                                                 | YES     | YES
 * | int<1>      | auth_plugin_data_len         | length of auth_response                                   | YES     | capabilities & CLIENT_SECURE_CONNECTION
 * | $length     | auth_plugin_data             | authentication data                                       | YES     | capabilities & CLIENT_SECURE_CONNECTION
 * | string<NUL> | database                     | schema name                                               | YES     | YES
 * | int<2>      | character_set                | new connection character set                              | YES     | YES
 * | string<NUL> | auth_plugin_name             | client authentication plugin name                         | YES     | capabilities & CLIENT_PLUGIN_AUTH 
 * | int<lenenc> | connection_attributes_length | length in bytes of the following block of key-value pairs | YES     | capabilities & CLIENT_CONNECT_ATTRS
 * | $length     | key Key name(loop)           | Key name                                                  | YES     | capabilities & CLIENT_CONNECT_ATTRS
 * | $length     | value of key(loop)           | value of key                                              | YES     | capabilities & CLIENT_CONNECT_ATTRS
 *
 */
struct mysql_cmd_change_user_t {
    uint8_t         command;
    audit_str_t     user;
    uint8_t         auth_plugin_data_len;
    audit_bytes_t   auth_plugin_data;
    audit_str_t     database;
    uint16_t        character_set;
    audit_str_t     auth_plugin_name;
    uint64_t        connection_attributes_length;
    audit_str_map_t connection_attributes;
};


/*****************************************************************************/


/* COM_RESET_CONNECTION
 *
 * Resets the session state
 *
 * https://mariadb.com/kb/en/com_reset_connection/
 * https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_reset_connection.html
 *
 * | Type   | Name          | Description                | MariaDB | MySQL
 * +--------+---------------+----------------------------+---------+-------
 * | int<1> | command       | 0x1F: COM_RESET_CONNECTION | YES     | YES
 *
*/
struct mysql_cmd_reset_connection_t {
    uint8_t command;
};


/*****************************************************************************/


/* COM_SET_OPTION
 *
 * Sets options for the current connection
 *
 * https://mariadb.com/kb/en/com_set_option/
 * https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_set_option.html
 *
 * | Type   | Name             | Description            | MariaDB | MySQL
 * +--------+------------------+------------------------+---------+-------
 * | int<1> | command          | 0x1A: COM_SET_OPTION   | YES     | YES
 * | int<2> | option_operation | The connection to kill | YES     | YES
 *
 */
struct mysql_cmd_set_option_t {
    uint8_t  command;
    uint16_t option_operation; //enum_mysql_set_option
};


//https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_prepare.html

struct mysql_cmd_stmt_prepare_t {
    uint8_t     command;
    audit_str_t query;
};

//https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_prepare.html#sect_protocol_com_stmt_prepare_response_ok
struct mysql_cmd_stmt_prepare_ok_t {
    uint8_t  status;
    uint32_t statement_id;
    uint16_t num_columns;
    uint16_t num_params;
    uint8_t  reserved_1;
    uint16_t warning_count;
    uint8_t  metadata_follows;

};


//https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_execute.html
struct mysql_cmd_stmt_execute_t {
    uint8_t  command;
    uint32_t statement_id;
    uint8_t  flags;  // enum_cursor_type
    uint32_t iteration_count;

    uint64_t parameter_count;
    audit_bytes_t null_bitmap;
    uint8_t  new_params_bind_flag;

    mysql_bin_params_t parameters;
};


//https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_fetch.html
struct mysql_cmd_stmt_fetch_t {
    uint8_t  command;
    uint32_t statement_id;
    uint32_t num_rows;
};


//https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_close.html
struct mysql_cmd_stmt_close_t {
    uint8_t  command;
    uint32_t statement_id;
};


//https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_reset.html
struct mysql_cmd_stmt_reset_t {
    uint8_t  command;
    uint32_t statement_id;
};


//https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_send_long_data.html
struct mysql_cmd_stmt_send_long_data_t {
    uint8_t       command;
    uint32_t      statement_id;
    uint16_t      param_id;
    audit_bytes_t data;
};


//https://mariadb.com/kb/en/com_stmt_bulk_execute/
struct mysql_cmd_stmt_bulk_execute_t {
    uint8_t    command;
    uint32_t   statement_id;
    uint16_t   bulk_flag;
};

/*****************************************************************************/


/*
 * https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query_response_text_resultset_column_definition.html
 */
struct mysql_column_def41_t {
    audit_str_t catalog;
    audit_str_t schema;
    audit_str_t table;
    audit_str_t org_table;
    audit_str_t name;
    audit_str_t org_name;
    uint64_t    fixed_length;
    uint16_t    character_set;
    uint32_t    column_length;
    uint8_t     type;
    uint16_t    flags;
    uint8_t     decimals;
};

struct mysql_cmd_binlog_dump_t {
    uint8_t     status;         // COM_BINLOG_DUMP
    uint32_t    binlog_pos;     // position in the binlog-file to start the stream with
    uint16_t    flags;          // can right now has one possible value: BINLOG_DUMP_NON_BLOCK
    uint32_t    server_id;      // Server id of this slave
    audit_str_t binlog_filename;// filename of the binlog on the master
};

/*
 * ColumnDefinition Packet Management
 */
struct mysql_col_mgr_t {
    uint32_t col_total_count;
    uint32_t col_recv_count;
};

/*
 * Row Packet Management
 */
struct mysql_row_mgr_t {
    bool     is_first_row;
    uint32_t row_count;
};

struct mysql_uncompress_mgt_t {
    audit_bytes_t buff;
    uint8_t*      buf_ptr;
    uint32_t      buf_len;
    uint32_t      buf_pos;

    uint32_t      packet_seqid; /* keep previous packet seqid */
    uint32_t      packet_index;
};


struct mysql_sess_t {
    audit_str_t   id;
    mysql_state_t state;
    audit_tuple_t tuple;

    bool             is_ssl;
    tls_sess_t*      tls;

    audit_str_t         user;      /* current user */
    audit_str_t         database;  /* current database */
    audit_str_t         initdb;    /* COM_INIT_DB set new DB */
    audit_str_t         chg_user;  /* COM_CHANGE_USER change new user */

    mysql_sess_phase_t  phase;     /* current phase */

    mysql_data_dir_t    data_dir;
    mysql_packet_type_t packet_type; /* current packet */

    enum_server_command command;   /* current command */
    struct timespec     sess_start_time;
    struct timespec     cmd_start_time;      /* command start time */
    bool                command_is_logd;
    audit_str_t         statement; /* current command statement */
    uint64_t            affected_rows;

    /* Complex Data Management */
    mysql_col_mgr_t     col_manager; /* column definition */
    mysql_row_mgr_t     row_manager; /* text resultset row */

    /* Server and Client Info */
    mysql_variant_t           variant;
    uint32_t                  capabilities; /* server and client negotiate */
    
    bool                      is_compressed;
    mysql_compress_type_t     compress_type;
    mysql_uncompress_mgt_t    server_uncompress_mgt;
    mysql_uncompress_mgt_t    client_uncompress_mgt;

    uint32_t                  packet_header_size; /* 4 or 7(compressed packet) */
    mysql_handshake_request_t handshake_request;
    mysql_handshake_respone_t handshake_respone;

    /* bytes statistics(no TCP/IP part, only MySQL Packet) */
    uint64_t statistics_session_client; /* how many byte sent to server for whole session */
    uint64_t statistics_session_server; /* how many byte sent to client for whole session */
    uint64_t statistics_command_client; /* how many byte sent to server for current one command */
    uint64_t statistics_command_server; /* how many byte sent to client for current one command */
};


struct mysql_sess_userdata_t {
    mysql_sess_t* sess_data;
};

/*****************************************************************************/
#endif /* __MYSQL_INTERNAL_HPP__ */

