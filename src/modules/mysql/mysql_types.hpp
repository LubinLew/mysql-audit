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


#ifndef __MYSQL_TYPES_H__
#define __MYSQL_TYPES_H__
/*****************************************************************************/

#include <audit_types.hpp>

/*****************************************************************************/

/* The client or server may bundle several MySQL packets, compress it and send it as one compressed packet. */
enum mysql_compress_type_t {
    MYSQL_COMPRESS_NONE, /* uncompressed */
    MYSQL_COMPRESS_ZLIB, /* deflate algorithm as described in RFC 1951 and implemented in zlib */
    MYSQL_COMPRESS_ZSTD
};


/*****************************************************************************
 *For most commands the client sends to the server, 
 *the server returns one of these packets in response:
 */
enum mysql_response_type_t {
    MYSQL_RESP_TYPE_OK  = 0x00,  /* OK_Packet */
    MYSQL_RESP_TYPE_LI  = 0xFB,  /* LOCAL INFILE */
    MYSQL_RESP_TYPE_EOF = 0xFE,  /* EOF_Packet */
    MYSQL_RESP_TYPE_ERR = 0xFF,  /* ERR_Packet */
};


/*****************************************************************************/

enum mysql_data_dir_t {
    MYSQL_DATA_DIR_C2S,  /* Client TO Server */
    MYSQL_DATA_DIR_S2C   /* Server To Client */
};

/*****************************************************************************/

enum mysql_packet_type_t {
    MYSQL_PACK_TYPE_RESP_OK,
    MYSQL_PACK_TYPE_RESP_ERR,
    MYSQL_PACK_TYPE_RESP_EOF,

    MYSQL_PACK_TYPE_HANDSHAKE_REQUEST,    //Protocol::HandshakeV10
    MYSQL_PACK_TYPE_HANDSHAKE_RESPONSE,   //Protocol::HandshakeResponse41
    MYSQL_PACK_TYPE_HANDSHAKE_SSL_REQUEST,//Protocol::SSLRequest
    MYSQL_PACK_TYPE_AUTH_SWICH_REQUEST,  //Protocol::AuthSwitchRequest
    MYSQL_PACK_TYPE_AUTH_SWICH_RESPONSE, //Protocol::AuthSwitchResponse
    MYSQL_PACK_TYPE_AUTH_MORE_DATA,      //Protocol::AuthMoreData
    MYSQL_PACK_TYPE_AUTH_NEXT_FACTOR,    //Protocol::AuthNextFactor  (NOT SUPPORTED)

    MYSQL_PACK_TYPE_LOCAL_INFILE_REQUEST,
    MYSQL_PACK_TYPE_LOCAL_INFILE_RESPONSE,

    MYSQL_PACK_TYPE_COLUMN_COUNT,
    MYSQL_PACK_TYPE_COLUMN_DEFINITION,
    MYSQL_PACK_TYPE_TEXT_RESULTSET_ROW,
    MYSQL_PACK_TYPE_BINARY_RESULTSET_ROW,

    MYSQL_PACK_TYPE_CMD_SLEEP,
    MYSQL_PACK_TYPE_CMD_QUIT,
    MYSQL_PACK_TYPE_CMD_INIT_DB,
    MYSQL_PACK_TYPE_CMD_QUERY,
    MYSQL_PACK_TYPE_CMD_FIELD_LIST,
    MYSQL_PACK_TYPE_CMD_CREATE_DB,
    MYSQL_PACK_TYPE_CMD_DROP_DB,
    MYSQL_PACK_TYPE_CMD_REFRESH,
    MYSQL_PACK_TYPE_CMD_SHUTDOWN,
    MYSQL_PACK_TYPE_CMD_STATISTICS,
    MYSQL_PACK_TYPE_CMD_PROCESS_INFO,
    MYSQL_PACK_TYPE_CMD_CONNECT,      /* Currently refused by the server. */
    MYSQL_PACK_TYPE_CMD_PROCESS_KILL, /* Deprecated. */
    MYSQL_PACK_TYPE_CMD_DEBUG,
    MYSQL_PACK_TYPE_CMD_PING,
    MYSQL_PACK_TYPE_CMD_TIME,           /* Currently refused by the server. */
    MYSQL_PACK_TYPE_CMD_DELAYED_INSERT, /* Functionality removed. */
    MYSQL_PACK_TYPE_CMD_CHANGE_USER,
    MYSQL_PACK_TYPE_CMD_BINLOG_DUMP,
    MYSQL_PACK_TYPE_CMD_TABLE_DUMP,
    MYSQL_PACK_TYPE_CMD_CONNECT_OUT,
    MYSQL_PACK_TYPE_CMD_REGISTER_SLAVE,
    MYSQL_PACK_TYPE_CMD_STMT_PREPARE,
    MYSQL_PACK_TYPE_CMD_STMT_PREPARE_OK,
    MYSQL_PACK_TYPE_CMD_STMT_EXECUTE,
    MYSQL_PACK_TYPE_CMD_STMT_SEND_LONG_DATA,
    MYSQL_PACK_TYPE_CMD_STMT_CLOSE,
    MYSQL_PACK_TYPE_CMD_STMT_RESET,
    MYSQL_PACK_TYPE_CMD_SET_OPTION,
    MYSQL_PACK_TYPE_CMD_STMT_FETCH,
    MYSQL_PACK_TYPE_CMD_DAEMON,
    MYSQL_PACK_TYPE_CMD_BINLOG_DUMP_GTID,
    MYSQL_PACK_TYPE_CMD_RESET_CONNECTION, 
    MYSQL_PACK_TYPE_CMD_CLONE,
    MYSQL_PACK_TYPE_CMD_SUBSCRIBE_GROUP_REPLICATION_STREAM,
    MYSQL_PACK_TYPE_CMD_STMT_BULK_EXECUTE,
};


/*****************************************************************************/

/* Standard Packet Format of MySQL/MariaDB
 *
 * https://mariadb.com/kb/en/0-packet/
 * https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_packets.html
 *
 * | Type        | Name              | Description            | MariaDB | MySQL
 * +-------------+-------------------+------------------------+---------+-------
 * | int<3>      | payload_length<1> | Length of the payload  | YES     | YES
 * | int<1>      | sequence_id<2>    | Sequence ID            | YES     | YES
 * | string<var> | payload           | payload of the packet  | YES     | YES
 *
 * <1>payload_length : The number of bytes in the packet beyond the initial 4 bytes that make up the packet header.
 * <2>sequence_id    : The sequence-id is incremented with each packet and may wrap around. 
 *                     It starts at 0 and is reset to 0 when a new command begins in the Command Phase.
 */
struct mysql_packet_t {
    uint32_t payload_length:24;
    uint32_t sequence_id:8;
    uint8_t  payload[]; /* http://gcc.gnu.org/onlinedocs/gcc/Zero-Length.html */
};

/*****************************************************************************/

enum mysql_sess_phase_t {
    MYSQL_SESS_PHASE_HANDSHAKE,
    MYSQL_SESS_PHASE_CMD,
    MYSQL_SESS_PHASE_END
};


enum mysql_variant_t {
    MYSQL_VARIANT_MYSQL,
    MYSQL_VARIANT_MARIADB,
    MYSQL_VARIANT_PERCONA
};
/*****************************************************************************/


/* MySQL/MariaDB Commands
 * 
 * https://github.com/mysql/mysql-server/blob/8.0/include/my_command.h
 * https://github.com/MariaDB/server/blob/11.3/include/mysql_com.h
 */
enum enum_server_command {
    COM_SLEEP,
    COM_QUIT,
    COM_INIT_DB,
    COM_QUERY,
    COM_FIELD_LIST,
    COM_CREATE_DB, /* 5 */
    COM_DROP_DB,
    COM_REFRESH,
    COM_SHUTDOWN,
    COM_STATISTICS,
    COM_PROCESS_INFO, /* 10 */
    COM_CONNECT,      /* Currently refused by the server. */
    COM_PROCESS_KILL, /* Deprecated. */
    COM_DEBUG,
    COM_PING,
    COM_TIME,           /* Currently refused by the server. 15 */
    COM_DELAYED_INSERT, /* Functionality removed. */
    COM_CHANGE_USER,
    COM_BINLOG_DUMP,
    COM_TABLE_DUMP,
    COM_CONNECT_OUT, /* 20 */
    COM_REGISTER_SLAVE,
    COM_STMT_PREPARE,
    COM_STMT_EXECUTE,
    COM_STMT_SEND_LONG_DATA,
    COM_STMT_CLOSE, /* 25 */
    COM_STMT_RESET,
    COM_SET_OPTION,
    COM_STMT_FETCH,
    COM_DAEMON,
    COM_BINLOG_DUMP_GTID, /* 30 */
    COM_RESET_CONNECTION, 
    COM_CLONE,
    COM_SUBSCRIBE_GROUP_REPLICATION_STREAM,
#if 1 /* MariaDB command */
    COM_MDB_GAP_BEG = COM_CLONE, /* 32 */
    COM_MDB_GAP_END=249,
    COM_STMT_BULK_EXECUTE=250,
    COM_SLAVE_WORKER=251,
    COM_SLAVE_IO=252,
    COM_SLAVE_SQL=253,
    COM_RESERVED_1=254,
#endif /* MariaDB command */
    COM_END /* Not a real command. Refused. */
};


/*****************************************************************************/

/* client/server capabilities
 * Docs:   https://dev.mysql.com/doc/dev/mysql-server/latest/group__group__cs__capabilities__flags.html
 * Source: https://github.com/mysql/mysql-server/blob/8.0/include/mysql_com.h
 */

#define CLIENT_LONG_PASSWORD 1
#define CLIENT_FOUND_ROWS   2
#define CLIENT_LONG_FLAG 4
#define CLIENT_CONNECT_WITH_DB 8
#define CLIENT_NO_SCHEMA   16
#define CLIENT_COMPRESS 32
#define CLIENT_ODBC 64
#define CLIENT_LOCAL_FILES 128
#define CLIENT_IGNORE_SPACE 256
#define CLIENT_PROTOCOL_41 512
#define CLIENT_INTERACTIVE 1024
#define CLIENT_SSL 2048
#define CLIENT_IGNORE_SIGPIPE 4096
#define CLIENT_TRANSACTIONS 8192
#define CLIENT_RESERVED 16384
#define CLIENT_SECURE_CONNECTION    32768
#define CLIENT_MULTI_STATEMENTS (1UL << 16)
#define CLIENT_MULTI_RESULTS (1UL << 17)
#define CLIENT_PS_MULTI_RESULTS (1UL << 18)
#define CLIENT_PLUGIN_AUTH (1UL << 19)
#define CLIENT_CONNECT_ATTRS (1UL << 20)
#define CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA (1UL << 21)
#define CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS (1UL << 22)
#define CLIENT_SESSION_TRACK (1UL << 23)
#define CLIENT_DEPRECATE_EOF (1UL << 24)
#define CLIENT_OPTIONAL_RESULTSET_METADATA (1UL << 25)
#define CLIENT_ZSTD_COMPRESSION_ALGORITHM (1UL << 26)
#define CLIENT_QUERY_ATTRIBUTES (1UL << 27)
#define MULTI_FACTOR_AUTHENTICATION (1UL << 28)
#define CLIENT_CAPABILITY_EXTENSION (1UL << 29)
#define CLIENT_SSL_VERIFY_SERVER_CERT (1UL << 30)
#define CLIENT_REMEMBER_OPTIONS   (1UL << 31)


/*****************************************************************************/


/** The status flags are a bit-field */
enum SERVER_STATUS_flags_enum {
    SERVER_STATUS_IN_TRANS = 1,
    SERVER_STATUS_AUTOCOMMIT = 2,   /**< Server in auto_commit mode */
    SERVER_MORE_RESULTS_EXISTS = 8, /**< Multi query - next query exists */
    SERVER_QUERY_NO_GOOD_INDEX_USED = 16,
    SERVER_QUERY_NO_INDEX_USED = 32,
    SERVER_STATUS_CURSOR_EXISTS = 64,
    SERVER_STATUS_LAST_ROW_SENT = 128,
    SERVER_STATUS_DB_DROPPED = 256, /**< A database was dropped */
    SERVER_STATUS_NO_BACKSLASH_ESCAPES = 512,
    SERVER_STATUS_METADATA_CHANGED = 1024,
    SERVER_QUERY_WAS_SLOW = 2048,
    SERVER_PS_OUT_PARAMS = 4096,
    SERVER_STATUS_IN_TRANS_READONLY = 8192,
    SERVER_SESSION_STATE_CHANGED = (1UL << 14)
};


/*****************************************************************************/

/* 
 * https://github.com/mysql/mysql-server/blob/8.0/include/field_types.h
 */
enum enum_field_types {
  MYSQL_TYPE_DECIMAL,
  MYSQL_TYPE_TINY,
  MYSQL_TYPE_SHORT,
  MYSQL_TYPE_LONG,
  MYSQL_TYPE_FLOAT,
  MYSQL_TYPE_DOUBLE, //5
  MYSQL_TYPE_NULL,
  MYSQL_TYPE_TIMESTAMP,
  MYSQL_TYPE_LONGLONG,
  MYSQL_TYPE_INT24,
  MYSQL_TYPE_DATE, //10
  MYSQL_TYPE_TIME,
  MYSQL_TYPE_DATETIME,
  MYSQL_TYPE_YEAR,
  MYSQL_TYPE_NEWDATE, /**< Internal to MySQL. Not used in protocol */
  MYSQL_TYPE_VARCHAR, //15
  MYSQL_TYPE_BIT,
  MYSQL_TYPE_TIMESTAMP2,
  MYSQL_TYPE_DATETIME2,   /**< Internal to MySQL. Not used in protocol */
  MYSQL_TYPE_TIME2,       /**< Internal to MySQL. Not used in protocol */
  MYSQL_TYPE_TYPED_ARRAY, /**< Used for replication only */
  MYSQL_TYPE_INVALID = 243,
  MYSQL_TYPE_BOOL = 244, /**< Currently just a placeholder */
  MYSQL_TYPE_JSON = 245,
  MYSQL_TYPE_NEWDECIMAL = 246,
  MYSQL_TYPE_ENUM = 247,
  MYSQL_TYPE_SET = 248,
  MYSQL_TYPE_TINY_BLOB = 249,
  MYSQL_TYPE_MEDIUM_BLOB = 250,
  MYSQL_TYPE_LONG_BLOB = 251,
  MYSQL_TYPE_BLOB = 252,
  MYSQL_TYPE_VAR_STRING = 253,
  MYSQL_TYPE_STRING = 254,
  MYSQL_TYPE_GEOMETRY = 255
};



/*****************************************************************************/

/** options for ::mysql_options() */
enum enum_mysql_set_option {
  MYSQL_OPTION_MULTI_STATEMENTS_ON,
  MYSQL_OPTION_MULTI_STATEMENTS_OFF
};


/*****************************************************************************/


enum enum_cursor_type {
  CURSOR_TYPE_NO_CURSOR = 0,
  CURSOR_TYPE_READ_ONLY = 1,
  CURSOR_TYPE_FOR_UPDATE = 2,
  CURSOR_TYPE_SCROLLABLE = 4,
  /**
    On when the client will send the parameter count
    even for 0 parameters.
  */
  PARAMETER_COUNT_AVAILABLE = 8
};


/*****************************************************************************/

/** COM_REFRESH Flags (first byte) */
enum enum_mysql_refresh_flag {
    REFRESH_GRANT     = 1,   /* Refresh grant tables */
    REFRESH_LOG       = 2,   /* Start on new log file */
    REFRESH_TABLES    = 4,   /* close all tables */
    REFRESH_HOSTS     = 8,   /* Flush host cache */
    REFRESH_STATUS    = 16,  /* Flush status variables */
    REFRESH_THREADS   = 32,  /* Flush thread cache */
    REFRESH_SLAVE     = 64,  /* Reset master info and restart slave thread */
    REFRESH_MASTER    = 128, /* Remove all bin logs in the index and truncate the index */
};


/*****************************************************************************/

/* MariaDB bulk execute flags */
#define MARIADB_BULK_AUTOID      64
#define MARIADB_BULK_SEND_TYPES 128

/* parameter indicator type */
enum mariadb_param_indicator_t {
    MARIAB_PARAM_INDICATOR_NONE = 0,
    MARIAB_PARAM_INDICATOR_NULL,
    MARIAB_PARAM_INDICATOR_DEFAULT,
    MARIAB_PARAM_INDICATOR_IGNORE
};


/*****************************************************************************/
#endif /* __MYSQL_TYPES_H__ */

