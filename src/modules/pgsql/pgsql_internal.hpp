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


#ifndef __PGSQL_INTERNAL_HPP__
#define __PGSQL_INTERNAL_HPP__
/*****************************************************************************/

#include <iostream>

#include <tls/tls.hpp>
#include <audit_types.hpp>

/*****************************************************************************/

#define PGSQL_MESSAGE_LENGTH 4

#define PGSQL_MSG_TAG_CANCELREQUEST 80877102
#define PGSQL_MSG_TAG_SSLREQUEST    0x04d2162f //80877103
#define PGSQL_MSG_TAG_GSSENCREQUEST 80877104


enum pgsql_msg_type_t {
    PGSQL_MSG_TYPE_CANCELREQUEST, /* c 2 s */
    PGSQL_MSG_TYPE_GSSENCREQUEST, /* c 2 s */
    PGSQL_MSG_TYPE_SSL_REQUEST,   /* c 2 s */
    PGSQL_MSG_TYPE_SSL_RESPONSE,  /* s 2 c */
    PGSQL_MSG_TYPE_STARTUP,       /* c 2 s */
    /* frontend msg */
    PGSQL_MSG_TYPE_AUTH_MSG            = 'p',
    PGSQL_MSG_TYPE_SIMPLE_QUERY        = 'Q',
    PGSQL_MSG_TYPE_PARSE               = 'P',
    PGSQL_MSG_TYPE_BIND                = 'B',
    PGSQL_MSG_TYPE_EXEC                = 'E',
    PGSQL_MSG_TYPE_DESC                = 'D',
    PGSQL_MSG_TYPE_CLOSE               = 'C',
    PGSQL_MSG_TYPE_FLUSH               = 'H',
    PGSQL_MSG_TYPE_SYNC                = 'S',
    PGSQL_MSG_TYPE_FUNC                = 'F',
    PGSQL_MSG_TYPE_FE_COPY_DATA        = 'd',
    PGSQL_MSG_TYPE_COPY_COMP           = 'c',
    PGSQL_MSG_TYPE_COPY_FAIL           = 'f',
    PGSQL_MSG_TYPE_TERM                = 'X',
    /* backend msg */
    PGSQL_MSG_TYPE_AUTH_REQ            = 'R',
    PGSQL_MSG_TYPE_BE_KEY_DATA         = 'K',
    PGSQL_MSG_TYPE_PARAM_STATUS        = 'S',
    PGSQL_MSG_TYPE_PARSE_COMP          = '1', /* 0x31 */
    PGSQL_MSG_TYPE_BIND_COMP           = '2',
    PGSQL_MSG_TYPE_CLOSE_COMP          = '3',
    PGSQL_MSG_TYPE_CMD_COMP            = 'C',
    PGSQL_MSG_TYPE_PARAM_DSEC          = 't',
    PGSQL_MSG_TYPE_ROW_DESC            = 'T',
    PGSQL_MSG_TYPE_DATA_ROW            = 'D',
    PGSQL_MSG_TYPE_EMPTY_QUERY         = 'I',
    PGSQL_MSG_TYPE_NO_DATA             = 'n',
    PGSQL_MSG_TYPE_ERROR               = 'E',
    PGSQL_MSG_TYPE_NOTICE              = 'N',
    PGSQL_MSG_TYPE_PORTAL_SUSP         = 's',
    PGSQL_MSG_TYPE_READY_QUERY         = 'Z',
    PGSQL_MSG_TYPE_NOTIFY              = 'A',
    PGSQL_MSG_TYPE_FUNC_RESP           = 'V',
    PGSQL_MSG_TYPE_COPY_IN_RESP        = 'G',
    PGSQL_MSG_TYPE_COPY_OUT_RESP       = 'H',
    PGSQL_MSG_TYPE_BE_COPY_DATA        = 'd',
    PGSQL_MSG_TYPE_BE_COPY_COMP        = 'c',
    PGSQL_MSG_TYPE_BE_NEGO_VER         = 'v',

};

enum pgsql_auth_type_t {
    PGSQL_AUTH_TYPE_SUCCESS,
    PGSQL_AUTH_TYPE_KERBEROS4,
    PGSQL_AUTH_TYPE_KERBEROS5,
    PGSQL_AUTH_TYPE_PLAINTEXT,
    PGSQL_AUTH_TYPE_CRYPT,
    PGSQL_AUTH_TYPE_MD5,
    PGSQL_AUTH_TYPE_SCM,
    PGSQL_AUTH_TYPE_GSSAPI,
    PGSQL_AUTH_TYPE_GSSAPI_SSPI_CONTINUE,
    PGSQL_AUTH_TYPE_SSPI,
    PGSQL_AUTH_TYPE_SASL,
    PGSQL_AUTH_TYPE_SASL_CONTINUE,
    PGSQL_AUTH_TYPE_SASL_COMPLETE,
    PGSQL_AUTH_TYPE_INVALID
};

enum pgsql_pahse_t {
    PGSQL_PHASE_STA, /* startup */
    PGSQL_PHASE_CMD,
    PGSQL_PHASE_END,
};

enum pgsql_data_direction_t {
    PGSQL_DATA_DIR_C2S,  /* Client TO Server */
    PGSQL_DATA_DIR_S2C   /* Server To Client */
};

struct pgsql_msg_detail_t {
    uint8_t     type;
    const char* description;
};

struct pgsql_msg_t {
    uint8_t  type;
    uint32_t length;
    uint8_t* body;
};

struct pgsql_tuple_t {
    bool is_v6;

    audit_str_t saddr;
    audit_str_t daddr;

    uint16_t sport;
    uint16_t dport;
};

struct pgsql_msg_err_t {
    audit_str_t severity;
    audit_str_t text;
    audit_str_t code;
    audit_str_t message;
    audit_str_t file;
    audit_str_t line;
    audit_str_t routine;
};


struct pgsql_msg_startup_t {
    uint16_t major_version;
    uint16_t minor_version;
    /* key value pair */
    audit_str_map_t paris;
};

struct pgsql_msg_be_key_data_t {
    uint32_t pid;
    uint32_t key;
};

struct pgsql_sess_t {
    audit_str_t   id;
    audit_tuple_t tuple;
    pgsql_pahse_t phase;

    audit_str_t server_version;
    audit_str_t  user;
    audit_str_t  database;

    audit_str_t  statement;

    pgsql_msg_type_t msg_type;

    bool             is_login_success;
    bool             is_simple_query;
    bool             is_ssl;
    tls_sess_t*      tls;

    struct timespec     sess_start_time;
    struct timespec     cmd_start_time;      /* command start time */

    pgsql_data_direction_t direction;
    pgsql_msg_detail_t*    current_msg_info;

    pgsql_msg_startup_t startup_msg;
    audit_str_map_t        parameter_status;
    pgsql_msg_be_key_data_t be_key_data;

    /* bytes statistics(no TCP/IP part, only pgsql Packet) */
    uint64_t statistics_session_client; /* how many byte sent to server for whole session */
    uint64_t statistics_session_server; /* how many byte sent to client for whole session */
    uint64_t statistics_command_client; /* how many byte sent to server for current one command */
    uint64_t statistics_command_server; /* how many byte sent to client for current one command */
};


struct pgsql_sess_userdata_t {
    pgsql_sess_t* sess_data;
};


/*****************************************************************************/
#endif /* __PGSQL_INTERNAL_HPP__ */

