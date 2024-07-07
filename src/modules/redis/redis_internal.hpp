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


#ifndef __REDIS_INTERNAL_HPP__
#define __REDIS_INTERNAL_HPP__
/*****************************************************************************/

#include <queue>
#include <iostream>

#include <tls/tls.hpp>
#include <audit_types.hpp>

/*****************************************************************************/

/* RESP3 is a superset of RESP2 that mainly aims to make a client author's life a little bit easier. */
enum redis_data_version_t {
    REDIS_DATA_VER_RESP1, // not support, Redis Version < 2.0
    REDIS_DATA_VER_RESP2, // Redis Version >= 2.0
    REDIS_DATA_VER_RESP3  // Redis Version >= 7.0
};

/* Simple types are similar to scalars in programming languages that represent plain literal values. Booleans and Integers are such examples.
 *
 * RESP strings are either simple or bulk. 
 * Simple strings never contain carriage return (\r) or line feed (\n) characters. 
 * Bulk strings can contain any binary data and may also be referred to as binary or blob. 
 * Note that bulk strings may be further encoded and decoded, e.g. with a wide multi-byte encoding, by the client.
 *
 * Aggregates, such as Arrays and Maps, can have varying numbers of sub-elements and nesting levels.
 */
enum redis_data_category_t {
    REDIS_DATA_CGY_SIMPLE,   // simple
    REDIS_DATA_CGY_AGGREGATE // aggregate
};

enum redis_data_type_t {
    REDIS_DATA_TYPE_SIMPLE_STRINGS   = '+',    //RESP2  Simple      +
    REDIS_DATA_TYPE_SIMPLE_ERRORS    = '-',    //RESP2  Simple      -
    REDIS_DATA_TYPE_INTEGERS         = ':',    //RESP2  Simple      :
    REDIS_DATA_TYPE_BULK_STRINGS     = '$',    //RESP2  Aggregate   $
    REDIS_DATA_TYPE_ARRAYS           = '*',    //RESP2  Aggregate   *
    REDIS_DATA_TYPE_NULLS            = '_',    //RESP3  Simple      _
    REDIS_DATA_TYPE_BOOLEANS         = '#',    //RESP3  Simple      #
    REDIS_DATA_TYPE_DOUBLES          = ',',    //RESP3  Simple      ,
    REDIS_DATA_TYPE_BIG_NUMBERS      = '(',    //RESP3  Simple      (
    REDIS_DATA_TYPE_BULK_ERRORS      = '!',    //RESP3  Aggregate   !
    REDIS_DATA_TYPE_VERBATIM_STRINGS = '=',    //RESP3  Aggregate   =
    REDIS_DATA_TYPE_MAPS             = '%',    //RESP3  Aggregate   %
    REDIS_DATA_TYPE_SETS             = '~',    //RESP3  Aggregate   ~
    REDIS_DATA_TYPE_PUSHES           = '>',    //RESP3  Aggregate   >     Server->Client
};

enum redis_cmd_type_t {
    REDIS_CMD_TYPE_OTHER = 0,
    REDIS_CMD_TYPE_AUTH,
    REDIS_CMD_TYPE_PING,
    REDIS_CMD_TYPE_SELECT,
    REDIS_CMD_TYPE_QUIT
};

enum redis_phase_t {
    REDIS_PHASE_STA,
    REDIS_PHASE_CMD,
    REDIS_PHASE_END
};

struct redis_statement_t {
    audit_str_t      statement_string;
    redis_cmd_type_t statement_type;
    const char*      statement_category;
};

struct redis_sess_t {
    audit_str_t   id;
    audit_tuple_t tuple;
    redis_phase_t phase;

    audit_str_t server_version;
    audit_str_t  user;
    audit_str_t  passwd;
    audit_str_t  database;

    std::queue<redis_statement_t> statements;
    bool         is_error;
    audit_str_t  error_msg;

    bool         is_ssl_testd;
    bool         is_ssl;
    tls_sess_t*  tls;

    struct timespec     sess_start_time;
    struct timespec     cmd_start_time;      /* command start time */

    audit_flow_direction_t direction;

    /* bytes statistics(no TCP/IP part, only redis Packet) */
    uint64_t statistics_session_client; /* how many byte sent to server for whole session */
    uint64_t statistics_session_server; /* how many byte sent to client for whole session */
    uint64_t statistics_command_client; /* how many byte sent to server for current one command */
    uint64_t statistics_command_server; /* how many byte sent to client for current one command */
};


struct redis_sess_userdata_t {
    redis_sess_t* sess_data;
};


/*****************************************************************************/
#endif /* __REDIS_INTERNAL_HPP__ */

