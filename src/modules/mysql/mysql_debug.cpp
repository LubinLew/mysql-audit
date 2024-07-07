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


#include <ios>
#include <iomanip>
#include <string>
#include <sstream>
#include <iostream>
#include <cstddef>

#include <string.h>
#include <stdarg.h>

#include "mysql_info.hpp"
#include "mysql_debug.hpp"

using namespace std;

/*****************************************************************************/

enum mysql_debug_type_t {
    MYSQL_DBG_TYPE_INT,
    MYSQL_DBG_TYPE_HEX,
    MYSQL_DBG_TYPE_STR,
    MYSQL_DBG_TYPE_STR_ARR,
    MYSQL_DBG_TYPE_STR_MAP,
    MYSQL_DBG_TYPE_BYTE,
    MYSQL_DBG_TYPE_PARAMS
};

struct mysql_debug_opt_t {
    const char* description;
    mysql_debug_type_t type;

    size_t length;
    size_t offset;
};

/*****************************************************************************/

static void mysql_debug_print_session(mysql_sess_t& sess)
{
    TEST_AUDIT_DEBUG_LEVEL_DBG

    auto& type = mysql_info_get_packet_type(sess.packet_type);
    cout << std::dec << "[" <<  sess.id  << "]<" << type << ">{";
    if (sess.data_dir == MYSQL_DATA_DIR_C2S) {
        cout << sess.tuple.saddr << ":" << sess.tuple.sport << " > " << sess.tuple.daddr << ":" << sess.tuple.dport;
    } else {
        cout << sess.tuple.daddr << ":" << sess.tuple.dport << " > " << sess.tuple.saddr << ":" << sess.tuple.sport;
    }

    cout << "} Next State: " << mysql_info_get_state(sess.state) << endl;
}


void mysql_debug_start_session(mysql_sess_t& sess)
{
    TEST_AUDIT_DEBUG_LEVEL_INFO

    cout << std::dec << "[[ SESSION START ]] {" << sess.tuple.saddr << ":" << sess.tuple.sport << " -> " << sess.tuple.daddr << ":" << sess.tuple.dport << "}" << endl;
}


void mysql_debug_end_session(mysql_sess_t& sess)
{
    TEST_AUDIT_DEBUG_LEVEL_INFO

    cout << std::dec << "[[ SESSION END ]] {" << sess.tuple.saddr << ":" << sess.tuple.sport << " -> " << sess.tuple.daddr << ":" << sess.tuple.dport << "}" << endl;
}


void mysql_debug_exit_session(mysql_sess_t& sess)
{
    TEST_AUDIT_DEBUG_LEVEL_WARN

    cout << std::dec << "[[ SESSION EXIT ]] {" << sess.tuple.saddr << ":" << sess.tuple.sport << " -> " << sess.tuple.daddr << ":" << sess.tuple.dport << "}" << endl;
}


void mysql_debug_data_coming(mysql_sess_t& sess, mysql_data_dir_t dir, size_t len)
{
    TEST_AUDIT_DEBUG_LEVEL_DBG

    audit_str_t direction;
    direction = (dir == MYSQL_DATA_DIR_C2S ? "Client" : "Server");
    std::cout << ">>>>>>>>>>>>[" << sess.id << "]" << direction << " side " << std::dec << len << " bytes data" << std::endl;
}


void mysql_debug_print_packet(mysql_sess_t& sess, mysql_packet_t* packet, size_t len)
{
    TEST_AUDIT_DEBUG_LEVEL_DBG

    audit_str_t end;
    audit_str_t direction;

    if (len > ((uint64_t)packet->payload_length + 4)) {
        end = "[Mutil-Packs]";
    } else {
        end = "";
    }

    direction = (sess.data_dir == MYSQL_DATA_DIR_C2S ? "Client" : "Server");

    std::cout << "[" << direction << " Buff Data(" << std::dec << len << ") Packet Length: " << packet->payload_length << ", Packet Number: " << packet->sequence_id << ", STATE: " << mysql_info_get_state(sess.state) << "]"  << end << std::endl;

    TEST_AUDIT_DEBUG_LEVEL_PKG
    if (packet->payload_length <= len) {
        audit_bytes_t pkg;
        pkg.assign(packet->payload, packet->payload + packet->payload_length);
        audit_debug_byte_dump(pkg, "");
    }
}


static uint64_t mysql_debug_type_int(size_t len, size_t offset, uint8_t *data, size_t* plen)
{
    uint8_t* field = data + offset;
    uint64_t result = 0;

    switch (len) {
    case 1:
        result  = *(uint8_t *)field;
        break;
    case 2:
        result = *(uint16_t *)field;
        break;
    case 4:
        result = *(uint32_t *)field;
        break;
    case 8:
        result = *(uint64_t *)field;
        break;
    default:
        break;
    }

    if (len == sizeof(uint64_t)) {// <lenenc> field
        if (result < 0xFB) {
            *plen = 1;
        } else if (result < 0x0000FFFF) {
            *plen = 2 + 1;
        } else if (result < 0x00FFFFFF) {
            *plen = 3 + 1;
        } else {
            *plen = 8 + 1;
        }
    } else {
        *plen = len;
    }

    return result;
}


static string& mysql_debug_type_string(size_t len, size_t offset, uint8_t *data, size_t* plen)
{
    uint8_t *field = data + offset;
    string& str = *(string *)field;
    *plen = str.size();
    return str;
}


static string mysql_debug_type_byte(size_t len, size_t offset, uint8_t *data, size_t* plen)
{
    uint8_t *field = data + offset;
    audit_bytes_t& str = *(audit_bytes_t *)field;
    size_t size = str.size();    
    std::ostringstream oss;

    if (size != 0) {
        for (const auto& it : str) {
            oss << std::hex << setfill('0') << setw(2) << (uint32_t)it;
        }
    }

    *plen = size;
    return oss.str();
}

static audit_str_arr_t& mysql_debug_type_vector_string(size_t len, size_t offset, uint8_t *data)
{
    return *(audit_str_arr_t*)(data + offset);
}



static audit_str_map_t& mysql_debug_type_attr(size_t len, size_t offset, uint8_t *data)
{
    return *(audit_str_map_t*)(data + offset);
}


static mysql_bin_params_t& mysql_debug_type_params(size_t len, size_t offset, uint8_t *data)
{
    return *(mysql_bin_params_t*)(data + offset);
}


static void mysql_debug_protocol(mysql_debug_opt_t *tbl, size_t n, uint8_t *data)
{
    TEST_AUDIT_DEBUG_LEVEL_PKG

    uint64_t integer;
    size_t length;

    for (size_t i = 0; i < n; i++) {
        const auto& item = tbl[i];

        cout << "  " << item.description << "(" << dec;
        switch (item.type) {
        case MYSQL_DBG_TYPE_INT:
            integer = mysql_debug_type_int(item.length, item.offset, data, &length);
            cout  << length << "i): "<< integer << endl;
            break;

        case MYSQL_DBG_TYPE_HEX:
            integer = mysql_debug_type_int(item.length, item.offset, data, &length);
            cout << length << "h): 0x" << hex << integer << endl;
            break;

        case MYSQL_DBG_TYPE_STR: {
                auto& str = mysql_debug_type_string(item.length, item.offset, data, &length);
                cout << length << "s): " << str << endl;
            }
            break;

        case MYSQL_DBG_TYPE_STR_MAP: {
                auto& map = mysql_debug_type_attr(item.length, item.offset, data);
                cout << map.size() << "c): "<<endl;
                for (const auto& it : map) {
                    cout << "    " << it.first << ": " << it.second << endl;
                }
            }
            break;

        case MYSQL_DBG_TYPE_BYTE: {
                auto str = mysql_debug_type_byte(item.length, item.offset, data, &length);
                cout << length << "b): " << str << endl;
            }
            break;

        case MYSQL_DBG_TYPE_STR_ARR: {
                auto& vt = mysql_debug_type_vector_string(item.length, item.offset, data);
                cout << vt.size() << "c): " << endl;
                for (const auto& it : vt) {
                    cout << "    " << it << endl;
                }
            }
            break;

        case MYSQL_DBG_TYPE_PARAMS: {
            auto& param = mysql_debug_type_params(item.length, item.offset, data);
            cout << param.size() << "c): " << endl;
            for (const auto& it : param) { //mysql_binary_param_t
                if (it.parameter_name.size()) {
                    cout << "    " << it.parameter_name << ": " << it.parameter_value << endl;
                } else {
                    cout << "    " << it.parameter_value << endl;
                }
            }
        }
        break;
        }
    }
}


void mysql_debug_handshake_request(mysql_sess_t &sess)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"Protocol",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint8_t),
         offsetof(mysql_handshake_request_t, server_protocol)},
        {"Version",
         MYSQL_DBG_TYPE_STR,
         0,
         offsetof(mysql_handshake_request_t, server_version)},
        {"Thread ID",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint32_t),
         offsetof(mysql_handshake_request_t, connection_id)},
        {"Salt",
         MYSQL_DBG_TYPE_BYTE,
         0,
         offsetof(mysql_handshake_request_t, auth_plugin_data1)},
        {"Server Capabilities",
         MYSQL_DBG_TYPE_HEX,
         sizeof(uint16_t),
         offsetof(mysql_handshake_request_t, capability_lower)},
        {"Server Language",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint8_t),
         offsetof(mysql_handshake_request_t, server_character_set)},
        {"Authentication Plugin Length",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint8_t),
         offsetof(mysql_handshake_request_t, auth_plugin_data_len)},
        {"Server Status",
         MYSQL_DBG_TYPE_HEX,
         sizeof(uint16_t),
         offsetof(mysql_handshake_request_t, server_status_flags)},
        {"Extended Server Capabilities",
         MYSQL_DBG_TYPE_HEX,
         sizeof(uint16_t),
         offsetof(mysql_handshake_request_t, capability_upper)},
        {"Authentication Plugin",
         MYSQL_DBG_TYPE_STR,
         sizeof(uint16_t),
         offsetof(mysql_handshake_request_t, auth_plugin_name)},
    };

    mysql_debug_print_session(sess);
    mysql_handshake_request_t &data = sess.handshake_request;
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t*)&data);
}


void mysql_debug_handshake_response(mysql_sess_t & sess)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"Client Capabilities",
         MYSQL_DBG_TYPE_HEX,
         sizeof(uint32_t),
         offsetof(mysql_handshake_respone_t, client_capabilities)},
        {"MAX Packet",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint32_t),
         offsetof(mysql_handshake_respone_t, max_packet_size)},
        {"Charset",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint8_t),
         offsetof(mysql_handshake_respone_t, character_set)},
        {"Username",
         MYSQL_DBG_TYPE_STR,
         0,
         offsetof(mysql_handshake_respone_t, username)},
        {"Atuh Response Length",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint64_t),
         offsetof(mysql_handshake_respone_t, auth_response_length)},
        {"Password",
         MYSQL_DBG_TYPE_BYTE,
         0,
         offsetof(mysql_handshake_respone_t, auth_response)},
        {"Client Auth Plugin",
         MYSQL_DBG_TYPE_STR,
         0,
         offsetof(mysql_handshake_respone_t, client_plugin_name)},
        {"Database",
         MYSQL_DBG_TYPE_STR,
         0,
         offsetof(mysql_handshake_respone_t, database)},
        {"Connection Attributes Length",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint64_t),
         offsetof(mysql_handshake_respone_t, client_attr_length)},
        {"Connection Attributes",
         MYSQL_DBG_TYPE_STR_MAP,
         0,
         offsetof(mysql_handshake_respone_t, client_attr)},
        {"zstd_compression_level",
        MYSQL_DBG_TYPE_INT,
        sizeof(uint8_t),
        offsetof(mysql_handshake_respone_t, zstd_compression_level)},
    };

    mysql_debug_print_session(sess);
    mysql_handshake_respone_t& data = sess.handshake_respone;
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t *)&data);
}


void mysql_debug_auth_more_data(mysql_sess_t &sess, mysql_auth_more_data_t& data)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"Data",
         MYSQL_DBG_TYPE_BYTE,
         0,
         offsetof(mysql_auth_more_data_t, data)}
    };

    mysql_debug_print_session(sess);
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t *)&data);
}

void mysql_debug_auth_switch_request(mysql_sess_t &sess, mysql_auth_switch_request_t& req)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"Status Flag",
         MYSQL_DBG_TYPE_HEX,
         sizeof(uint8_t),
         offsetof(mysql_auth_switch_request_t, status_flag)},
        {"Auth Method Name",
         MYSQL_DBG_TYPE_STR,
         0,
         offsetof(mysql_auth_switch_request_t, plugin_name)},
        {"Auth Method Data",
         MYSQL_DBG_TYPE_BYTE,
         0,
         offsetof(mysql_auth_switch_request_t, plugin_data)},
    };

    mysql_debug_print_session(sess);
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t *)&req);
}


void mysql_debug_auth_switch_response(mysql_sess_t &sess, mysql_auth_switch_response_t& resp)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"Auth Method Data",
         MYSQL_DBG_TYPE_BYTE,
         0,
         offsetof(mysql_auth_switch_response_t, data)},
    };

    mysql_debug_print_session(sess);
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t *)&resp);
}


void mysql_debug_response_ok(mysql_sess_t &sess, mysql_ok_packet_t& ok)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"code",
         MYSQL_DBG_TYPE_HEX,
         sizeof(uint8_t),
         offsetof(mysql_ok_packet_t, header)},
        {"Affected_Rows",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint64_t),
         offsetof(mysql_ok_packet_t, affected_rows)},
        {"Last Insert-id",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint64_t),
         offsetof(mysql_ok_packet_t, last_insert_id)},
        {"Status Flags",
         MYSQL_DBG_TYPE_HEX,
         sizeof(uint16_t),
         offsetof(mysql_ok_packet_t, status_flags)},
        {"Warning",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint16_t),
         offsetof(mysql_ok_packet_t, warnings)},
    };

    mysql_debug_print_session(sess);
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t *)&ok);
}


void mysql_debug_response_err(mysql_sess_t &sess, mysql_err_packet_t& err)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"Error Code",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint16_t),
         offsetof(mysql_err_packet_t, error_code)},
        {"sql_state_marker",
         MYSQL_DBG_TYPE_STR,
         0,
         offsetof(mysql_err_packet_t, sql_state_marker)},
        {"sql_state",
         MYSQL_DBG_TYPE_STR,
         0,
         offsetof(mysql_err_packet_t, sql_state)},
        {"Error Message",
         MYSQL_DBG_TYPE_STR,
         0,
         offsetof(mysql_err_packet_t, error_message)}
    };

    mysql_debug_print_session(sess);
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t *)&err);
}


void mysql_debug_response_eof(mysql_sess_t &sess, mysql_eof_packet_t& eof)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"Warnings",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint16_t),
         offsetof(mysql_eof_packet_t, warnings)},
        {"Status Flags",
         MYSQL_DBG_TYPE_HEX,
         sizeof(uint16_t),
         offsetof(mysql_eof_packet_t, status_flags)}
    };

    mysql_debug_print_session(sess);
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t *)&eof);
}


void mysql_debug_cmd_quit(mysql_sess_t &sess)
{
    mysql_debug_print_session(sess);
}

void mysql_debug_cmd_query(mysql_sess_t &sess, mysql_cmd_query_t& req)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"Command",
         MYSQL_DBG_TYPE_HEX,
         sizeof(uint8_t),
         offsetof(mysql_cmd_query_t, command)},
        {"Parameter Count",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint64_t),
         offsetof(mysql_cmd_query_t, parameter_count)},
        {"Parameter Set Count",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint64_t),
         offsetof(mysql_cmd_query_t, parameter_set_count)},
        {"parameter_count",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint64_t),
         offsetof(mysql_cmd_query_t, parameter_count)},
        {"parameters",
         MYSQL_DBG_TYPE_PARAMS,
         0,
         offsetof(mysql_cmd_query_t, parameters)},
        {"Statement",
         MYSQL_DBG_TYPE_STR,
         0,
        offsetof(mysql_cmd_query_t, query)},
    };

    mysql_debug_print_session(sess);
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t *)&req);
}


void mysql_debug_column_count_packet(mysql_sess_t &sess, mysql_column_count_t& count)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"Metadata Follows",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint8_t),
         offsetof(mysql_column_count_t, metadata_follows)},
        {"Column Count",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint64_t),
         offsetof(mysql_column_count_t, column_count)},
    };

    mysql_debug_print_session(sess);
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t *)&count);
}


void mysql_debug_column_definition_packet(mysql_sess_t &sess, mysql_column_def41_t& column)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"Catalog",
         MYSQL_DBG_TYPE_STR,
         0,
         offsetof(mysql_column_def41_t, catalog)},
        {"Schema",
         MYSQL_DBG_TYPE_STR,
         0,
         offsetof(mysql_column_def41_t, schema)},
        {"Table",
         MYSQL_DBG_TYPE_STR,
         0,
         offsetof(mysql_column_def41_t, table)},
        {"Org Table",
         MYSQL_DBG_TYPE_STR,
         0,
         offsetof(mysql_column_def41_t, org_table)},
        {"Name",
         MYSQL_DBG_TYPE_STR,
         0,
         offsetof(mysql_column_def41_t, name)},
        {"Org Name",
         MYSQL_DBG_TYPE_STR,
         0,
         offsetof(mysql_column_def41_t, org_name)},
        {"Fixed Length",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint64_t),
         offsetof(mysql_column_def41_t, fixed_length)},
        {"Character Set",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint16_t),
         offsetof(mysql_column_def41_t, character_set)},
        {"Column Length",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint32_t),
         offsetof(mysql_column_def41_t, column_length)},
        {"Type",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint8_t),
         offsetof(mysql_column_def41_t, type)},
        {"Flags",
         MYSQL_DBG_TYPE_HEX,
         sizeof(uint16_t),
         offsetof(mysql_column_def41_t, flags)},
        {"Decimals",
         MYSQL_DBG_TYPE_HEX,
         sizeof(uint8_t),
         offsetof(mysql_column_def41_t, decimals)},
    };

    mysql_debug_print_session(sess);
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t *)&column);
}

void mysql_debug_text_resultset_row_packet(mysql_sess_t &sess, mysql_text_resultset_row_packet_t& row)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"Text",
         MYSQL_DBG_TYPE_STR_ARR,
         0,
         offsetof(mysql_text_resultset_row_packet_t, texts)}
    };

    mysql_debug_print_session(sess);
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t *)&row);
}


void mysql_debug_binary_resultset_row_packet(mysql_sess_t &sess, mysql_binary_resultset_row_packet_t& row)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"Text",
         MYSQL_DBG_TYPE_BYTE,
         0,
         offsetof(mysql_binary_resultset_row_packet_t, null_bitmap)},
        {"Text",
         MYSQL_DBG_TYPE_BYTE,
         0,
         offsetof(mysql_binary_resultset_row_packet_t, values)}
    };

    mysql_debug_print_session(sess);
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t *)&row);
}


void mysql_debug_local_inflie_request(mysql_sess_t &sess, mysql_infile_request_t& data)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"FileName",
         MYSQL_DBG_TYPE_STR,
         0,
         offsetof(mysql_infile_request_t, filename)}
    };

    mysql_debug_print_session(sess);
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t *)&data);
}

void mysql_debug_local_inflie_response(mysql_sess_t &sess, mysql_infile_response_t& data)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"Raw Data",
         MYSQL_DBG_TYPE_BYTE,
         0,
         offsetof(mysql_infile_response_t, raw_data)}
    };

    mysql_debug_print_session(sess);
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t *)&data);
}



void mysql_debug_cmd_initdb(mysql_sess_t &sess, mysql_cmd_initdb_t& db)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"Schema_Name",
         MYSQL_DBG_TYPE_STR,
         0,
         offsetof(mysql_cmd_initdb_t, schema_name)}
    };

    mysql_debug_print_session(sess);
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t *)&db);

}

void mysql_debug_cmd_field_list(mysql_sess_t &sess, mysql_cmd_field_list_t& list)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"Table",
         MYSQL_DBG_TYPE_STR,
         0,
         offsetof(mysql_cmd_field_list_t, table)},
        {"Wildcard",
         MYSQL_DBG_TYPE_STR,
         0,
         offsetof(mysql_cmd_field_list_t, wildcard)}
    };

    mysql_debug_print_session(sess);
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t *)&list);
}


void mysql_debug_cmd_refresh(mysql_sess_t &sess, mysql_cmd_refresh_t& refresh)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"Sub Command",
         MYSQL_DBG_TYPE_HEX,
         sizeof(uint8_t),
         offsetof(mysql_cmd_refresh_t, sub_command)},
    };

    mysql_debug_print_session(sess);
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t *)&refresh);
}


void mysql_debug_cmd_statistics_request(mysql_sess_t &sess)
{
    mysql_debug_print_session(sess);
}


void mysql_debug_cmd_ping(mysql_sess_t &sess)
{
    mysql_debug_print_session(sess);
}

void mysql_debug_cmd_debug(mysql_sess_t &sess)
{
    mysql_debug_print_session(sess);
}


void mysql_debug_cmd_change_user(mysql_sess_t &sess, mysql_cmd_change_user_t& user)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"user",
         MYSQL_DBG_TYPE_STR,
         0,
         offsetof(mysql_cmd_change_user_t, user)},
        {"auth_plugin_data_len",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint8_t),
         offsetof(mysql_cmd_change_user_t, auth_plugin_data_len)},
        {"auth_plugin_data",
         MYSQL_DBG_TYPE_BYTE,
         0,
         offsetof(mysql_cmd_change_user_t, auth_plugin_data)},
         {"database",
          MYSQL_DBG_TYPE_STR,
          0,
          offsetof(mysql_cmd_change_user_t, database)},
        {"character_set",
         MYSQL_DBG_TYPE_HEX,
         sizeof(uint16_t),
         offsetof(mysql_cmd_change_user_t, character_set)},
        {"auth_plugin_name",
         MYSQL_DBG_TYPE_STR,
         sizeof(uint16_t),
         offsetof(mysql_cmd_change_user_t, auth_plugin_name)},
        {"connection_attributes_length",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint64_t),
         offsetof(mysql_cmd_change_user_t, connection_attributes_length)},
        {"connection_attributes",
         MYSQL_DBG_TYPE_STR_MAP,
         0,
         offsetof(mysql_cmd_change_user_t, connection_attributes)},
    };

    mysql_debug_print_session(sess);
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t *)&user);
}

void mysql_debug_com_reset_connection(mysql_sess_t &sess, mysql_cmd_reset_connection_t& conn)
{
    mysql_debug_print_session(sess);
}

void mysql_debug_cmd_process_kill(mysql_sess_t &sess, mysql_cmd_process_kill_t& kill)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"connection_id",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint32_t),
         offsetof(mysql_cmd_process_kill_t, connection_id)},
    };

    mysql_debug_print_session(sess);
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t *)&kill);
}



void mysql_debug_cmd_statistics_response(mysql_sess_t &sess, mysql_cmd_statistics_t& statistics)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"Statistics",
         MYSQL_DBG_TYPE_STR,
         0,
         offsetof(mysql_cmd_statistics_t, statistics)},
    };

    mysql_debug_print_session(sess);
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t *)&statistics);
}


void mysql_debug_cmd_smst_prepare(mysql_sess_t &sess, mysql_cmd_stmt_prepare_t& pre)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"query",
         MYSQL_DBG_TYPE_STR,
         0,
         offsetof(mysql_cmd_stmt_prepare_t, query)},
    };

    mysql_debug_print_session(sess);
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t *)&pre);
}


void mysql_debug_cmd_smst_prepare_response(mysql_sess_t &sess, mysql_cmd_stmt_prepare_ok_t& pre)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"status",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint8_t),
         offsetof(mysql_cmd_stmt_prepare_ok_t, status)},
        {"statement_id",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint32_t),
         offsetof(mysql_cmd_stmt_prepare_ok_t, statement_id)},
        {"num_columns",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint16_t),
         offsetof(mysql_cmd_stmt_prepare_ok_t, num_columns)},
        {"num_params",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint16_t),
         offsetof(mysql_cmd_stmt_prepare_ok_t, num_params)},
        {"warning_count",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint16_t),
         offsetof(mysql_cmd_stmt_prepare_ok_t, warning_count)},
        {"metadata_follows",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint8_t),
         offsetof(mysql_cmd_stmt_prepare_ok_t, metadata_follows)},
    };

    mysql_debug_print_session(sess);
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t *)&pre);
}



void mysql_debug_cmd_smst_execute(mysql_sess_t &sess, mysql_cmd_stmt_execute_t& exe)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"statement_id",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint32_t),
         offsetof(mysql_cmd_stmt_execute_t, statement_id)},
        {"cursor_type",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint8_t),
         offsetof(mysql_cmd_stmt_execute_t, flags)},
        {"parameter_count",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint64_t),
         offsetof(mysql_cmd_stmt_execute_t, parameter_count)},
        {"parameters",
         MYSQL_DBG_TYPE_PARAMS,
         0,
         offsetof(mysql_cmd_stmt_execute_t, parameters)},
    };

    mysql_debug_print_session(sess);
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t *)&exe);


}

void mysql_debug_cmd_smst_close(mysql_sess_t &sess, mysql_cmd_stmt_close_t& close)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"statement_id",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint32_t),
         offsetof(mysql_cmd_stmt_close_t, statement_id)},
    };

    mysql_debug_print_session(sess);
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t *)&close);
}

void mysql_debug_cmd_smst_fetch(mysql_sess_t &sess, mysql_cmd_stmt_fetch_t& fetch)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"statement_id",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint32_t),
         offsetof(mysql_cmd_stmt_fetch_t, statement_id)},
        {"num_rows",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint32_t),
         offsetof(mysql_cmd_stmt_fetch_t, num_rows)},
    };

    mysql_debug_print_session(sess);
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t *)&fetch);


}


void mysql_debug_cmd_smst_reset(mysql_sess_t &sess, mysql_cmd_stmt_reset_t& rst)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"statement_id",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint32_t),
         offsetof(mysql_cmd_stmt_reset_t, statement_id)},
    };

    mysql_debug_print_session(sess);
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t *)&rst);
}


void mysql_debug_cmd_smst_send_long_data(mysql_sess_t &sess, mysql_cmd_stmt_send_long_data_t& data)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"statement_id",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint32_t),
         offsetof(mysql_cmd_stmt_send_long_data_t, statement_id)},
        {"param_id",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint16_t),
         offsetof(mysql_cmd_stmt_send_long_data_t, param_id)},
        {"data",
         MYSQL_DBG_TYPE_BYTE,
         0,
         offsetof(mysql_cmd_stmt_send_long_data_t, data)},
    };

    mysql_debug_print_session(sess);
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t *)&data);
}

void mysql_debug_cmd_smst_bulk_execute(mysql_sess_t &sess, mysql_cmd_stmt_bulk_execute_t& bulk)
{
    mysql_debug_print_session(sess);
}

void mysql_debug_cmd_binlog_dump(mysql_sess_t &sess, mysql_cmd_binlog_dump_t& dump)
{
    static mysql_debug_opt_t dbg_tbl[] = {
        {"binlog_pos",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint32_t),
         offsetof(mysql_cmd_binlog_dump_t, binlog_pos)},
        {"flags",
         MYSQL_DBG_TYPE_HEX,
         sizeof(uint16_t),
         offsetof(mysql_cmd_binlog_dump_t, flags)},
        {"server_id",
         MYSQL_DBG_TYPE_INT,
         sizeof(uint32_t),
         offsetof(mysql_cmd_binlog_dump_t, server_id)},
        {"binlog_filename",
         MYSQL_DBG_TYPE_STR,
         0,
         offsetof(mysql_cmd_binlog_dump_t, binlog_filename)},
    };

    mysql_debug_print_session(sess);
    mysql_debug_protocol(dbg_tbl, sizeof(dbg_tbl) / sizeof(dbg_tbl[0]), (uint8_t *)&dump);

}

/*****************************************************************************/

