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


#include <audit_data.hpp>

#include "redis_internal.hpp"
#include "redis_data.hpp"
#include "redis_audit.hpp"
#include "redis_debug.hpp"


static const char* redis_data_type_name(uint8_t type)
{
    struct redis_data_type_2_name_t {
        redis_data_type_t type;
        const char*       name;
    };

    static redis_data_type_2_name_t tbl[] = {
        {REDIS_DATA_TYPE_SIMPLE_STRINGS  , "Simple strings  "},
        {REDIS_DATA_TYPE_SIMPLE_ERRORS   , "Simple Errors   "},
        {REDIS_DATA_TYPE_INTEGERS        , "Integers        "},
        {REDIS_DATA_TYPE_BULK_STRINGS    , "Bulk strings    "},
        {REDIS_DATA_TYPE_ARRAYS          , "Arrays          "},
        {REDIS_DATA_TYPE_NULLS           , "Nulls           "},
        {REDIS_DATA_TYPE_BOOLEANS        , "Booleans        "},
        {REDIS_DATA_TYPE_DOUBLES         , "Doubles         "},
        {REDIS_DATA_TYPE_BIG_NUMBERS     , "Big numbers     "},
        {REDIS_DATA_TYPE_BULK_ERRORS     , "Bulk errors     "},
        {REDIS_DATA_TYPE_VERBATIM_STRINGS, "Verbatim strings"},
        {REDIS_DATA_TYPE_MAPS            , "Maps            "},
        {REDIS_DATA_TYPE_SETS            , "Sets            "},
        {REDIS_DATA_TYPE_PUSHES          , "Pushes          "}
    };

    for (size_t i = 0; i < sizeof(tbl)/sizeof(redis_data_type_2_name_t); i++) {
        if (type == tbl[i].type) {
            return tbl[i].name;
        }
    }

    return "Unknown";
}

static audit_str_t redis_data_type_simple_string(redis_sess_t& sess, uint8_t** start, uint8_t* end)
{
    return audit_data_get_crlf_string(start, end);
}

static audit_str_t redis_data_type_simple_error(redis_sess_t& sess, uint8_t** start, uint8_t* end)
{
    return audit_data_get_crlf_string(start, end);
}

static audit_str_t redis_data_type_integer(redis_sess_t& sess, uint8_t** start, uint8_t* end)
{
    return audit_data_get_crlf_string(start, end);
}

static audit_str_t redis_data_type_bulk_string(redis_sess_t& sess, uint8_t** start, uint8_t* end)
{
//    size_t remain = audit_data_get_remain_length(start, end);

    auto size = std::atol(audit_data_get_crlf_string(start, end).c_str());
    if (size == -1) { /* Null bulk strings in RESP2 */
        return "";
    }

    auto bulk = audit_data_get_fixed_string(start, end, size);
    audit_data_skip_bytes(start, end, 2); // skip the final CRLF

    return bulk;
}

static audit_str_t redis_data_type_array(redis_sess_t& sess, uint8_t** start, uint8_t* end)
{
    auto size = std::atol(audit_data_get_crlf_string(start, end).c_str());
    if (size == -1) { /* Null array in RESP2 */
        return "";
    }

    audit_str_t result("");
    for (long i = 0; i < size; i++) {
        auto val = redis_data_proc(sess, start, end);
        result = result.append(val);
        if ((i != (size - 1)) && (size != 1)) {
            result.push_back(' ');
        }
    }

    return result;
}

static audit_str_t redis_data_type_null(redis_sess_t& sess, uint8_t** start, uint8_t* end)
{
    audit_data_skip_bytes(start, end, 2); // skip the final CRLF
    return "nul";
}

static audit_str_t redis_data_type_boolean(redis_sess_t& sess, uint8_t** start, uint8_t* end)
{
    audit_data_skip_bytes(start, end, 2); // skip the final CRLF
    return "nul";
}

static audit_str_t redis_data_type_double(redis_sess_t& sess, uint8_t** start, uint8_t* end)
{
    return audit_data_get_crlf_string(start, end);
}

static audit_str_t redis_data_type_big_number(redis_sess_t& sess, uint8_t** start, uint8_t* end)
{
    return audit_data_get_crlf_string(start, end);
}

static audit_str_t redis_data_type_bulk_error(redis_sess_t& sess, uint8_t** start, uint8_t* end)
{
    auto size = std::atol(audit_data_get_crlf_string(start, end).c_str());
    if (size == -1) { /* Null bulk strings in RESP2 */
        return "";
    }

    auto bulk = audit_data_get_fixed_string(start, end, size);
    audit_data_skip_bytes(start, end, 2); // skip the final CRLF

    return bulk;
}

static audit_str_t redis_data_type_verbatim_string(redis_sess_t& sess, uint8_t** start, uint8_t* end)
{
    auto size = std::atol(audit_data_get_crlf_string(start, end).c_str());
    if (size == -1) { /* Null bulk strings in RESP2 */
        return "";
    }

    auto bulk = audit_data_get_fixed_string(start, end, size);
    audit_data_skip_bytes(start, end, 2); // skip the final CRLF

    return bulk;
}

static audit_str_t redis_data_type_map(redis_sess_t& sess, uint8_t** start, uint8_t* end)
{
    auto size = std::atol(audit_data_get_crlf_string(start, end).c_str());
    if (size <= 0) {
        return "{}";
    }

    audit_str_t result("{");

    for (long i = 0; i < size; i++) {
        auto key = redis_data_proc(sess, start, end);
        auto val = redis_data_proc(sess, start, end);
        result = result.append(key + ": " + val);
        if ((i != (size - 1)) && (size != 1)) {
            result.push_back(',');
        }
    }

    result.push_back('}');

    return result;
}

static audit_str_t redis_data_type_set(redis_sess_t& sess, uint8_t** start, uint8_t* end)
{
    auto size = std::atol(audit_data_get_crlf_string(start, end).c_str());
    if (size == -1) { /* Null array in RESP2 */
        return "()";
    }

    audit_str_t result("(");
    for (long i = 0; i < size; i++) {
        auto val = redis_data_proc(sess, start, end);
        result = result.append(val);
        if ((i != (size - 1)) && (size != 1)) {
            result.push_back(',');
        }
    }
    result.push_back(')');

    return result;
}

static audit_str_t redis_data_type_push(redis_sess_t& sess, uint8_t** start, uint8_t* end)
{
    auto size = std::atol(audit_data_get_crlf_string(start, end).c_str());
    if (size <= 0) {
        return "{}";
    }

    audit_str_t result("{");
    for (long i = 0; i < size; i++) {
        auto key = redis_data_proc(sess, start, end);
        auto val = redis_data_proc(sess, start, end);
        result = result.append(key + ": " + val);
        if ((i != (size - 1)) && (size != 1)) {
            result.push_back(',');
        }
    }
    result.push_back('}');

    return result;
}

audit_str_t redis_data_proc(redis_sess_t& sess, uint8_t** start, uint8_t* end)
{
    audit_str_t ret {};
    uint8_t type = audit_data_get_uint8(start, end);

    /* we only care about ERROR on server side */
    if (g_audit_debug_level < AUDIT_DBG_LVL_PKG) {
        if (sess.direction == AUDIT_FLOW_DIR_S2C) {
            if ((type != REDIS_DATA_TYPE_SIMPLE_ERRORS) && (type != REDIS_DATA_TYPE_BULK_ERRORS)) {
            /* Server Return OK (or data), skip */
                return "OK";
            }
        }
    }

    sess.is_error = false;

    switch (type) {
    case REDIS_DATA_TYPE_SIMPLE_STRINGS:      //RESP2  Simple      +
        ret = redis_data_type_simple_string(sess, start, end);
        break;
    case REDIS_DATA_TYPE_SIMPLE_ERRORS:       //RESP2  Simple      -
        sess.is_error = true;
        ret = redis_data_type_simple_error(sess, start, end);
        break;
    case REDIS_DATA_TYPE_INTEGERS:            //RESP2  Simple      :
        ret = redis_data_type_integer(sess, start, end);
        break;
    case REDIS_DATA_TYPE_BULK_STRINGS:        //RESP2  Aggregate   $
        ret = redis_data_type_bulk_string(sess, start, end);
        break;
    case REDIS_DATA_TYPE_ARRAYS:              //RESP2  Aggregate   *
        ret = redis_data_type_array(sess, start, end);
        break;
    case REDIS_DATA_TYPE_NULLS:               //RESP3  Simple      _
        ret = redis_data_type_null(sess, start, end);
        break;
    case REDIS_DATA_TYPE_BOOLEANS:            //RESP3  Simple      #
        ret = redis_data_type_boolean(sess, start, end);
        break;
    case REDIS_DATA_TYPE_DOUBLES:             //RESP3  Simple      ,
        ret = redis_data_type_double(sess, start, end);
        break;
    case REDIS_DATA_TYPE_BIG_NUMBERS:         //RESP3  Simple      (
        ret = redis_data_type_big_number(sess, start, end);
        break;
    case REDIS_DATA_TYPE_BULK_ERRORS:         //RESP3  Aggregate   !
        sess.is_error = true;
        ret = redis_data_type_bulk_error(sess, start, end);
        break;
    case REDIS_DATA_TYPE_VERBATIM_STRINGS:    //RESP3  Aggregate   =
        ret = redis_data_type_verbatim_string(sess, start, end);
        break;
    case REDIS_DATA_TYPE_MAPS:                //RESP3  Aggregate   %
        ret = redis_data_type_map(sess, start, end);
        break;
    case REDIS_DATA_TYPE_SETS:                //RESP3  Aggregate   ~
        ret = redis_data_type_set(sess, start, end);
        break;
    case REDIS_DATA_TYPE_PUSHES:              //RESP3  Aggregate   >
        ret = redis_data_type_push(sess, start, end);
        break;
    default:
        audit_debug_err("unknown data type: %d", type);
        *start = end; /* stop loop */
        return "unknown";
        break;
    }

    audit_debug_pkg("Type: [%c][%s] %s", type, redis_data_type_name(type), ret.c_str());

    return ret;
}

