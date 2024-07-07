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

#include "audit_debug.hpp"

using namespace std;

/*****************************************************************************/

audit_debug_level_t g_audit_debug_level = AUDIT_DBG_LVL_PKG;

/*****************************************************************************/

static const char* g_debug_level_tbl[] = {
    "ERROR_",
    "WARN__",
    "INFO__",
    "DEBUG_",
    "PACKET",
};

/*****************************************************************************/

void audit_debug_log(audit_debug_level_t level, const char* format, ...)
{
    va_list valist;
    char buffer[4096] = {0};

    va_start(valist, format);
    vsnprintf(buffer, 4095, format, valist);
    va_end(valist);

    time_t    timestamp;
    struct tm local_tm;
    time(&timestamp);
    localtime_r(&timestamp, &local_tm);
    printf("[%d%02d%02d %02d:%02d:%02d][%s]%s\n",            \
        1900 + local_tm.tm_year, local_tm.tm_mon+1, local_tm.tm_mday, \
        local_tm.tm_hour, local_tm.tm_min, local_tm.tm_sec,  \
        g_debug_level_tbl[level], buffer);
}

void audit_debug_init(audit_debug_level_t level)
{
    static bool is_called = false;

    if (is_called) {
        audit_debug_log(AUDIT_DBG_LVL_WARN, "audit_debug_init() was called multiple times");
    } else {
        is_called = true;
    }

    if (level < AUDIT_DBG_LVL_ERR) {
        level = AUDIT_DBG_LVL_ERR;
    }

    if (level > AUDIT_DBG_LVL_PKG) {
        level = AUDIT_DBG_LVL_PKG;
    }

    g_audit_debug_level = level;
    audit_debug_log(AUDIT_DBG_LVL_INFO, "Debug LeveL : %s", g_debug_level_tbl[level]);
}

void audit_debug_byte_array(uint8_t* start, size_t size, const char* format, ...)
{
    TEST_AUDIT_DEBUG_LEVEL_PKG

    /* format part */
    va_list valist;
    char buffer[1024] = {0};
    va_start(valist, format);
    vsnprintf(buffer, 1023, format, valist);
    va_end(valist);

    /* bytes part */
    std::ostringstream oss;
    if (size != 0) {
        size_t new_size = std::min(size, (size_t)1024);
        for (size_t i = 0; i < new_size; i++) {
            oss << hex << setfill('0') << setw(2) << (uint32_t)start[i];
        }
    }
    audit_str_t hexstr = oss.str();

    audit_debug_log(AUDIT_DBG_LVL_PKG, "%s, bytes[%u]:%s", buffer, size, hexstr.c_str());

}

void audit_debug_byte_array(audit_bytes_t& bytes, const char* format, ...)
{
    TEST_AUDIT_DEBUG_LEVEL_PKG

    /* format part */
    va_list valist;
    char buffer[1024] = {0};
    va_start(valist, format);
    vsnprintf(buffer, 1023, format, valist);
    va_end(valist);

    /* bytes part */
    size_t size = bytes.size();
    std::ostringstream oss;
    if (size != 0) {
        for (const auto& it : bytes) {
            oss << hex << setfill('0') << setw(2) << (uint32_t)it;
        }
    }
    audit_str_t hexstr = oss.str();

    audit_debug_log(AUDIT_DBG_LVL_PKG, "%s, bytes[%u]:%s", buffer, size, hexstr.c_str());
}

void audit_debug_byte_dump(audit_bytes_t& bytes, const char* format, ...)
{
    TEST_AUDIT_DEBUG_LEVEL_PKG

    static const char printable_ascii_tbl[] = {
    /*0   1    2    3    4    5    6    7    8    9    a    b    c    d    e    f */
    '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', /* 0x00-0x0F */
    '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', /* 0x10-0x1F */
    ' ', '!', '"', '#', '$', '%', '&', '\'','(', ')', '*', '+', ',', '-', '.', '/', /* 0x20-0x2F */
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', /* 0x30-0x3F */
    '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', /* 0x40-0x4F */
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\',']', '^', '_', /* 0x50-0x5F */
    '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', /* 0x60-0x6F */
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~', '.', /* 0x70-0x7F */
    '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', /* 0x80-0x8F */
    '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', /* 0x90-0x9F */
    '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', /* 0xA0-0xAF */
    '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', /* 0xB0-0xBF */
    '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', /* 0xC0-0xCF */
    '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', /* 0xD0-0xDF */
    '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', /* 0xE0-0xEF */
    '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', /* 0xF0-0xFF */
    };

    /* format part */
    va_list valist;
    char buffer[1024] = {0};
    va_start(valist, format);
    vsnprintf(buffer, 1023, format, valist);
    va_end(valist);

    /* bytes part */
    std::ostringstream oss;
    uint32_t counter = 0;
    uint32_t AUDIT_PRINT_BYTE_BY_LINE = 16;
    char ascii_tbl[AUDIT_PRINT_BYTE_BY_LINE];

    oss << "  ";
    for (size_t i = 0; i < bytes.size(); i++) {
        uint8_t byte = bytes[i];
        ascii_tbl[counter++] = printable_ascii_tbl[byte];
        oss << std::hex << setfill('0') << setw(2) << (uint32_t)byte << " ";
        if (counter % AUDIT_PRINT_BYTE_BY_LINE == 0) {
            counter = 0;
            oss << "   ";
            for (uint32_t j = 0; j < AUDIT_PRINT_BYTE_BY_LINE; j++) {
                oss << ascii_tbl[j];
            }
            oss << endl << "  ";
        }
    }

    if (counter != 0) {/* fill space */
        for (auto k = counter; k < AUDIT_PRINT_BYTE_BY_LINE; k++) {
            oss << "   ";
       }
        oss << "   ";
        for (uint32_t m = 0; m < counter; m++) {
            oss << ascii_tbl[m];
       }
       oss << endl;
    }

    audit_str_t hexstr = oss.str();
    audit_debug_log(AUDIT_DBG_LVL_PKG, "%s, bytes[%u]:\n%s", buffer, bytes.size(), hexstr.c_str());
}


void audit_debug_free(void)
{
    return;
}

/*****************************************************************************/

