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


#ifndef __AUDIT_DEBUG_H__
#define __AUDIT_DEBUG_H__

/*****************************************************************************/

#include "audit_types.hpp"

/*****************************************************************************/

enum audit_debug_level_t {
    AUDIT_DBG_LVL_ERR,
    AUDIT_DBG_LVL_WARN,
    AUDIT_DBG_LVL_INFO,
    AUDIT_DBG_LVL_DBG,
    AUDIT_DBG_LVL_PKG,  /* packet detail */
};

extern audit_debug_level_t g_audit_debug_level;

void audit_debug_init(audit_debug_level_t level);
void audit_debug_log(audit_debug_level_t level, const char* format, ...);
void audit_debug_free(void);

/* print hex string (packet level) */
void audit_debug_byte_array(audit_bytes_t& bytes, const char* format, ...);
void audit_debug_byte_array(uint8_t* start, size_t size, const char* format, ...);
void audit_debug_byte_dump(audit_bytes_t& bytes, const char* format, ...);

/*****************************************************************************/

/* User should call these utils */

#define audit_debug_info(fmt, ...) if (g_audit_debug_level >= AUDIT_DBG_LVL_INFO) audit_debug_log(AUDIT_DBG_LVL_INFO, "[%s:%d]" fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define audit_debug_warn(fmt, ...) if (g_audit_debug_level >= AUDIT_DBG_LVL_WARN) audit_debug_log(AUDIT_DBG_LVL_WARN, "[%s:%d]" fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define audit_debug_err(fmt,  ...) if (g_audit_debug_level >= AUDIT_DBG_LVL_ERR)  audit_debug_log(AUDIT_DBG_LVL_ERR,  "[%s:%d]" fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define audit_debug_dbg(fmt,  ...) if (g_audit_debug_level >= AUDIT_DBG_LVL_DBG)  audit_debug_log(AUDIT_DBG_LVL_DBG,  "[%s:%d]" fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define audit_debug_pkg(fmt,  ...) if (g_audit_debug_level >= AUDIT_DBG_LVL_PKG)  audit_debug_log(AUDIT_DBG_LVL_PKG,  "[%s:%d]" fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define TEST_AUDIT_DEBUG_LEVEL_ERR    if (g_audit_debug_level < AUDIT_DBG_LVL_ERR)  {return;}
#define TEST_AUDIT_DEBUG_LEVEL_WARN   if (g_audit_debug_level < AUDIT_DBG_LVL_WARN) {return;}
#define TEST_AUDIT_DEBUG_LEVEL_INFO   if (g_audit_debug_level < AUDIT_DBG_LVL_INFO) {return;}
#define TEST_AUDIT_DEBUG_LEVEL_DBG    if (g_audit_debug_level < AUDIT_DBG_LVL_DBG)  {return;}
#define TEST_AUDIT_DEBUG_LEVEL_PKG    if (g_audit_debug_level < AUDIT_DBG_LVL_PKG)  {return;}

/*****************************************************************************/
#endif /* __AUDIT_DEBUG_H__ */

