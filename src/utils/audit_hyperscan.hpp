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


#ifndef __AUDIT_HYPERSCAN_HPP__
#define __AUDIT_HYPERSCAN_HPP__
/*****************************************************************************/

#include <stddef.h> /* size_t */

/*****************************************************************************/

struct audit_hs_data_t {
    unsigned int id;
    const char*  pattern;
    const char*  category;
    unsigned int cgy_id;
    const char*  description;
};

struct audit_hs_hdl_t;

/*****************************************************************************/

bool audit_hs_init(void);

audit_hs_hdl_t* audit_hs_block_create(void);

bool audit_hs_block_compile(audit_hs_hdl_t* handle, const audit_hs_data_t* tbl, size_t size);

const audit_hs_data_t* audit_hs_block_scan(audit_hs_hdl_t* handle, const char *data,  unsigned int len);

void audit_hs_block_free(audit_hs_hdl_t* handle);

/*****************************************************************************/
#endif /* __AUDIT_HYPERSCAN_HPP__ */


