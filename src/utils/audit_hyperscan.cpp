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


#include <hs/hs.h> //hyperscan

#include "audit_debug.hpp"
#include "audit_hyperscan.hpp"

/*****************************************************************************/

using whs_map_t = std::map<unsigned int, const audit_hs_data_t*>;

/*****************************************************************************/

/* handler */
struct audit_hs_hdl_t {
    hs_database_t* db;
    hs_scratch_t*  scratch;
    whs_map_t      info;
};

struct audit_hs_match_t {
    unsigned int id;
#ifdef _HS_DETAIL_MATCH
    unsigned long long from;
    unsigned long long to;
    unsigned int flags;
#endif
};

/* ------------------------------------------------------------------------------------------ */

/** the match event callback function 
 * Return: 
 *    Non-zero: the matching should cease
      zero   : the matching should go on
*/
static int eventHandler(unsigned int id,
                 unsigned long long from,
                 unsigned long long to,
                 unsigned int flags,
                 void *ctx) 
{
    if likely(ctx != nullptr) {
        audit_hs_match_t* match = (audit_hs_match_t*)ctx;
        match->id    = id;
#ifdef _HS_DETAIL_MATCH
        match->from  = from;
        match->to    = to;
        match->flags = flags;
#endif
    }

    return HS_SCAN_TERMINATED;
}


 bool audit_hs_init(void)
{
    hs_error_t ret;

    /* veritfy arch */
    ret = hs_valid_platform();
    if (ret != HS_SUCCESS) {
        audit_debug_err("This system does not support Hyperscan");
        return false;
    }

    return true;
}

bool audit_hs_block_compile(audit_hs_hdl_t* handle, const audit_hs_data_t* tbl, size_t count)
{
    hs_error_t ret;
    hs_compile_error_t* compile_err;

    if (!tbl || !count) {
        audit_debug_err("Invalid Paramters");
        return false;
    }

    whs_map_t& map = handle->info;

    std::unique_ptr<const char*[]>experssions_buf = std::make_unique<const char*[]>(count);
    const char** experssions  = experssions_buf.get();

    std::unique_ptr<unsigned int[]>flags_buf = std::make_unique<unsigned int[]>(count);
    unsigned int* flags = flags_buf.get();

    std::unique_ptr<unsigned int[]>ids_buf = std::make_unique<unsigned int[]>(count);
    unsigned int* ids = ids_buf.get();

    for (size_t i = 0; i < count; i++) {
        const audit_hs_data_t* statement = &tbl[i];
        map.insert({statement->id, statement});
        experssions[i] = statement->pattern;
        flags[i] = HS_FLAG_CASELESS | HS_FLAG_DOTALL | HS_FLAG_SINGLEMATCH;
        ids[i] = statement->id;
    }

    ret = hs_compile_ext_multi(experssions, flags, ids, nullptr, count,
                        HS_MODE_BLOCK, nullptr, &handle->db, &compile_err);
    if (ret != HS_SUCCESS) {
        audit_debug_err("hs_compile_ext_multi() failed: %s", compile_err->message);
        hs_free_compile_error(compile_err);
        return false;
    }

    ret = hs_alloc_scratch(handle->db, &handle->scratch);
    if (ret != HS_SUCCESS) {
        audit_debug_err("hs_alloc_scratch: %d", ret);
        hs_free_database(handle->db);
        handle->db = nullptr;
        return false;
    }

    return true;
}


audit_hs_hdl_t* audit_hs_block_create(void)
{
    audit_hs_hdl_t *handle = nullptr;

    try {
        handle = new audit_hs_hdl_t();
    } catch (std::exception &ex) {
        audit_debug_err("whs_block_create failed, %s", ex.what());
        return nullptr;
    }

    return handle;
}


const audit_hs_data_t* audit_hs_block_scan(audit_hs_hdl_t* handle, const char *data,  unsigned int len)
{
    hs_error_t  ret;
    audit_hs_match_t match;

    if (!handle || !data) {
        return nullptr;
    }

    ret = hs_scan(handle->db, data, len, 0, handle->scratch, eventHandler, &match);
    if (likely(HS_SUCCESS == ret)) {
        return nullptr;
    }
 
    if likely(HS_SCAN_TERMINATED == ret) {
        audit_debug_pkg("HS MATCH ID: %u", match.id);
        auto search = handle->info.find(match.id);
        if (search != handle->info.end()) {
            return search->second;
        }

        audit_debug_err("audit_hs_data_t not found");
        return nullptr;
    }

    audit_debug_err("hs_scan() return %d", ret);
    return nullptr;
}


void audit_hs_block_free(audit_hs_hdl_t* handle)
{
    hs_error_t  ret;

    if (NULL == handle) {
        audit_debug_err("handle is null");
        return;
    }

    if (handle->scratch) {
        ret = hs_free_scratch(handle->scratch);
        if (ret != HS_SUCCESS) {
            audit_debug_err("hs_free_scratch() return %d", ret);
        }
        handle->scratch = nullptr;
    }


    if (handle->db) {
        ret = hs_free_database(handle->db);
        if (ret != HS_SUCCESS) {
            audit_debug_err("hs_free_database() return %d", ret);
        }
        handle->db = nullptr;
    }

    delete handle;
}


