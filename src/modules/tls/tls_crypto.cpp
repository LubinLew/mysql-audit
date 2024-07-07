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


#include "audit_debug.hpp"
#include "tls_crypto.hpp"

#include <gcrypt.h>
#include <memory>
/*****************************************************************************/

struct tls_hmac_mgr_t {
    gcry_mac_hd_t md;
    int           algo;
    const char*   name; /* algo name */
};

struct tls_md_mgr_t {
    gcry_md_hd_t md;
    int          algo;
    const char*   name; /* algo name */
};

/*****************************************************************************/
void tls_crypto_init(void)
{
    auto version = gcry_check_version(nullptr);
    audit_debug_info("gcrypt version: %s", version);
}




tls_hmac_mgr_t* tls_hmac_init(int algo)
{
    tls_hmac_mgr_t* mgr = new tls_hmac_mgr_t();
    mgr->algo = algo;
    mgr->name = gcry_mac_algo_name(algo);

//    audit_debug_dbg("%s", mgr->name);

    gcry_error_t err = gcry_mac_open(&mgr->md, algo, 0, nullptr);
    if (err) {
        delete mgr;
        audit_debug_err("gcry_mac_open(%s) failed, %s", mgr->name, gcry_strerror(err));
        return nullptr;
    }

    return mgr;
}


bool tls_hmac_setkey(tls_hmac_mgr_t* mgr, audit_bytes_t& data)
{
    gcry_error_t err = gcry_mac_setkey(mgr->md, data.data(), data.size());
    if (err) {
        audit_debug_err("gcry_mac_setkey(%s) failed, %s", mgr->name, gcry_strerror(err));
        return false;
    }

    return true;
}


void tls_hmac_reset(tls_hmac_mgr_t* mgr)
{
    gcry_mac_reset(mgr->md);
}


void tls_hmac_update(tls_hmac_mgr_t* mgr, audit_bytes_t& data)
{
    gcry_mac_write(mgr->md, data.data(), data.size());
}


bool tls_hmac_final(tls_hmac_mgr_t* mgr, audit_bytes_t& result)
{
    size_t length = gcry_mac_get_algo_maclen(mgr->algo);

    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(length);
    uint8_t* buff = buffer.get();
    gcry_error_t err = gcry_mac_read(mgr->md, buff, &length);
    if (err) {
        audit_debug_err("gcry_mac_read(%s) failed, %s", mgr->name, gcry_strerror(err));
        return false;
    }

    result.assign(buff, buff + length);

    return true;
}


void tls_hmac_cleanup(tls_hmac_mgr_t* mgr)
{
    if (mgr) {
        gcry_mac_close(mgr->md);
        delete mgr;
    }
}

/*****************************************************************************/

tls_md_mgr_t* tls_md_init(int algo)
{
    struct hash_trans_t {
      int mac_algo;
      int md_algo;
   };

    static hash_trans_t _tbl[] = {
        {GCRY_MAC_HMAC_MD5,    GCRY_MD_MD5   },
        {GCRY_MAC_HMAC_SHA1,   GCRY_MD_SHA1  },
        {GCRY_MAC_HMAC_SM3,    GCRY_MD_SM3   },
        {GCRY_MAC_HMAC_SHA256, GCRY_MD_SHA256},
        {GCRY_MAC_HMAC_SHA384, GCRY_MD_SHA384}
    };

    for (const auto& it : _tbl) {
        if (it.mac_algo == algo) {
            algo = it.md_algo;
            break;
        }
    }

    tls_md_mgr_t* mgr = new tls_md_mgr_t();
    mgr->algo = algo;
    mgr->name = gcry_md_algo_name(algo);
    if ((nullptr == mgr->name) || (mgr->name[0] == '?')) {
        audit_debug_err("invalid algo : %d", algo);
        return nullptr;
    }

//    audit_debug_dbg("%s", mgr->name);

    gcry_error_t err = gcry_md_open(&mgr->md, algo, 0);
    if (err) {
        delete mgr;
         audit_debug_err("gcry_md_open(%s) failed, %s", mgr->name, gcry_strerror(err));
        return nullptr;
    }

    return mgr;
}

void tls_md_update(tls_md_mgr_t* mgr, tls_bytes_t& data)
{
    gcry_md_write(mgr->md, data.data(), data.size());
}

void tls_md_final(tls_md_mgr_t* mgr, tls_bytes_t& result)
{
    int len = gcry_md_get_algo_dlen(mgr->algo);
    uint8_t* data = gcry_md_read(mgr->md, mgr->algo);
    result.assign(data, data + len);
}

void tls_md_reset(tls_md_mgr_t* mgr)
{
    gcry_md_reset(mgr->md);
}

void tls_md_cleanup(tls_md_mgr_t* mgr)
{
    gcry_md_close(mgr->md);
}

/*****************************************************************************/


