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


#include <gcrypt.h>

#include <audit_debug.hpp>

#include "tls_prf.hpp"
#include "tls_crypto.hpp"
/*****************************************************************************/

/* https://www.ietf.org/rfc/rfc2246.html#section-5

P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
                  HMAC_hash(secret, A(2) + seed) +
                  HMAC_hash(secret, A(3) + seed) + ...
 Where + indicates concatenation.

 A() is defined as:
     A(0) = seed
     A(i) = HMAC_hash(secret, A(i-1))

P_hash can be iterated as many times as is necessary to produce the required quantity of data. 
For example, if P_SHA-1 was being used to create 64 bytes of data, it would have to be iterated 4 time(through A(4)), 
creating 80 bytes of output data; the last 16 bytes of the final iteration would then be discarded, 
leaving 64 bytes of output data.
 */
bool P_hash(int md,             /* HMAC algorithms, MD5, SHA-1 ... */
                tls_bytes_t& secret,
                tls_bytes_t& seed,
                tls_bytes_t& result, /* buf to store HASH */
                size_t hash_len)       /* the HASH length we expect */
{
    tls_hmac_mgr_t* mgr = tls_hmac_init(md);
    if (!mgr) {
        return false;
    }

    tls_bytes_t tmp1 = {}; //sotre A(i)
    tls_bytes_t tmp2 = {}; //store HMAC_hash(secret, A(i) + seed)
    result.clear();

    size_t left = hash_len;

    // A(0) = seed
    tls_bytes_t* Ai  = &seed;

    while (left) {
        /* A(i) = HMAC_hash(secret, A(i-1)) */
        tls_hmac_setkey(mgr, secret);
        tls_hmac_update(mgr, *Ai);
        tls_hmac_final(mgr, tmp1);
        Ai = &tmp1;

        /* HMAC_hash(secret, A(i) + seed) */
        tls_hmac_reset(mgr);
        tls_hmac_setkey(mgr, secret);
        tls_hmac_update(mgr, *Ai);
        tls_hmac_update(mgr, seed);
        tls_hmac_final(mgr, tmp2);
        tls_hmac_reset(mgr);

        /* + */
        size_t tocpy = std::min(left, tmp2.size());
        std::copy(tmp2.begin(), tmp2.begin() + tocpy, std::back_inserter(result));
        left -= tocpy;
    }

    tls_hmac_cleanup(mgr);

    return true;
}


static bool tls_prf(tls_bytes_t&  secure,
                        audit_str_t& usage,
                        tls_bytes_t& rand1,
                        tls_bytes_t& rand2,
                        tls_bytes_t& result,
                        size_t hash_len)
{
    bool ret = false;

    /* seed = usage + rand1 + rand2 */
    tls_bytes_t seed(usage.begin(), usage.end());
    if (!rand1.empty()) {
        seed.insert(seed.end(), rand1.begin(), rand1.end());
    }
    if (!rand2.empty()) {
        seed.insert(seed.end(), rand2.begin(), rand2.end());
    }

    /* S1 and S2 are the two halves of the secret and each is the same length. 
     * S1 is taken from the first half of the secret, S2 from the second half. 
     * Their length is created by rounding up the length of the overall secret divided by two; 
     * thus, if the original secret is an odd number of bytes long, 
     * the last byte of S1 will be the same as the first byte of S2.
     */
    size_t L_S  = secure.size();
    size_t L_S1 = L_S / 2 + L_S % 2; // = L_S2
    tls_bytes_t S1(secure.begin(), secure.begin() + L_S1);
    tls_bytes_t S2(secure.begin() + (L_S - L_S1), secure.end());


    tls_bytes_t md5hash  = {};
    ret = P_hash(GCRY_MAC_HMAC_MD5,  S1, seed, md5hash,  hash_len);
    tls_bytes_t sha1hash = {};
    ret = P_hash(GCRY_MAC_HMAC_SHA1, S2, seed, sha1hash, hash_len);

    result.clear();
    for (size_t i = 0; i < hash_len; i++) {
       result.push_back(md5hash[i] ^ sha1hash[i]);
    }

    return ret;
}


static bool tls12_prf(int md,
                tls_bytes_t& secure,
                audit_str_t& usage,
                tls_bytes_t& rand1,
                tls_bytes_t& rand2,
                tls_bytes_t& result,
                size_t hash_len)
{
    //seed
    tls_bytes_t seed(usage.begin(), usage.end());

    if (!rand1.empty()) {
        seed.insert(seed.end(), rand1.begin(), rand1.end());
    }
    if (!rand2.empty()) {
        seed.insert(seed.end(), rand2.begin(), rand2.end());
    }

    auto ok = P_hash(md, secure, seed, result, hash_len);
    if(ok){
        return true;
    }

    return false;
}


/* out_len is the wanted output length for the pseudorandom function.
 * Ensure that ssl->cipher_suite is set. */
bool prf(tls_sess_t& sess,
         tls_bytes_t& secure,
         audit_str_t& usage,
         tls_bytes_t& rand1,
         tls_bytes_t& rand2,
         tls_bytes_t& result,
         size_t hash_len)
{
    bool ret = true;

    switch (sess.version) {
    case TLS_VER_1_0:
    case TLS_VER_1_1:
         ret = tls_prf(secure, usage, rand1, rand2, result, hash_len);
        break;

    case TLS_VER_1_2:
        ret = tls12_prf(sess.paramters.prf_algorithm, secure, usage, rand1, rand2, result, hash_len);
        break;

    default:
        audit_debug_err("Unsupported Protocol Version %#x", sess.version);
        ret = false;
    }

    return ret;
}

