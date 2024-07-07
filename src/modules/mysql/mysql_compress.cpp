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


#include <zlib.h>
#include <zstd.h>

#include "mysql_utils.hpp"
#include "mysql_debug.hpp"
#include "mysql_compress.hpp"

/*****************************************************************************/

#define mysql_get_uncompress_mgt(_sess) (_sess.data_dir == MYSQL_DATA_DIR_C2S ? _sess.client_uncompress_mgt : _sess.server_uncompress_mgt)

/*****************************************************************************/

/* zlib COMPRESS
 *
 * trigger command: 
 *  mysql -C 
 *
 * int uncompress(Bytef * dest, uLongf * destLen, const Bytef * source, uLong sourceLen);
 */
static bool mysql_uncompress_zlib(uint8_t* dest, size_t dest_len, uint8_t* src, size_t src_len)
{
    uint64_t func_uncompress_len = dest_len;
    int ret = uncompress((Bytef*)dest, &func_uncompress_len, (Bytef*)src, src_len);
    /* uncompress returns Z_OK if success, 
     * Z_MEM_ERROR if there was not enough memory, 
     * Z_BUF_ERROR if there was not enough room in the output buffer, 
     * Z_DATA_ERROR if the input data was corrupted or incomplete. 
     */
    if (ret != Z_OK) {
        audit_debug_err("zlib uncompress failed, %d", ret);
        return false;
    }

    if (func_uncompress_len != dest_len) {
        audit_debug_err("zlib uncompress short than expected(%d/%d)", ret, dest_len);
        return false;
    }

    return true;

}


/* zstd COMPRESS
 *
 * trigger command: 
 *  (>= 8.0.18) mysql --compression-algorithms=zstd
 *
 * size_t ZSTD_decompress( void* dst, size_t dstCapacity, const void* src, size_t compressedSize);
 */
static bool mysql_uncompress_zstd(uint8_t* dest, size_t dest_len, uint8_t* src, size_t src_len)
{
    size_t ret = ZSTD_decompress(dest, dest_len, src, src_len);
    if (ret != dest_len) {
        if (ZSTD_isError(ret)) {
            audit_debug_err("zstd uncompress failed, %s", ZSTD_getErrorName(ret));
        } else {
            audit_debug_err("zstd uncompress short than expected(%d/%lu)", ret, dest_len);
        }
        return false;
    }

    return true;
}


bool mysql_uncompress_packet(mysql_sess_t& sess, mysql_packet_t* packet)
{

    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;

    uint32_t uncompress_len = audit_data_get_uint24(&start, end);
    uint32_t compress_len   = packet->payload_length;

    mysql_uncompress_mgt_t& mgt = mysql_get_uncompress_mgt(sess);
    size_t remain_size = mgt.buff.size();

    audit_debug_dbg("[DIR:%d]compress-len:%5u, uncompress-len:%5u, remain-size: %5zd", sess.data_dir, compress_len, uncompress_len, remain_size);

    bool ret = false;

    if (uncompress_len == 0) {
        if (remain_size != 0) {
            std::copy(start, start + compress_len,  std::back_inserter(mgt.buff));
            mgt.buf_len += compress_len;
            mgt.buf_ptr = mgt.buff.data();
        } else {
            mgt.buf_ptr = start;
            mgt.buf_len = compress_len;
        }
        mgt.buf_pos = 0;
        return true;
    }

    mgt.buff.resize(remain_size + uncompress_len);
    uint8_t* dest = mgt.buff.data() + remain_size;

    switch (sess.compress_type) {
    case MYSQL_COMPRESS_ZLIB:
        ret = mysql_uncompress_zlib(dest, uncompress_len, start, compress_len);
        break;

    case MYSQL_COMPRESS_ZSTD:
        ret = mysql_uncompress_zstd(dest, uncompress_len, start, compress_len);
        break;

    default:
        break;
    }

    if (false == ret) {
        mgt.buff.clear();
        mgt.buf_len = 0;
        mgt.buf_ptr = nullptr;
    } else {
        mgt.buf_pos = 0;
        mgt.buf_len = remain_size + uncompress_len;
        mgt.buf_ptr = mgt.buff.data();
    }

    return ret;
}


static void mysql_uncompress_data_remain_proc(mysql_uncompress_mgt_t& mgt, uint32_t remain_size)
{
    audit_bytes_t& buff = mgt.buff;

    mgt.packet_index = 0;
    mgt.packet_seqid = 0;

    if (remain_size == 0) {
        buff.clear();
        return;
    }

    if (buff.empty()) {/* data for next packet */
        uint8_t* new_start = mgt.buf_ptr + mgt.buf_pos;
        std::copy(new_start, new_start + remain_size, std::back_inserter(buff));
    } else {/* delete the data used */
         buff.erase(buff.begin(), buff.begin() + mgt.buf_pos);
    }
}


mysql_packet_t* mysql_uncompress_get_packet(mysql_sess_t& sess)
{
    mysql_uncompress_mgt_t& mgt = mysql_get_uncompress_mgt(sess);

    uint32_t buf_remain = mgt.buf_len - mgt.buf_pos;
    audit_debug_dbg("buff data size = %u", buf_remain);

    if (buf_remain < 4) {
        mysql_uncompress_data_remain_proc(mgt, buf_remain);
        return nullptr;
    }

    mysql_packet_t* packet = (mysql_packet_t*)(mgt.buf_ptr + mgt.buf_pos);
    if ((mgt.packet_seqid != 0) && (packet->sequence_id != 0)) {
        if (packet->sequence_id != (mgt.packet_seqid + 1)) {
            audit_debug_err("packet out of order, index:%u, seqid:%u(last %u), payload-len:%u",  \
            mgt.packet_index, \
            packet->sequence_id, \
            mgt.packet_seqid, \
            packet->payload_length);
            mysql_uncompress_data_remain_proc(mgt, 0);
            return nullptr;
        }
    }
    mgt.packet_seqid = packet->sequence_id;

    if (packet->payload_length > buf_remain) {
        mysql_uncompress_data_remain_proc(mgt, buf_remain);
        return nullptr;
    }

    audit_debug_dbg("[next packet]index:%u, payload-len:%u, seqid:%u", mgt.packet_index, packet->payload_length, packet->sequence_id);

    mgt.buf_pos += sizeof(mysql_packet_t) + packet->payload_length; /* next packet offset */
    ++mgt.packet_index;

    return packet;
}

/*****************************************************************************/

