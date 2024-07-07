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
#include <audit_debug.hpp>

#include "tls_debug.hpp"
#include "tls_internal.hpp"

/*****************************************************************************/

bool tls_decrypt_with_private_key(tls_bytes_t& enc, tls_bytes_t& dec);
bool tls_generate_keyring_material(tls_sess_t& sess);
bool tls_session_hash(tls_sess_t& sess);
bool tls_finished_msg_verify(tls_sess_t& sess, audit_str_t& lable, audit_bytes_t& data);
bool tls_handshake_messages_push(tls_sess_t& sess, uint8_t type, uint8_t* start, uint8_t* end);

/*****************************************************************************/

/* When this message will be sent:
 * When a client first connects to a server, it is required to send the ClientHello as its first message. 
 * The client can also send a ClientHello in response to a HelloRequest 
 * or on its own initiative in order to renegotiate the security parameters in an existing connection.
 *
 * struct {
 *    ProtocolVersion client_version;
 *    Random random;
 *    SessionID session_id;
 *    CipherSuite cipher_suites<2..2^16-2>;
 *    CompressionMethod compression_methods<1..2^8-1>;
 *    select (extensions_present) {
 *        case false:
 *           struct {};
 *        case true:
 *            Extension extensions<0..2^16-1>;
 *    };
 * } ClientHello;
 */
bool tls_handshake_client_hello(tls_sess_t& sess, uint8_t* start, uint8_t* end)
{
    ClientHello hello = {};

    hello.version = audit_data_get_uint16_be(&start, end);

    audit_data_get_bytes(&start, end, sess.paramters.client_random, 32);

    hello.session_id_length = audit_data_get_uint8(&start, end);
    if (hello.session_id_length) {
        audit_data_get_bytes(&start, end, sess.session_id, hello.session_id_length);
    }

    /* cipher suites */
    hello.cipher_suites_length = audit_data_get_uint16_be(&start, end);
#ifdef _TLS_DETAIL_INFO
    for (uint16_t i = 0; i < hello.cipher_suites_length / 2; i++) {
        uint16_t cipher = audit_data_get_uint16_be(&start, end);
        hello.cipher_suites_data.push_back(cipher);
    }
#else  /* _TLS_DETAIL_INFO */
    audit_data_skip_bytes(&start, end, hello.cipher_suites_length);
#endif /* _TLS_DETAIL_INFO */

    /* compression methods */
    hello.compression_methods_length = audit_data_get_uint8(&start, end);
#ifdef _TLS_DETAIL_INFO
    for (uint8_t i = 0; i < hello.compression_methods_length; i++) {
        uint8_t method = audit_data_get_uint8(&start, end);
        hello.compression_methods_data.push_back(method);
    }
#else  /* _TLS_DETAIL_INFO */
    audit_data_skip_bytes(&start, end, hello.compression_methods_length);
#endif /* _TLS_DETAIL_INFO */

    if (audit_data_get_remain_length(&start, end) < 2) {/* no extensions */
        return true;
    }

    hello.extensions_length = audit_data_get_uint16_be(&start, end);
    while (start < end) {
        uint16_t type   = audit_data_get_uint16_be(&start, end);
        uint16_t length = audit_data_get_uint16_be(&start, end);
        switch (type) {
        case encrypt_then_mac:
            sess.client_encrypt_then_mac = true;
            audit_debug_dbg("ClientHello support encrypt_then_mac");
            break;
        case session_ticket:
            audit_data_get_bytes(&start, end, sess.session_ticket, length);
            break;
        case extended_master_secret:
            sess.client_extended_master_secret = true;
            audit_debug_dbg("ClientHello support extended_master_secret");
            break;
        default: /* ignore */
            audit_data_skip_bytes(&start, end, length);
        }
    }

    return true;
}


/* When this message will be sent:
 * This message is always sent by the client.  It MUST immediately follow the client certificate message, if it is sent.  
 * Otherwise, it MUST be the first message sent by the client after it receives the ServerHelloDone message.
 *
 * struct {
 *   select (KeyExchangeAlgorithm) {
 *      case rsa:    --------------------------- only support RSA KeyExchangeAlgorithm
 *          EncryptedPreMasterSecret;
 *      case dhe_dss:
 *      case dhe_rsa:
 *      case dh_dss:
 *      case dh_rsa:
 *      case dh_anon:
 *          ClientDiffieHellmanPublic;
 *    } exchange_keys;
 * } ClientKeyExchange;
 */
static bool tls_handshake_client_key_exchange(tls_sess_t& sess, uint8_t* start, uint8_t* end)
{
    uint32_t premaster_length = audit_data_get_uint16_be(&start, end);

    tls_bytes_t encrypt_pre_master_secure = {};
    audit_data_get_bytes(&start, end, encrypt_pre_master_secure, premaster_length);

    /* decrypt pre_master_secure */
    bool ret = tls_decrypt_with_private_key(encrypt_pre_master_secure, sess.pre_master_secure);
    if (!ret) {
        return false;
    }

    /* calc all keys */
    ret = tls_generate_keyring_material(sess);
    if (!ret) {
        return false;
    }

    return true;
}


/* When this message will be sent:
 * This is the first message the client can send after receiving a ServerHelloDone message. 
 * This message is only sent if the server requests a certificate.  
 * If no suitable certificate is available, the client MUST send a certificate message containing no certificates.  
 * That is, the certificate_list structure has a length of zero.  
 * If the client does not send any certificates, the server MAY at its discretion either continue the handshake without client authentication, 
 * or respond with a fatal handshake_failure alert. 
 * Also, if some aspect of the certificate chain was unacceptable (e.g., it was not signed by a known, trusted CA), 
 * the server MAY at its discretion either continue the handshake(considering the client unauthenticated) or send a fatal alert.
* 
 * opaque ASN.1Cert<1..2^24-1>;
 * struct {
 *     ASN.1Cert certificate_list<0..2^24-1>;
 * } Certificate;
 */
static bool tls_handshake_certificate(tls_sess_t& sess, uint8_t* start, uint8_t* end)
{
    return true;
}


/* This message is used to provide explicit verification of a client certificate.
 * This message is only sent following a client certificate that has signing capability 
 * (i.e., all certificates except those containing fixed Diffie-Hellman parameters). 
 * When sent, it MUST immediately follow the client key exchange message.
 *
 * struct {
 *    digitally-signed struct {
 *        opaque handshake_messages[handshake_messages_length];
 *    }
 * } CertificateVerify;
 */
static bool tls_handshake_certificate_verify(tls_sess_t& sess, uint8_t* start, uint8_t* end)
{
    return true;
}


/* When this message will be sent:
 * A Finished message is always sent immediately after a change cipher spec message to verify that 
 * the key exchange and authentication processes were successful. 
 * It is essential that a change cipher spec message be received between the other handshake messages and the Finished message.
 *
 * The Finished message is the first one protected with the just negotiated algorithms, keys, and secrets.  
 * Recipients of Finished messages MUST verify that the contents are correct.  
 * Once a side has sent its Finished message and received and validated the Finished message from its peer, 
 * it may begin to send and receive application data over the connection.
 *
 * struct {
 *     opaque verify_data[verify_data_length];
 * } Finished;
 *
 * verify_data
 *  PRF(master_secret, finished_label, Hash(handshake_messages))
 *     [0..verify_data_length-1];
 *
 * finished_label
 *  For Finished messages sent by the client, the string "client finished".  
 *  For Finished messages sent by the server, the string "server finished".
 *
 * handshake_messages
 *  All of the data from all messages in this handshake (not including any HelloRequest messages) up to, but not including, this message.  
 *  This is only data visible at the handshake layer and does not include record layer headers.  
 *  This is the concatenation of all the Handshake structures as defined in Section 7.4, exchanged thus far.
 */
static bool tls_handshake_finished(tls_sess_t& sess, uint8_t* start, uint8_t* end)
{
    audit_bytes_t verify_data(start, end); 
    audit_debug_byte_array(verify_data, "client finished verify_data");
    audit_str_t finished_label("client finished");
    return tls_finished_msg_verify(sess, finished_label, verify_data);
}


bool tls_record_handshake_client(tls_sess_t& sess, tls_record_header_t& record)
{
    uint8_t* start = record.payload;
    uint8_t* end   = start + record.length;

    tls_bytes_t decrypted_record = {};

    bool ret = true;

    if (sess.client_change_cipher_spec_sent) { //Encrypted Handshake Message
        audit_debug_dbg("Encrypted Client Handshake Message");
        bool ok = sess.client_decorder.decrypt(record, decrypted_record);
        if (!ok) {
            return false;
        }
        start = decrypted_record.data();
        end   = start + decrypted_record.size();
    }

    while (start < end) { /* one record may contain multipe handshake msg */
        uint8_t* msg_start = start;
        uint8_t  msg_type  = audit_data_get_uint8(&start, end);
        uint32_t length    = audit_data_get_uint24_be(&start, end);
        uint8_t* msg_end   = start + length; // = msg_start + length + 4;
        uint32_t left_size = end - start;

        audit_debug_dbg("<Handshake: %s> length: %lu", tls_info_handshake_type(msg_type), length);
        tls_handshake_messages_push(sess, msg_type, msg_start, msg_end);

        if (length > record.length) {
            audit_debug_err("handshake msg spec length:%u, but only %u left", length, left_size);
            return false;
        }

        switch(msg_type) {
        case client_hello:
            ret = tls_handshake_client_hello(sess, start, end);
            break;

        case certificate: /* client sent certificate to server */
            ret = tls_handshake_certificate(sess, start, end);
            break;

        case client_key_exchange:
            ret = tls_handshake_client_key_exchange(sess, start, end);
            break;

        case certificate_verify:
            ret = tls_handshake_certificate_verify(sess, start, end);
            break;

        case finished:
            ret = tls_handshake_finished(sess, start, end);
            break;

        default:
            audit_debug_dbg("<unknown> msg_type:%d", msg_type);
            break;
        }

        if (!ret) {
            return false;
        }

        start += length;
    }

    return ret;
}

/*****************************************************************************/

bool tls_record_application_data_client(tls_sess_t& sess, tls_record_header_t& record)
{
    tls_bytes_t dec = {};

    bool ok = sess.client_decorder.decrypt(record, dec);
    if (ok) {
        tls_bytes_t& payload = sess.ssl_client_payload;
        payload.insert(payload.end(), dec.begin(), dec.end());
        return true;
    }

    return false;
}

/*****************************************************************************/

bool tls_record_change_cipher_spec_client(tls_sess_t& sess, tls_record_header_t& record)
{

    sess.client_change_cipher_spec_sent = true;

    return true;
}

/*****************************************************************************/

bool tls_record_alert_client(tls_sess_t& sess, tls_record_header_t& record)
{
    return true;
}

/*****************************************************************************/

