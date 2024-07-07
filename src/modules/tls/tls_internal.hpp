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


#ifndef __TLS_INTERNAL__
#define __TLS_INTERNAL__
/*****************************************************************************/

#include "tls.hpp"
#include "tls_decoder.hpp"

/*****************************************************************************/

enum tls_version_t {
    SSL_VER_3_0 = 0x0300,
    TLS_VER_1_0 = 0x0301,
    TLS_VER_1_1 = 0x0302,
    TLS_VER_1_2 = 0x0303,
    TLS_VER_1_3 = 0x0304
};

// https://www.rfc-editor.org/rfc/rfc5246#section-6.2.1
enum tls_record_type_t {
    change_cipher_spec = 20, //means subsequent records will be encrypted.
    alert              = 21, //Alert messages convey the severity of the message(warning or fatal) and a description of the alert.
    handshake          = 22,
    application_data   = 23
};

/*****************************************************************************/

// https://www.rfc-editor.org/rfc/rfc5246#section-7.4
enum tls_handshake_type_t {
    hello_request       = 0,
    client_hello        = 1,
    server_hello        = 2,
    new_session_ticket  = 4,
    end_of_early_data   = 5,
    encrypted_extensions =8,
    certificate         = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done   = 14,
    certificate_verify  = 15,
    client_key_exchange = 16,
    finished            = 20,
    certificate_url     = 21, //Extensions, https://www.rfc-editor.org/rfc/rfc3546#section-2.4 
    certificate_status  = 22, //Extensions
    key_update          = 24,
    message_hash        = 254
};

using cipher_arr_t = std::vector<uint16_t>;

// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
enum tls_extension_type_t {
    server_name                                 = 0 ,
    max_fragment_length                         = 1 ,
    client_certificate_url                      = 2 ,
    trusted_ca_keys                             = 3 ,
    truncated_hmac                              = 4 ,
    status_request                              = 5 ,
    user_mapping                                = 6 ,
    client_authz                                = 7 ,
    server_authz                                = 8 ,
    cert_type                                   = 9 ,
    supported_groups                            = 10,
    ec_point_formats                            = 11,
    srp                                         = 12,
    signature_algorithms                        = 13,
    use_srtp                                    = 14,
    heartbeat                                   = 15,
    application_layer_protocol_negotiation      = 16,
    status_request_v2                           = 17,
    signed_certificate_timestamp                = 18,
    client_certificate_type                     = 19,
    server_certificate_type                     = 20,
    padding                                     = 21,
    encrypt_then_mac                            = 22,
    extended_master_secret                      = 23,
    token_binding                               = 24,
    cached_info                                 = 25,
    tls_lts                                     = 26,
    compress_certificate                        = 27,
    record_size_limit                           = 28,
    pwd_protect                                 = 29,
    pwd_clear                                   = 30,
    password_salt                               = 31,
    ticket_pinning                              = 32,
    tls_cert_with_extern_psk                    = 33,
    delegated_credential                        = 34,
    session_ticket                              = 35, //interest
    TLMSP                                       = 36,
    TLMSP_proxying                              = 37,
    TLMSP_delegate                              = 38,
    supported_ekt_ciphers                       = 39,
    pre_shared_key                              = 41,
    early_data                                  = 42,
    supported_versions                          = 43,
    cookie                                      = 44,
    psk_key_exchange_modes                      = 45,
    certificate_authorities                     = 47,
    oid_filters                                 = 48,
    post_handshake_auth                         = 49,
    signature_algorithms_cert                   = 50,
    key_share                                   = 51,
    transparency_info                           = 52,
    connection_id                               = 54,
    external_id_hash                            = 55,
    external_session_id                         = 56,
    quic_transport_parameters                   = 57,
    ticket_request                              = 58,
    dnssec_chain                                = 59,
    sequence_number_encryption_algorithms       = 60
};

// https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.2
struct tls_extension_t {
    uint16_t      type;
    uint16_t      length;
    tls_bytes_t data;
};

using extension_arr_t = std::vector<tls_extension_t>;


struct ClientHello {
    uint16_t      version;

    tls_bytes_t   random_bytes;
 
    uint8_t       session_id_length;
    tls_bytes_t   session_id_data;

    uint16_t      cipher_suites_length;
    cipher_arr_t  cipher_suites_data;

    uint8_t       compression_methods_length;
    tls_bytes_t   compression_methods_data;

    //extensions, https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.4
    uint16_t        extensions_length;
    extension_arr_t extensions_data;
};


struct ServerHello {
    /* This field will contain the lower of that suggested by the client in the client hello and the highest supported by the server. */
    uint16_t      version; 
    tls_bytes_t   random_bytes;
 
    uint8_t       session_id_length;
    tls_bytes_t   session_id_data;

    uint16_t      cipher_suite;
    uint8_t       compression_method;

    //ignore extensions
};

// https://www.rfc-editor.org/rfc/rfc8446#section-4.6.1
struct NewSessionTicket {
    uint32_t    ticket_lifetime;
//    uint32_t      ticket_age_add;

    uint16_t    ticket_length;
    tls_bytes_t ticket_data;

    //ignore extensions
};

/* RFC 5246, section 8.1 says that the master secret is always 48 bytes */
#define TLS_MASTER_SECRET_LENGTH        48

struct tls_cipher_suite_t {
    uint32_t number;

    uint32_t encryption_type;  // data encryption algorithm (symmetric cryptography)
    uint32_t encryption_mode;  // CBC,GCM ...

    uint32_t hmac_type;         // SHA256, SHA385, SM3

    const char* name;          // IANA name
};


struct tls_sess_t {
    uint16_t      version;

    tls_conn_end_t endpoint;

    tls_bytes_t ssl_server_payload; //buff for decrypted app data
    tls_bytes_t ssl_client_payload; //buff for decrypted app data

    bool        client_encrypt_then_mac;
    bool        server_encrypt_then_mac;

    // https://www.ietf.org/rfc/rfc7627.html
    bool        client_extended_master_secret;
    bool        server_extended_master_secret;

    bool        client_change_cipher_spec_sent;
    bool        server_change_cipher_spec_sent;

    tls_bytes_t session_id;
    tls_bytes_t session_ticket;

    tls_bytes_t handshake_message;
    bool        session_hash_finished;
    tls_bytes_t session_hash;
    tls_bytes_t client_handshake_messages_hash; // hash for client finished
    tls_bytes_t server_handshake_messages_hash; // hash for server finished

    tls_bytes_t pre_master_secure;          // decrypted pre_master from ClentKeyExchange messages

    tls_security_parameters_t paramters;

    tls_bytes_t client_write_MAC_key;// This key is used by the server to authenticate data that is sent by the client.
    tls_bytes_t server_write_MAC_key;// The server write MAC key is used by the client to authenticate the data that is sent by the server.
    tls_bytes_t client_write_key;    // This key encrypts data that the client writes.
    tls_bytes_t server_write_key;    // The server write encryption key encrypts the data that the server writes.
    tls_bytes_t client_write_IV_key; // The client write IV key is generated when AEAD is used for encryption and authentication.
    tls_bytes_t server_write_IV_key; // Similarly, the server write IV key is generated when AEAD is used for encryption and authentication.

    tls_record_decorder client_decorder;
    tls_record_decorder server_decorder;
};


/*****************************************************************************/
#endif /* __TLS_INTERNAL__ */

