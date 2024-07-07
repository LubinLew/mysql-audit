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


#include <algorithm>

#include "tls_internal.hpp"
#include "tls_debug.hpp"

/*****************************************************************************/

struct tls_type_name_t {
    uint16_t    type;
    const char* name;
};

#define TLS_TYPE_DEF(_val) {_val, #_val}

using tls_type_arr_t = std::vector<tls_type_name_t>;

/*****************************************************************************/

static const char* tls_type_binary_search(tls_type_arr_t& tab, uint16_t type)
{
    const char*  result { "unknown" };
    tls_type_name_t tmp { type, nullptr };

    std::binary_search(tab.begin(), tab.end(), tmp,
        [&](const tls_type_name_t& val, const tls_type_name_t& element) {
            if (element.type == val.type) {
                result = element.name;
            }
            return val.type < element.type;
        }
    );

    return result;
}

/*****************************************************************************/

const char* tls_info_endpoint(uint16_t end)
{
    return end == TLS_CONN_END_CLIENT ? "Client" : "Server";
}

/*****************************************************************************/

const char* tls_info_version(uint16_t type)
{
    static tls_type_arr_t _tls_version {
        { SSL_VER_3_0, "SSLv3.0" },
        { TLS_VER_1_0, "TLSv1.0" },
        { TLS_VER_1_1, "TLSv1.1" },
        { TLS_VER_1_2, "TLSv1.2" },
        { TLS_VER_1_3, "TLSv1.3" }
    };

    return tls_type_binary_search(_tls_version, type);
}

/*****************************************************************************/

const char* tls_info_record_type(uint16_t type)
{
    static tls_type_arr_t _tls_record_name {
        TLS_TYPE_DEF(change_cipher_spec),
        TLS_TYPE_DEF(alert),
        TLS_TYPE_DEF(handshake),
        TLS_TYPE_DEF(application_data)
    };

    return tls_type_binary_search(_tls_record_name, type);
}

/*****************************************************************************/

const char* tls_info_handshake_type(uint16_t type)
{
    static tls_type_arr_t _tls_handshake_name {
        TLS_TYPE_DEF(hello_request),
        TLS_TYPE_DEF(client_hello),
        TLS_TYPE_DEF(server_hello),
        TLS_TYPE_DEF(new_session_ticket),
        TLS_TYPE_DEF(end_of_early_data),
        TLS_TYPE_DEF(encrypted_extensions),
        TLS_TYPE_DEF(certificate),
        TLS_TYPE_DEF(server_key_exchange),
        TLS_TYPE_DEF(certificate_request),
        TLS_TYPE_DEF(server_hello_done),
        TLS_TYPE_DEF(certificate_verify),
        TLS_TYPE_DEF(client_key_exchange),
        TLS_TYPE_DEF(finished),
        TLS_TYPE_DEF(certificate_url),
        TLS_TYPE_DEF(certificate_status),
        TLS_TYPE_DEF(key_update),
        TLS_TYPE_DEF(message_hash)
    };

    return tls_type_binary_search(_tls_handshake_name, type);
}

/*****************************************************************************/

const char* tls_info_extension_type(uint8_t type)
{
    static tls_type_arr_t _tls_extension_name {
        TLS_TYPE_DEF(server_name),
        TLS_TYPE_DEF(max_fragment_length),
        TLS_TYPE_DEF(client_certificate_url),
        TLS_TYPE_DEF(trusted_ca_keys),
        TLS_TYPE_DEF(truncated_hmac),
        TLS_TYPE_DEF(status_request),
        TLS_TYPE_DEF(user_mapping),
        TLS_TYPE_DEF(client_authz),
        TLS_TYPE_DEF(server_authz),
        TLS_TYPE_DEF(cert_type),
        TLS_TYPE_DEF(supported_groups),
        TLS_TYPE_DEF(ec_point_formats),
        TLS_TYPE_DEF(srp),
        TLS_TYPE_DEF(signature_algorithms),
        TLS_TYPE_DEF(use_srtp),
        TLS_TYPE_DEF(heartbeat),
        TLS_TYPE_DEF(application_layer_protocol_negotiation),
        TLS_TYPE_DEF(status_request_v2),
        TLS_TYPE_DEF(signed_certificate_timestamp),
        TLS_TYPE_DEF(client_certificate_type),
        TLS_TYPE_DEF(server_certificate_type),
        TLS_TYPE_DEF(padding),
        TLS_TYPE_DEF(encrypt_then_mac),
        TLS_TYPE_DEF(extended_master_secret),
        TLS_TYPE_DEF(token_binding),
        TLS_TYPE_DEF(cached_info),
        TLS_TYPE_DEF(tls_lts),
        TLS_TYPE_DEF(compress_certificate),
        TLS_TYPE_DEF(record_size_limit),
        TLS_TYPE_DEF(pwd_protect),
        TLS_TYPE_DEF(pwd_clear),
        TLS_TYPE_DEF(password_salt),
        TLS_TYPE_DEF(ticket_pinning),
        TLS_TYPE_DEF(tls_cert_with_extern_psk),
        TLS_TYPE_DEF(delegated_credential),
        TLS_TYPE_DEF(session_ticket),
        TLS_TYPE_DEF(TLMSP),
        TLS_TYPE_DEF(TLMSP_proxying),
        TLS_TYPE_DEF(TLMSP_delegate),
        TLS_TYPE_DEF(supported_ekt_ciphers),
        TLS_TYPE_DEF(pre_shared_key),
        TLS_TYPE_DEF(early_data),
        TLS_TYPE_DEF(supported_versions),
        TLS_TYPE_DEF(cookie),
        TLS_TYPE_DEF(psk_key_exchange_modes),
        TLS_TYPE_DEF(certificate_authorities),
        TLS_TYPE_DEF(oid_filters),
        TLS_TYPE_DEF(post_handshake_auth),
        TLS_TYPE_DEF(signature_algorithms_cert),
        TLS_TYPE_DEF(key_share),
        TLS_TYPE_DEF(transparency_info),
        TLS_TYPE_DEF(connection_id),
        TLS_TYPE_DEF(external_id_hash),
        TLS_TYPE_DEF(external_session_id),
        TLS_TYPE_DEF(quic_transport_parameters),
        TLS_TYPE_DEF(ticket_request),
        TLS_TYPE_DEF(dnssec_chain),
        TLS_TYPE_DEF(sequence_number_encryption_algorithms)
    };

    return tls_type_binary_search(_tls_extension_name, type);
}

