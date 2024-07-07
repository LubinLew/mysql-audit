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


#include <time.h>

#include <map>
#include "tls_internal.hpp"

/*****************************************************************************/

struct tls_resumption_data_t {
    time_t expiration;
    tls_security_parameters_t parameters;
};

using tls_sess_resumption_t = std::map<tls_bytes_t, tls_resumption_data_t>;


static tls_sess_resumption_t g_sess_id_bucket;
static tls_sess_resumption_t g_sess_ticket_bucket;

/*****************************************************************************/

void tls_sess_id_insert(tls_sess_t& tls, tls_bytes_t& id, uint32_t lifetime)
{
    time_t now = time(nullptr);
    tls_resumption_data_t data = {now + lifetime, tls.paramters};

    g_sess_id_bucket.insert({id, data});

}

bool tls_sess_id_lookup(tls_sess_t& tls, tls_bytes_t& id)
{
    auto search = g_sess_id_bucket.find(id);
     if (search != g_sess_id_bucket.end()) {
         tls.paramters = search->second.parameters;
         return true;
     }

    return false;
}



/* https://datatracker.ietf.org/doc/html/rfc5077#section-3.1

     Client                                                Server
     ClientHello
     (SessionTicket extension)      -------->
                                                      ServerHello
                                  (empty SessionTicket extension)
                                                 NewSessionTicket
                                               [ChangeCipherSpec]
                                   <--------             Finished
     [ChangeCipherSpec]
     Finished                      -------->
     Application Data              <------->     Application Data

   Figure 2: Message Flow for Abbreviated Handshake Using New Session Ticket
*/
void tls_sess_ticket_insert(tls_sess_t& tls, tls_bytes_t& ticket, uint32_t lifetime)
{
    time_t now = time(nullptr);
    tls_resumption_data_t data = {now + lifetime, tls.paramters};

    g_sess_id_bucket.insert({ticket, data});

}

bool tls_sess_ticket_lookup(tls_sess_t& tls, tls_bytes_t& ticket)
{
    auto search = g_sess_id_bucket.find(ticket);
     if (search != g_sess_id_bucket.end()) {
         tls.paramters = search->second.parameters;
         return true;
     }

    return false;
}


