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


#ifndef __AUDIT_MODULE_H__
#define __AUDIT_MODULE_H__
/*****************************************************************************/

#include "audit_types.hpp"


/*****************************************************************************/

using audit_module_entry = void (*)(audit_conf_t& conf);

struct audit_module_t {
    audit_str_t        name;
    audit_module_entry entry;

    uint16_t           default_port;
    audit_str_t        default_private_key_path;
};

void audit_module_register(audit_module_t& module);
audit_module_entry audit_module_get_entry(audit_str_t& module_name);
uint16_t audit_module_get_default_port(audit_str_t& module_name);
audit_str_t audit_module_get_default_rsakey_path(audit_str_t& module_name);


/*****************************************************************************/
#endif /* __AUDIT_MODULE_H__ */

