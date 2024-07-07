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


#include "audit_module.hpp"

/*****************************************************************************/

static std::map<audit_str_t, audit_module_t> g_moudles;

/*****************************************************************************/

void audit_module_register(audit_module_t& module)
{
#if 0
    auto search = g_moudles.find(module.name);
    if (search != g_moudles.end()) {
    }
#endif

    g_moudles.insert({module.name, module});
}

audit_module_entry audit_module_get_entry(audit_str_t& module_name)
{
    auto search = g_moudles.find(module_name);
    if (search != g_moudles.end()) {
        return search->second.entry;
    }

    return nullptr;
}


uint16_t audit_module_get_default_port(audit_str_t& module_name)
{
    auto search = g_moudles.find(module_name);
    if (search != g_moudles.end()) {
        return search->second.default_port;
    }

    return 0;
}

audit_str_t audit_module_get_default_rsakey_path(audit_str_t& module_name)
{
    auto search = g_moudles.find(module_name);
    if (search != g_moudles.end()) {
        return search->second.default_private_key_path;
    }

    return "";
}

