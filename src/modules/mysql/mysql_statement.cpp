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


#include <audit_hyperscan.hpp>

#include "mysql_types.hpp"
#include "mysql_debug.hpp"
#include "mysql_statement.hpp"

/*****************************************************************************/

audit_hs_hdl_t* mysql_statement_init(void)
{
    if (!audit_hs_init()) {
        return nullptr;
    }

    audit_hs_hdl_t* hdl = audit_hs_block_create();
    if (nullptr == hdl) {
        return nullptr;
    }

    const static audit_hs_data_t _statements[] = {
    {1001, "ALTER\\s",                                 "ALTER",                0 },
    {1011, "CREATE\\s",                                "CREATE",               0 },
    {1023, "DROP\\s",                                  "DROP",                 0 },
    {1035, "RENAME\\s",                                "RENAME",               0 },
    {1036, "TRUNCATE\\s",                              "TRUNCATE",             0 },
    {1037, "CALL\\s",                                  "CALL",                 0 },
    {1038, "DELETE\\s",                                "DELETE",               0 },
    {1039, "DO\\s",                                    "DO",                   0 },
    {1040, "EXCEPT\\s",                                "EXCEPT",               0 },
    {1041, "HANDLER\\s",                               "HANDLER",              0 },
    {1042, "IMPORT\\s",                                "IMPORT",               0 },
    {1043, "INSERT\\s",                                "INSERT",               0 },
    {1044, "INTERSECT\\s",                             "INTERSECT",            0 },
    {1045, "LOAD\\s",                                  "LOAD",                 0 },
    {1047, "REPLACE\\s",                               "REPLACE",              0 },
    {1048, "SELECT\\s",                                "SELECT",               0 },
    {1049, "TABLE\\s",                                 "TABLE",                0 },
    {1050, "UPDATE\\s",                                "UPDATE",               0 },
    {1051, "VALUES\\s",                                "VALUES",               0 },
    {1052, "WITH\\s+.+?\\s+SELECT\\s",                 "SELECT",               0 },
    {1053, "WITH\\s+.+?\\s+UPDATE\\s",                 "UPDATE",               0 },
    {1054, "WITH\\s+.+?\\s+DELETE\\s",                 "DELETE",               0 },
    {1056, "COMMIT",                                   "COMMIT",               0 },
    {1057, "ROLLBACK",                                 "ROLLBACK",             0 },
    {1058, "SAVEPOINT\\s",                             "SAVEPOINT",            0 },
    {1060, "RELEASE\\s",                               "RELEASE",              0 },
    {1061, "LOCK\\s",                                  "LOCK",                 0 },
    {1062, "UNLOCK\\s",                                "UNLOCK",               0 },
    {1065, "SET\\s",                                   "SET",                  0 },
    {1066, "XA\\s",                                    "XA",                   0 },
    {1067, "PURGE\\s",                                 "PURGE",                0 },
    {1069, "RESET\\s",                                 "RESET",                0 },
    {1071, "CHANGE\\s",                                "CHANGE",               0 },
    {1076, "START\\s",                                 "START",                0 },
    {1078, "STOP\\s",                                  "STOP",                 0 },
    {1082, "PREPARE\\s",                               "PREPARE",              0 },
    {1083, "EXECUTE\\s",                               "EXECUTE",              0 },
    {1084, "DEALLOCATE\\s",                            "DEALLOCATE",           0 },
    {1085, "BEGIN",                                    "BEGIN",                0 },
    {1086, "CLOSE\\s",                                 "CLOSE",                0 },
    {1087, "FETCH\\s",                                 "FETCH",                0 },
    {1088, "OPEN\\s",                                  "OPEN",                 0 },
    {1089, "DECLARE\\s",                               "DECLARE",              0 },
    {1091, "GET\\s",                                   "GET",                  0 },
    {1094, "RESIGNAL\\s",                              "RESIGNAL",             0 },
    {1095, "SIGNAL\\s",                                "SIGNAL",               0 },
    {1096, "GRANT\\s",                                 "GRANT",                0 },
    {1098, "REVOKE\\s",                                "REVOKE",               0 },
    {1106, "ANALYZE\\s",                               "ANALYZE",              0 },
    {1107, "CHECK\\s",                                 "CHECK",                0 },
    {1108, "CHECKSUM\\s",                              "CHECKSUM",             0 },
    {1109, "OPTIMIZE\\s",                              "OPTIMIZE",             0 },
    {1110, "REPAIR\\s",                                "REPAIR",               0 },
    {1111, "INSTALL\\s",                               "INSTALL",              0 },
    {1113, "UNINSTALL\\s",                             "UNINSTALL",            0 },
    {1115, "CLONE\\s",                                 "CLONE",                0 },
    {1117, "SHOW\\s",                                  "SHOW",                 0 },
    {1118, "BINLOG\\s",                                "BINLOG",               0 },
    {1119, "CACHE\\s",                                 "CACHE",                0 },
    {1120, "FLUSH\\s",                                 "FLUSH",                0 },
    {1121, "KILL\\s",                                  "KILL",                 0 },
    {1124, "RESTART\\s",                               "RESTART",              0 },
    {1125, "SHUTDOWN\\s",                              "SHUTDOWN",             0 },
    {1126, "DESCRIBE\\s",                              "DESCRIBE",             0 },
    {1127, "DESC\\s",                                  "DESC",                 0 },
    {1128, "EXPLAIN\\s",                               "EXPLAIN",              0 },
    {1129, "HELP\\s",                                  "HELP",                 0 },
    {1130, "USE\\s",                                   "USE",                  0 }
    };

    auto ok = audit_hs_block_compile(hdl, _statements, sizeof(_statements)/sizeof(_statements[0]));
    if (!ok) {
        audit_hs_block_free(hdl);
        return nullptr;
    }

    /* everything is ready */
    return hdl;
}


void mysql_statement_free(audit_hs_hdl_t * hdl)
{
    audit_hs_block_free(hdl);
}


const audit_hs_data_t* mysql_statement_analysis(audit_hs_hdl_t* hdl, const char* data, size_t len)
{
     return audit_hs_block_scan(hdl, data, (unsigned int)len);

}

#ifdef _HS_TEST
int main(int argc, const char* argv[])
{
    const whs_data_t* result;
    whs_hdl_t* hdl =  mysql_statement_init();

    const char* data = argv[1];
    std::cout << "Input: " << data << std::endl;
    result = mysql_statement_analysis(hdl, (uint8_t*)data, strlen(data));
    if (result) {
        std::cout << result->category << std::endl;
        std::cout << result->pattern << std::endl;
    }

    mysql_statement_free(hdl);

    return 0;
}


#endif
/*****************************************************************************/

