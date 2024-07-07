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


#include <stdio.h> 
#include <stdlib.h> 
#include <getopt.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/prctl.h>

#include <iostream>
#include <fstream>
#include <string>
#include <stdexcept>

#include <pcap/pcap.h>
#include <nlohmann/json.hpp>

#include <audit_module.hpp>
#include <audit_debug.hpp>

/* modules */
#include <http/http.hpp>
#include <mysql/mysql.hpp>
#include <pgsql/pgsql.hpp>
#include <redis/redis.hpp>

/*****************************************************************************/

#define VERSION "0.1"

#define WORKDIR          "/var/audit"
#define PIDFILE          "/var/run/mysql-audit.pid"

#define DEFAULT_CONFILE  "/etc/mysql-audit.conf"
#define DEFAULT_LOGFILE  "/var/log/mysql-audit.log"
#define DEFAULT_AUDITLOG "/var/log/mysql-audit.json"
#define DEFAULT_KEYPATH  "/var/lib/mysql/server-key.pem"

/*****************************************************************************/

static void go_daemon(void);
static void list_interface(void);
static void get_conf(audit_conf_t& conf);
static bool check_conf(audit_conf_t& conf);
static void pidfile_create(void);
static void pidfile_delete(void);
static uint64_t pidfile_get(void);
static void change_process_name(int argc, char* argv[], audit_str_t& name);

/*****************************************************************************/

static bool is_quiet = false;
static bool is_start = false;
static std::string conf_path(DEFAULT_CONFILE);
static audit_debug_level_t debug_level = AUDIT_DBG_LVL_ERR;

/*****************************************************************************/

static void help(char *argv[])
{
    const char* help_msg = "Usage: %s -i <interface> -p <port> [-b|-r|-s] [-f]\n"
"    -i <interface>\n"
"    --interface=<interface>\n"
"         Listen on interface. If unspecified, `any` will be used.\n"
"         Note that captures on the `any` device will not be done in promiscuous mode.\n"
"    -b\n"
"    --start\n"
"         Start the dissect process.\n"
"    -c\n"
"    --config\n"
"         config file path.\n"
"    -d <level>\n"
"    --debug <level>\n"
"         Set debug level(0:ERROR, 1:WARN, 2:INFO, 3:DEBUG, 4 PACKET).\n"
"    -r\n"
"    --restart\n"
"         Restart the dissect process.\n"
"    -s\n"
"    --stop\n"
"         Stop the dissect process.\n"
"    -p\n"
"    --port <port number>\n"
"         port number.\n"
"    -f\n"
"    --frontend\n"
"         run in frontend, default is daemon.\n"
"    -k\n"
"    --key\n"
"         RSA Private Key Path, only support PEM format.\n"
"    -a\n"
"    --pass <PASSWORD>\n"
"         RSA Private Key Password(!!! Not implemented).\n"
"    -g\n"
"    --reopen\n"
"         Reopen log file(mysql-audit.json).\n"
"    -v\n"
"    --version\n"
"         Show version number.\n"
"    -h\n"
"    --help\n"
"         Show this hlep\n";

    printf("MySQL Audit, Version %s\n\n", VERSION);
    printf(help_msg, argv[0]);
}


static void load_modules(void)
{
    http_module_register();
    mysql_module_register();
    pgsql_module_register();
    redis_module_register();
}

int main(int argc, char *argv[])
{
    int c;
    int option_index = 0;
    bool restart = false;
    auto pid = pidfile_get();
    bool is_running = (pid == 0 ? false : true);
    bool is_daemon = true;
    audit_module_entry module_entry = nullptr;
    audit_conf_t conf = {};

    prctl(PR_SET_NAME, "mysql-audit", 0, 0, 0);

    load_modules();
    get_conf(conf);

    static struct option long_options[] = {
        {"pass",       required_argument, 0,  'a' }, /* SSL Private Key Password */
        {"start",      no_argument,       0,  'b' }, /* start */
        {"config",     required_argument, 0,  'c' }, /* config file path */
        {"debug",      no_argument,       0,  'd' }, /* debug */
        {"frontend",   no_argument,       0,  'f' }, /* not daemon */
        {"interface",  required_argument, 0,  'i' }, /* interface to capture packets, default is any */
        {"key",        required_argument, 0,  'k' }, /* SSL Private Key Path */
        {"iflist",     no_argument,       0,  'l' }, /* show interface list */
        {"module",     required_argument, 0,  'm' }, /* module name, mysql / pgsql / redis */
        {"port",       required_argument, 0,  'p' }, /* port */
        {"quiet",      no_argument,       0,  'q' }, /* quiet */
        {"restart",    no_argument,       0,  'r' }, /* restart */
        {"stop",       no_argument,       0,  's' }, /* stop */
        {"reopen",     no_argument,       0,  'g' }, /* reopen log file */
        {"version",    no_argument,       0,  'v' }, /* show version */
        {"help",       no_argument,       0,  'h' }, /* help */
        {0,            0,                 0,  0   }
    };

    while (1) {
        c = getopt_long(argc, argv, "a:bc:d:i:fk:m:p:qlrsvhg", long_options, &option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'a':
            conf.rsa_key_pass = std::string(optarg);
            break;

        case 'i':
            conf.if_name = std::string(optarg);
            break;

        case 'b':
            is_start = true;
            break;

        case 'c':
            conf_path = std::string(optarg);
            break;

        case 'd': {
            int debug = std::stoi(optarg);
            debug_level = debug > AUDIT_DBG_LVL_PKG ? AUDIT_DBG_LVL_PKG : (audit_debug_level_t)debug;
            debug_level = debug < AUDIT_DBG_LVL_ERR ? AUDIT_DBG_LVL_ERR : (audit_debug_level_t)debug;
            } break;

        case 'f':
            is_daemon = false;
            break;

        case 'k':
            conf.rsa_key_path = std::string(optarg);
            break;

        case 'p':
            conf.port = std::stoi(optarg);
            break;

        case 'l':
            list_interface();
            exit(EXIT_SUCCESS);
            break;

        case 'm':
            conf.module_name = std::string(optarg);
            break;

        case 'v':
            fprintf(stdout, "mysql-audit version: %s\n", VERSION);
            exit(EXIT_SUCCESS);
            break;

        case 'r':
            restart = true;
            break;

        case 's':
            if (is_running) {
                kill((pid_t)pid, SIGKILL);
                pidfile_delete();
                fprintf(stdout, "== stop mysql-audit\n");
            } else {
                fprintf(stdout, "== stop mysql-audit(not running)\n");
            }
            exit(EXIT_SUCCESS);
            break;

        case 'h':
            help(argv);
            exit(EXIT_SUCCESS);
            break;

        case 'g':
            break;

        case 'q':
            is_quiet = true;
            break;

        default:
            help(argv);
            exit(EXIT_FAILURE);
            break;
        }
    }

    module_entry = audit_module_get_entry(conf.module_name);
    if (nullptr == module_entry) {
        exit(EXIT_FAILURE);
    }


    if (!check_conf(conf)) {
        exit(EXIT_FAILURE);
    }

    if (restart && is_running) {/* kill old process */
        auto ret = kill((pid_t)pid, SIGKILL);
        if (ret == 0) {
            pidfile_delete();
            is_running = false;
        } else {
            std::cerr << "kill(" << pid << ") failed, ret=" << ret << std::endl;
        }
    }

    if (is_start == false) {
        if (is_running) {
            kill((pid_t)pid, SIGKILL);
            pidfile_delete();
        }
        exit(EXIT_SUCCESS);
    }

    if (is_daemon) {
        go_daemon();
    }

    audit_str_t process_name = "mysql-audit-" + conf.module_name;
    change_process_name(argc, argv, process_name);

    /* child process */
    chdir(WORKDIR);
    pidfile_create();

    audit_debug_init(debug_level);
    module_entry(conf);

    return 0;
}

static void change_process_name(int argc, char* argv[], audit_str_t& name)
{
    size_t length = 0;

    for (int i = 0; i < argc; i++) {
        length += strlen(argv[0]) + 1;
    }

    --length;

    if (length < name.size()) {
        memcpy(argv[0], name.c_str(), length);
    } else {
        memcpy(argv[0], name.c_str(), name.size());
        for (size_t i = name.size(); i < length; i++) {
            argv[0][i] = 0;
        }
    }

    prctl(PR_SET_NAME, name.c_str(), 0, 0, 0);
}


static bool is_valid_interface(std::string& if_name)
{
    const char* name = if_name.c_str();

    if (if_name.size() >= IF_NAMESIZE) {
        fprintf(stderr, "Invalid interface name %s\n", optarg);
        return false;
    }

    if (strcmp(name, "any") != 0) {
        return true;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs = nullptr;
    int ret = pcap_findalldevs(&alldevs, errbuf);
    if (PCAP_ERROR == ret) {
        fprintf(stderr, "Get interfaces failed, %s\n", errbuf);
        return false;
    }

    if (nullptr == alldevs) {
        fprintf(stderr, "No interfaces found on this host\n");
        return false;
    }

    pcap_if_t* tmp = alldevs;
    while (tmp) {
        if (strcmp(tmp->name, name) == 0) {
            break;
        } else {
            tmp = tmp->next;
        }
    }

    if (nullptr == tmp) {
        pcap_freealldevs(alldevs);
        fprintf(stderr, "The interface %s not exist\n", name);
        return false;
    }

    if (!(tmp->flags & PCAP_IF_UP)) {
        pcap_freealldevs(alldevs);
        fprintf(stderr, "The interface %s is down\n", name);
        return false;
    }

    if (!(tmp->flags & PCAP_IF_RUNNING)) {
        pcap_freealldevs(alldevs);
        fprintf(stderr, "The interface %s is not running\n", name);
        return false;
    }

    if (tmp->flags & PCAP_IF_LOOPBACK) {
        pcap_freealldevs(alldevs);
        fprintf(stderr, "The interface %s is a lookback interface\n", name);
        return false;
    }

    pcap_freealldevs(alldevs);
    return true;
}


static bool is_valid_port(int port)
{
    if ((port > 65535) || (port < 1)) {
        fprintf(stderr, "Invalid port %d\n", port);
        return false;
    }

    return true;
}


static void list_interface(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs = nullptr;

    int ret = pcap_findalldevs(&alldevs, errbuf);
    if (PCAP_ERROR == ret) {
        fprintf(stderr, "Get interfaces failed, %s\n", errbuf);
        return;
    }

    if (nullptr == alldevs) {
        fprintf(stderr, "No interfaces found on this host\n");
        return;
    }

    pcap_if_t* tmp = alldevs;
    while (tmp) {
        if (!(tmp->flags & PCAP_IF_UP)) {
            tmp = tmp->next;
            continue;
        }
        
        if (!(tmp->flags & PCAP_IF_RUNNING)) {
            tmp = tmp->next;
            continue;
        }
        
        if (tmp->flags & PCAP_IF_LOOPBACK) {
            tmp = tmp->next;
            continue;
        }

        if (tmp->flags & PCAP_IF_CONNECTION_STATUS_UNKNOWN) {
            tmp = tmp->next;
            continue;
        }

        if (!(tmp->flags & PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE)) {
            if (!(tmp->flags & PCAP_IF_CONNECTION_STATUS_CONNECTED)) {
                tmp = tmp->next;
                continue;
            }
        }

        if (nullptr == tmp->addresses) {
            tmp = tmp->next;
            continue;
        }

        fprintf(stdout, "Interface: %s\n", tmp->name);

        tmp = tmp->next;
    }

    pcap_freealldevs(alldevs);
}


static void pidfile_create(void)
{
    FILE* fp = NULL;
    
    fp = fopen(PIDFILE, "w");
    if (NULL == fp) {
        fprintf(stderr, "fopen(%s) failed, %s\n", PIDFILE, strerror(errno));
    } else {
        char buf[32];
        sprintf(buf, "%lu", (unsigned long)getpid());
        fwrite(buf, 1, strlen(buf), fp);
        fclose(fp);
    }
}

static void pidfile_delete(void)
{
    unlink(PIDFILE);
}

static uint64_t pidfile_get(void)
{
    uint64_t pid = 0UL;
    FILE* fp = NULL;
    fp = fopen(PIDFILE, "r");
    if (NULL != fp) {
        fscanf(fp, "%lu", &pid);
        fclose(fp);
        /* process not exist */
        if (kill((pid_t)pid, 0) != 0) {
            pid = 0UL;
            unlink(PIDFILE);
        }
    }

    return pid;
}


/* Daemonize a process */
static void go_daemon(void)
{
    int fd;
    pid_t pid;

    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "fork(1) failed, %s\n", strerror(errno));
        return;
    } else if (pid) { /* parent process exit  */
        exit(0);
    }

    /* Become session leader */
    if (setsid() < 0) {
        fprintf(stderr, "setsid() failed, %s\n", strerror(errno));
        return;
    }

    /* Dup stdin, stdout and stderr to mysql-audit.log */
    if ((fd = open(DEFAULT_LOGFILE, O_RDWR | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR)) >= 0) {
        dup2(fd, 0);
        dup2(fd, 1);
        dup2(fd, 2);

        close(fd);
    }
}



static void get_conf(audit_conf_t& conf)
{
    bool ok = false;
    nlohmann::json j;
    const char* conf_path_str = conf_path.c_str();

    conf.audit_log_path = DEFAULT_AUDITLOG;

    int ret = access(conf_path_str, F_OK);
    if (ret == 0) {
        ret = access(conf_path_str, R_OK);
        if (ret == 0) {
            try {
                std::ifstream f(conf_path_str);
                j = nlohmann::json::parse(f);
                ok = true;
            } catch (std::exception &ex) {
                std::cerr << ex.what() << std::endl;
            }
        }
    }

    if (!ok) {
        conf.if_name = "any";
        conf.port = 3306;
        is_start = false;
        debug_level = AUDIT_DBG_LVL_ERR;
        conf.audit_log_path = std::string(DEFAULT_AUDITLOG);
        conf.rsa_key_path   = std::string(DEFAULT_KEYPATH);
        conf.rsa_key_pass   = std::string("");
        return;
    }


    if (j.contains("interface")) {
        conf.if_name = j["interface"];
    } else {
        conf.if_name = "any";
    }

    if (j.contains("port")) {
        std::string port = j["port"];
        conf.port = std::stoi(port);
    } else {
        conf.port = 3306;
    }

    if (j.contains("status")) {
        std::string status =  j["status"];
        if (status.compare("start") == 0) {
            is_start = true;
        } else {
            is_start = false;
        }
    } else {
        is_start = false;
    }

    if (j.contains("key")) {
        std::string key = j["key"];
        conf.rsa_key_path = key;
    } else {
        conf.rsa_key_path = std::string(DEFAULT_KEYPATH);
    }

    if (j.contains("debug")) {
        std::string debug_str =  j["debug"];
        int debug = std::stoi(debug_str);
        debug_level = debug > AUDIT_DBG_LVL_PKG ? AUDIT_DBG_LVL_PKG : (audit_debug_level_t)debug;
        debug_level = debug < AUDIT_DBG_LVL_ERR ? AUDIT_DBG_LVL_ERR : (audit_debug_level_t)debug;
    } else {
        debug_level = AUDIT_DBG_LVL_ERR;
    }
}

static bool check_conf(audit_conf_t& conf)
{
    if (!is_valid_interface(conf.if_name)) {
        return false;
    }

    if (!is_valid_port(conf.port)) {
        return false;
    }

    if (!is_quiet) {
        printf("=============== mysql-audit v%s ===================\n", VERSION);
        printf("== Module      : %s\n", conf.module_name.c_str());
        printf("== Config File : %s\n", conf_path.c_str());
        printf("== Private Key : %s\n", conf.rsa_key_path.c_str());
        printf("== Key Password: %s\n", conf.rsa_key_pass.c_str());
        printf("== Interface   : %s\n", conf.if_name.c_str());
        printf("== Port        : %d\n", conf.port);
        printf("== Debug       : %d(0:Err,1:Warn,2:Info,3,Dbg,4:Pkg)\n", debug_level);
        printf("== Start       : %s\n", is_start ? "True" : "False");
        printf("================================================\n");
    }

    uint64_t pid = pidfile_get();
    if (is_start) {
        if (pid) {
            kill((pid_t)pid, SIGKILL);
            printf("=== Kill old process %d\n", int(pid));
            pidfile_delete();
        }
    }

    return true;
}

