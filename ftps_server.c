/*
 * Git: https://github.com/crypery
 * Author: https://crypery.com
 * License: GNU AGPL v3 (Affero GPL)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <io.h>
#include <direct.h>
#include <time.h>
#include "ftps.h"
#include "json.h"

#define MAX_LINE 4096
#define LOG_FILE_NAME "ftps_server.log"

/* ---- Logging ---- */
typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO  = 1,
    LOG_LEVEL_WARN  = 2,
    LOG_LEVEL_ERROR = 3
} LogLevel;

typedef enum {
    LOG_OUTPUT_BOTH   = 0,
    LOG_OUTPUT_CONSOLE = 1,
    LOG_OUTPUT_FILE    = 2
} LogOutput;

static FILE *g_log_file = NULL;
static LogOutput g_log_output = LOG_OUTPUT_BOTH;
static int g_log_initialized = 0;

static void log_timestamp(char *buf, size_t buf_len) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    if (tm_info) {
        strftime(buf, buf_len, "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        snprintf(buf, buf_len, "unknown");
    }
}

static void log_init(int output) {
    if (output == LOG_OUTPUT_FILE) {
        g_log_output = LOG_OUTPUT_FILE;
    } else if (output == LOG_OUTPUT_CONSOLE) {
        g_log_output = LOG_OUTPUT_CONSOLE;
    } else {
        g_log_output = LOG_OUTPUT_BOTH;
    }
    
    if (g_log_output == LOG_OUTPUT_FILE || g_log_output == LOG_OUTPUT_BOTH) {
        g_log_file = fopen(LOG_FILE_NAME, "a");
        if (g_log_file) {
            char ts[64];
            log_timestamp(ts, sizeof(ts));
            fprintf(g_log_file, "[%s] FTPS server log started\n", ts);
            fflush(g_log_file);
        }
    }
    g_log_initialized = 1;
}

static void log_close(void) {
    if (g_log_file) {
        char ts[64];
        log_timestamp(ts, sizeof(ts));
        fprintf(g_log_file, "[%s] FTPS server log closed\n", ts);
        fflush(g_log_file);
        fclose(g_log_file);
        g_log_file = NULL;
    }
    g_log_initialized = 0;
}

static void log_msg(LogLevel level, const char *fmt, ...) {
    char ts[64];
    log_timestamp(ts, sizeof(ts));

    const char *level_str;
    switch (level) {
        case LOG_LEVEL_DEBUG: level_str = "DEBUG"; break;
        case LOG_LEVEL_INFO:  level_str = "INFO";  break;
        case LOG_LEVEL_WARN:  level_str = "WARN";  break;
        case LOG_LEVEL_ERROR: level_str = "ERROR"; break;
        default: level_str = "UNKNOWN"; break;
    }

    char msg[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    char full_msg[1200];
    snprintf(full_msg, sizeof(full_msg), "[%s] [%d] [%s] %s\n", ts, level, level_str, msg);

    if (g_log_output == LOG_OUTPUT_FILE || g_log_output == LOG_OUTPUT_BOTH) {
        if (g_log_file) {
            fprintf(g_log_file, "%s", full_msg);
            fflush(g_log_file);
        }
    }

    if (g_log_output == LOG_OUTPUT_CONSOLE || g_log_output == LOG_OUTPUT_BOTH) {
        fprintf(stderr, "%s", full_msg);
        fflush(stderr);
    }
}

#define LOG_INFO(fmt, ...) log_msg(LOG_LEVEL_INFO, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) log_msg(LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) log_msg(LOG_LEVEL_WARN, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) log_msg(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)

/* ---- Configuration ---- */
typedef struct {
    int port;
    char root[256];
    int passive_port_start;
    int passive_port_end;
    int control_timeout;
    int data_timeout;
    int pasv_timeout;
    char username[128];
    char password[128];
    char cert_file[256];
    char key_file[256];
    int use_tls;
    int tls_version;
    int log_output;
} ServerConfig;

static ServerConfig g_config;

static void config_defaults(void) {
    g_config.port = 2121;
    strncpy(g_config.root, "ftps_root", sizeof(g_config.root) - 1);
    g_config.root[sizeof(g_config.root) - 1] = 0;
    g_config.passive_port_start = 50000;
    g_config.passive_port_end = 50100;
    g_config.control_timeout = 60;
    g_config.data_timeout = 30;
    g_config.pasv_timeout = 10;
    strncpy(g_config.username, "ftpuser", sizeof(g_config.username) - 1);
    strncpy(g_config.password, "ftppass", sizeof(g_config.password) - 1);
    strncpy(g_config.cert_file, "localhost.crt", sizeof(g_config.cert_file) - 1);
    strncpy(g_config.key_file, "localhost.key", sizeof(g_config.key_file) - 1);
    g_config.use_tls = 1;
    g_config.tls_version = 0;
    g_config.log_output = 0;
}

static int load_config(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        LOG_WARN("cannot open config file '%s', using defaults", path);
        return -1;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 65536) {
        fclose(f);
        LOG_ERROR("config file size invalid: %ld", sz);
        return -1;
    }
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        LOG_ERROR("memory allocation failed for config");
        return -1;
    }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = 0;

    JsonObject obj;
    json_init(&obj);
    JsonValue *root = json_parse_buf(buf, rd);
    if (!root) {
        LOG_ERROR("failed to parse JSON config");
        free(buf);
        return -1;
    }
    memcpy(&obj.root, root, sizeof(JsonValue));

    /* port */
    if (json_has(&obj.root, "port")) {
        JsonValue *v = json_get(&obj.root, "port");
        if (json_is_number(v)) {
            int p = (int)json_number(v);
            if (p > 0 && p < 65536) {
                g_config.port = p;
                LOG_INFO("config: port = %d", p);
            } else {
                LOG_WARN("config: invalid port %d, using default", p);
            }
        }
    }
    /* root */
    if (json_has(&obj.root, "root")) {
        JsonValue *v = json_get(&obj.root, "root");
        if (json_is_string(v)) {
            const char *s = json_string(v);
            if (s) {
                strncpy(g_config.root, s, sizeof(g_config.root) - 1);
                g_config.root[sizeof(g_config.root) - 1] = 0;
                LOG_INFO("config: root = %s", g_config.root);
            }
        }
    }
    /* passive_port_start */
    if (json_has(&obj.root, "passive_port_start")) {
        JsonValue *v = json_get(&obj.root, "passive_port_start");
        if (json_is_number(v)) {
            int p = (int)json_number(v);
            if (p > 0 && p < 65535) {
                g_config.passive_port_start = p;
                LOG_INFO("config: passive_port_start = %d", p);
            } else {
                LOG_WARN("config: invalid passive_port_start %d", p);
            }
        }
    }
    /* passive_port_end */
    if (json_has(&obj.root, "passive_port_end")) {
        JsonValue *v = json_get(&obj.root, "passive_port_end");
        if (json_is_number(v)) {
            int p = (int)json_number(v);
            if (p > 0 && p < 65536) {
                g_config.passive_port_end = p;
                LOG_INFO("config: passive_port_end = %d", p);
            } else {
                LOG_WARN("config: invalid passive_port_end %d", p);
            }
        }
    }
    /* control_timeout */
    if (json_has(&obj.root, "control_timeout")) {
        JsonValue *v = json_get(&obj.root, "control_timeout");
        if (json_is_number(v)) {
            int t = (int)json_number(v);
            if (t > 0 && t <= 3600) {
                g_config.control_timeout = t;
                LOG_INFO("config: control_timeout = %d", t);
            } else {
                LOG_WARN("config: invalid control_timeout %d", t);
            }
        }
    }
    /* data_timeout */
    if (json_has(&obj.root, "data_timeout")) {
        JsonValue *v = json_get(&obj.root, "data_timeout");
        if (json_is_number(v)) {
            int t = (int)json_number(v);
            if (t > 0 && t <= 3600) {
                g_config.data_timeout = t;
                LOG_INFO("config: data_timeout = %d", t);
            } else {
                LOG_WARN("config: invalid data_timeout %d", t);
            }
        }
    }
    /* pasv_timeout */
    if (json_has(&obj.root, "pasv_timeout")) {
        JsonValue *v = json_get(&obj.root, "pasv_timeout");
        if (json_is_number(v)) {
            int t = (int)json_number(v);
            if (t > 0 && t <= 300) {
                g_config.pasv_timeout = t;
                LOG_INFO("config: pasv_timeout = %d", t);
            } else {
                LOG_WARN("config: invalid pasv_timeout %d", t);
            }
        }
    }
    /* username */
    if (json_has(&obj.root, "username")) {
        JsonValue *v = json_get(&obj.root, "username");
        if (json_is_string(v)) {
            const char *s = json_string(v);
            if (s) {
                strncpy(g_config.username, s, sizeof(g_config.username) - 1);
                g_config.username[sizeof(g_config.username) - 1] = 0;
                LOG_INFO("config: username = %s", s);
            }
        }
    }
    /* password */
    if (json_has(&obj.root, "password")) {
        JsonValue *v = json_get(&obj.root, "password");
        if (json_is_string(v)) {
            const char *s = json_string(v);
            if (s) {
                strncpy(g_config.password, s, sizeof(g_config.password) - 1);
                g_config.password[sizeof(g_config.password) - 1] = 0;
                LOG_INFO("config: password = %s", s);
            }
        }
    }
    /* cert_file */
    if (json_has(&obj.root, "cert_file")) {
        JsonValue *v = json_get(&obj.root, "cert_file");
        if (json_is_string(v)) {
            const char *s = json_string(v);
            if (s) {
                strncpy(g_config.cert_file, s, sizeof(g_config.cert_file) - 1);
                g_config.cert_file[sizeof(g_config.cert_file) - 1] = 0;
                LOG_INFO("config: cert_file = %s", s);
            }
        }
    }
    /* key_file */
    if (json_has(&obj.root, "key_file")) {
        JsonValue *v = json_get(&obj.root, "key_file");
        if (json_is_string(v)) {
            const char *s = json_string(v);
            if (s) {
                strncpy(g_config.key_file, s, sizeof(g_config.key_file) - 1);
                g_config.key_file[sizeof(g_config.key_file) - 1] = 0;
                LOG_INFO("config: key_file = %s", s);
            }
        }
    }
    /* use_tls */
    if (json_has(&obj.root, "use_tls")) {
        JsonValue *v = json_get(&obj.root, "use_tls");
        if (json_is_bool(v)) {
            g_config.use_tls = json_bool(v);
            LOG_INFO("config: use_tls = %s", g_config.use_tls ? "true" : "false");
        }
    }
    /* tls_version */
    if (json_has(&obj.root, "tls_version")) {
        JsonValue *v = json_get(&obj.root, "tls_version");
        if (json_is_number(v)) {
            int ver = (int)json_number(v);
            if (ver >= 0 && ver <= 2) {
                g_config.tls_version = ver;
                LOG_INFO("config: tls_version = %d", ver);
            } else {
                LOG_WARN("config: invalid tls_version %d, using auto", ver);
            }
        }
    }
    /* log_output */
    if (json_has(&obj.root, "log_output")) {
        JsonValue *v = json_get(&obj.root, "log_output");
        if (json_is_number(v)) {
            int out = (int)json_number(v);
            if (out >= 0 && out <= 2) {
                g_config.log_output = out;
                LOG_INFO("config: log_output = %d", out);
            } else {
                LOG_WARN("config: invalid log_output %d, using both", out);
            }
        }
    }

    json_destroy(&obj);
    free(buf);
    return 0;
}

static int validate_config(void) {
    int errors = 0;

    if (g_config.port <= 0 || g_config.port >= 65536) {
        LOG_ERROR("config validation: port must be 1-65535, got %d", g_config.port);
        errors++;
    }

    if (!g_config.root || strlen(g_config.root) == 0) {
        LOG_ERROR("config validation: root must not be empty");
        errors++;
    }

    if (g_config.passive_port_start <= 0 || g_config.passive_port_start >= 65535) {
        LOG_ERROR("config validation: passive_port_start must be 1-65534, got %d", g_config.passive_port_start);
        errors++;
    }

    if (g_config.passive_port_end <= 1 || g_config.passive_port_end > 65536) {
        LOG_ERROR("config validation: passive_port_end must be 2-65536, got %d", g_config.passive_port_end);
        errors++;
    }

    if (g_config.passive_port_start >= g_config.passive_port_end) {
        LOG_ERROR("config validation: passive_port_start (%d) must be less than passive_port_end (%d)",
                  g_config.passive_port_start, g_config.passive_port_end);
        errors++;
    }

    if (g_config.control_timeout <= 0 || g_config.control_timeout > 3600) {
        LOG_ERROR("config validation: control_timeout must be 1-3600, got %d", g_config.control_timeout);
        errors++;
    }

    if (g_config.data_timeout <= 0 || g_config.data_timeout > 3600) {
        LOG_ERROR("config validation: data_timeout must be 1-3600, got %d", g_config.data_timeout);
        errors++;
    }

    if (g_config.pasv_timeout <= 0 || g_config.pasv_timeout > 300) {
        LOG_ERROR("config validation: pasv_timeout must be 1-300, got %d", g_config.pasv_timeout);
        errors++;
    }

    if (strlen(g_config.username) == 0) {
        LOG_ERROR("config validation: username must not be empty");
        errors++;
    }

    if (strlen(g_config.password) == 0) {
        LOG_ERROR("config validation: password must not be empty");
        errors++;
    }

    if (g_config.tls_version < 0 || g_config.tls_version > 2) {
        LOG_ERROR("config validation: tls_version must be 0 (auto), 1 (1.2), or 2 (1.3), got %d", g_config.tls_version);
        errors++;
    }

    if (g_config.log_output < 0 || g_config.log_output > 2) {
        LOG_ERROR("config validation: log_output must be 0 (both), 1 (console), or 2 (file), got %d", g_config.log_output);
        errors++;
    }

    return errors;
}

/* Server TLS identity, loaded from localhost.crt / localhost.key.
 * If not loadable, the TLS layer auto-generates a self-signed cert. */
static RSAKey g_key;
static int g_has_identity = 0;
static uint8_t g_cert[TLS_RSA_MAX_CERT_SIZE];
static int g_cert_len = 0;

typedef struct {
    const char *root;
    char cwd[1024];
    char user[64];
    int authed;
    char type;
    char prot;
    FTPS_Conn *data_listener;
    char rnfr[1024];
    int has_rnfr;
    RSAKey dkey;
    int has_dkey;
    uint8_t dcert[TLS_RSA_MAX_CERT_SIZE];
    int dcert_len;
    int passive_port_counter;
    int passive_port_start;
    int passive_port_end;
    int use_tls;
    int tls_version;
} FTPS_Session;

/* ---- path sandbox helpers ---- */

#define MAX_PATH_PARTS 128

static void path_push(char parts[][256], int *depth, const char *s, size_t len) {
    if (len == 0) return;
    if (len == 1 && s[0] == '.') return;
    if (len == 2 && s[0] == '.' && s[1] == '.') {
        if (*depth > 0) (*depth)--;
        return;
    }
    if (*depth < MAX_PATH_PARTS - 1 && len < 256) {
        memcpy(parts[*depth], s, len);
        parts[*depth][len] = 0;
        (*depth)++;
    }
}

static void push_path(char parts[][256], int *depth, const char *in) {
    char tok[256];
    size_t t = 0;
    const char *p = in ? in : "";
    for (;;) {
        char c = *p;
        if (c == 0 || c == '/' || c == '\\') {
            if (t > 0) { path_push(parts, depth, tok, t); t = 0; }
            if (c == 0) break;
            p++;
            continue;
        }
        if (t < sizeof(tok)) tok[t++] = c;
        p++;
    }
}

static void norm_path(char *out, size_t n, const char *cwd, const char *arg) {
    char parts[MAX_PATH_PARTS][256];
    int depth = 0;
    int absolute = arg && (arg[0] == '/' || arg[0] == '\\');
    if (!absolute && cwd && cwd[0]) push_path(parts, &depth, cwd);
    push_path(parts, &depth, arg);

    size_t o = 0;
    for (int i = 0; i < depth; i++) {
        size_t l = strlen(parts[i]);
        if (o + (o ? 1 : 0) + l + 1 > n) break;
        if (o) out[o++] = '/';
        memcpy(out + o, parts[i], l);
        o += l;
    }
    out[o] = 0;
}

static void make_full_path(char *out, size_t n, const char *root, const char *rel) {
    if (rel && rel[0]) snprintf(out, n, "%s/%s", root, rel);
    else snprintf(out, n, "%s", root);
}

/* ---- data transfer ---- */

static int send_file_data(FTPS_Conn *data, const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { return 0; }
    char buf[16384];
    int n;
    while ((n = (int)fread(buf, 1, sizeof(buf), f)) > 0) {
        if (ftps_send(data, buf, n) != 0) { fclose(f); return 0; }
    }
    fclose(f);
    return 1;
}

static int recv_file_data(FTPS_Conn *data, const char *path) {
    FILE *f = fopen(path, "wb");
    if (!f) return 0;
    char buf[16384];
    int total = 0;
    for (;;) {
        int n = ftps_recv(data, buf, sizeof(buf));
        if (n < 0) { fclose(f); return 0; }
        if (n == 0) break;
        total += n;
        if (fwrite(buf, 1, (size_t)n, f) != (size_t)n) { fclose(f); return 0; }
    }
    fclose(f);
    return 1;
}

static int list_directory(FTPS_Conn *data, const char *dirpath, int mlsd) {
    char pattern[1200];
    snprintf(pattern, sizeof(pattern), "%s/*", dirpath);
    struct _finddata_t fd;
    intptr_t h = _findfirst(pattern, &fd);
    if (h == -1) return 0;
    char line[1200];
    do {
        if (fd.name[0] == '.') continue;
        if (mlsd) {
            char ts[32] = "00000000000000";
            struct tm *tm = localtime(&fd.time_write);
            if (tm) strftime(ts, sizeof(ts), "%Y%m%d%H%M%S", tm);
            if (fd.attrib & _A_SUBDIR)
                snprintf(line, sizeof(line), "type=dir;modify=%s; %s\r\n", ts, fd.name);
            else
                snprintf(line, sizeof(line), "type=file;size=%ld;modify=%s; %s\r\n",
                         (long)fd.size, ts, fd.name);
        } else {
            const char *kind = (fd.attrib & _A_SUBDIR) ? "drwxr-xr-x" : "-rw-r--r--";
            snprintf(line, sizeof(line), "%s    1 ftp ftp %12ld %s\r\n", kind, (long)fd.size, fd.name);
        }
        if (ftps_send(data, line, strlen(line)) != 0) { _findclose(h); return 0; }
    } while (_findnext(h, &fd) == 0);
    _findclose(h);
    return 1;
}

static int open_data_listener(FTPS_Session *s, uint16_t *port) {
    if (s->data_listener) { ftps_destroy(s->data_listener); s->data_listener = NULL; }
    s->data_listener = ftps_create();
    if (!s->data_listener) return -1;

    int current_port = s->passive_port_counter;
    if (current_port < s->passive_port_start || current_port >= s->passive_port_end) {
        current_port = s->passive_port_start;
    }

    int rc = ftps_listen(s->data_listener, NULL, current_port);
    if (rc != 0) {
        LOG_ERROR("failed to listen on passive port %d", current_port);
        ftps_destroy(s->data_listener);
        s->data_listener = NULL;
        return -1;
    }

    uint32_t ip;
    rc = ftps_get_local(s->data_listener, &ip, port);
    if (rc == 0) {
        s->passive_port_counter = current_port + 1;
        if (s->passive_port_counter >= s->passive_port_end) {
            s->passive_port_counter = s->passive_port_start;
        }
        LOG_DEBUG("passive listener on port %d", *port);
    } else {
        LOG_ERROR("failed to get passive port info");
        ftps_destroy(s->data_listener);
        s->data_listener = NULL;
    }
    return rc;
}

static void do_data_command(FTPS_Conn *c, FTPS_Session *s, const char *verb, const char *arg) {
    if (!s->data_listener) { ftps_send_line(c, "425 Use PASV first"); return; }
    if (s->use_tls && !c->tls_established) { ftps_send_line(c, "530 TLS required"); return; }
    if (!s->authed) { ftps_send_line(c, "530 Not logged in"); return; }

    char rel[1024] = { 0 };
    int is_list = (strcmp(verb, "LIST") == 0) || (strcmp(verb, "MLSD") == 0);
    int is_mlsd = (strcmp(verb, "MLSD") == 0);
    norm_path(rel, sizeof(rel), s->cwd, arg);
    if (!is_list && rel[0] == '\0') {
        ftps_send_line(c, "550 Invalid path");
        return;
    }
    char fp[1300];
    make_full_path(fp, sizeof(fp), s->root, rel);

    ftps_send_line(c, "150 Opening data connection");

    int pasv_timeout_ms = g_config.pasv_timeout * 1000;
    if (pasv_timeout_ms > 30000) pasv_timeout_ms = 30000;
    if (pasv_timeout_ms <= 0) pasv_timeout_ms = 10000;

    if (ftps_wait_in(s->data_listener, pasv_timeout_ms) <= 0) {
        LOG_WARN("data connection timeout for %s %s", verb, arg);
        ftps_destroy(s->data_listener);
        s->data_listener = NULL;
        ftps_send_line(c, "425 Data connection not established (timeout)");
        return;
    }

    FTPS_Conn *data = ftps_accept(s->data_listener);
    ftps_destroy(s->data_listener);
    s->data_listener = NULL;
    if (!data) {
        LOG_ERROR("failed to accept data connection for %s", verb);
        ftps_send_line(c, "425 Data connection failed");
        return;
    }
    ftps_set_socket_timeout(data, g_config.data_timeout);

    if (s->use_tls && s->prot == 'P') {
        if (s->has_dkey) ftps_set_identity(data, &s->dkey, s->dcert_len ? s->dcert : NULL, s->dcert_len);
        if (ftps_tls_handshake(data) != 0) {
            LOG_ERROR("data TLS handshake failed for %s %s", verb, arg);
            ftps_destroy(data);
            ftps_send_line(c, "425 Data TLS handshake failed");
            return;
        }
    }

    int ok = 0;
    if (is_list) {
        ok = list_directory(data, fp, is_mlsd);
    } else if (strcmp(verb, "RETR") == 0) {
        ok = send_file_data(data, fp);
    } else if (strcmp(verb, "STOR") == 0) {
        ok = recv_file_data(data, fp);
    }

    ftps_close(data);
    ftps_destroy(data);

    if (ok) {
        LOG_INFO("transfer ok: %s %s", verb, arg);
        ftps_send_line(c, "226 Transfer complete");
    } else {
        LOG_ERROR("transfer failed: %s %s", verb, arg);
        ftps_send_line(c, "550 Transfer failed");
    }
}

static int handle_session(FTPS_Conn *c, const char *root, int use_tls, int tls_version) {
    FTPS_Session s;
    memset(&s, 0, sizeof(s));
    s.root = root;
    s.type = 'I';
    s.prot = 'P';
    s.passive_port_start = g_config.passive_port_start;
    s.passive_port_end = g_config.passive_port_end;
    s.passive_port_counter = g_config.passive_port_start;
    s.use_tls = use_tls;
    s.tls_version = tls_version;

    if (g_has_identity) ftps_set_identity(c, &g_key, g_cert, g_cert_len);

    ftps_set_socket_timeout(c, g_config.control_timeout);

    if (use_tls) {
        ftps_set_tls_version(c, tls_version);
    }

    ftps_send_line(c, "220 ftps test server ready");

    char line[MAX_LINE];
    for (;;) {
        int n = ftps_recv_line(c, line, sizeof(line));
        if (n <= 0) break;

        char verb[64] = { 0 }, arg[2048] = { 0 };
        char *sp = strchr(line, ' ');
        if (sp) {
            size_t vl = (size_t)(sp - line);
            if (vl >= sizeof(verb)) vl = sizeof(verb) - 1;
            memcpy(verb, line, vl);
            verb[vl] = 0;
            while (*sp == ' ') sp++;
            snprintf(arg, sizeof(arg), "%s", sp);
        } else {
            snprintf(verb, sizeof(verb), "%s", line);
        }
        for (char *p = verb; *p; p++) *p = (char)toupper((unsigned char)*p);

        if (strcmp(verb, "AUTH") == 0) {
            if (strcmp(arg, "TLS") == 0) {
                if (!use_tls) {
                    ftps_send_line(c, "504 TLS not enabled on server");
                    continue;
                }
                ftps_send_line(c, "234 Starting TLS handshake");
                if (ftps_tls_handshake(c) != 0) {
                    LOG_ERROR("control TLS handshake failed for user %s", s.user);
                    break;
                }
                if (c->tls.has_rsa_key) {
                    memcpy(&s.dkey, &c->tls.static_rsa_key, sizeof(RSAKey));
                    s.has_dkey = 1;
                }
                if (c->tls.has_cert) {
                    memcpy(s.dcert, c->tls.cert, (size_t)c->tls.cert_len);
                    s.dcert_len = c->tls.cert_len;
                }
                LOG_INFO("TLS established for user %s", s.user);
            } else {
                ftps_send_line(c, "504 Unsupported auth type");
            }
            continue;
        }
        if (strcmp(verb, "USER") == 0) {
            snprintf(s.user, sizeof(s.user), "%s", arg);
            LOG_INFO("USER %s", s.user);
            ftps_send_line(c, "331 Password required for %s", s.user);
            continue;
        }
        if (strcmp(verb, "PASS") == 0) {
            if (strcmp(arg, g_config.password) == 0 && strcmp(s.user, g_config.username) == 0) {
                s.authed = 1;
                LOG_INFO("login ok: %s", s.user);
                ftps_send_line(c, "230 Logged in");
            } else {
                s.authed = 0;
                LOG_WARN("login failed: %s", s.user);
                ftps_send_line(c, "530 Login or password incorrect");
            }
            continue;
        }
        if (strcmp(verb, "SYST") == 0) { ftps_send_line(c, "215 UNIX Type: L8"); continue; }
        if (strcmp(verb, "NOOP") == 0) { ftps_send_line(c, "200 NOOP ok"); continue; }
        if (strcmp(verb, "FEAT") == 0) {
            ftps_send_line(c, "211-Features:");
            if (use_tls) {
                ftps_send_line(c, " AUTH TLS");
            }
            ftps_send_line(c, " PBSZ");
            ftps_send_line(c, " PROT");
            ftps_send_line(c, " PASV");
            ftps_send_line(c, " EPSV");
            ftps_send_line(c, " TYPE");
            ftps_send_line(c, " SIZE");
            ftps_send_line(c, " REST STREAM");
            ftps_send_line(c, " MLSD");
            ftps_send_line(c, " MLST type*;size*;modify*;");
            ftps_send_line(c, "211 End");
            continue;
        }
        if (strcmp(verb, "OPTS") == 0) { ftps_send_line(c, "200 OPTS ok"); continue; }
        if (strcmp(verb, "PBSZ") == 0) { ftps_send_line(c, "200 PBSZ=0 ok"); continue; }
        if (strcmp(verb, "PROT") == 0) {
            if (use_tls) {
                if (strcmp(arg, "P") == 0) { s.prot = 'P'; ftps_send_line(c, "200 Protection set to Private"); }
                else if (strcmp(arg, "C") == 0) { s.prot = 'C'; ftps_send_line(c, "200 Protection set to Clear"); }
                else ftps_send_line(c, "504 Unsupported PROT");
            } else {
                ftps_send_line(c, "200 Protection set to Clear");
            }
            continue;
        }
        if (strcmp(verb, "TYPE") == 0) {
            if (strcmp(arg, "I") == 0 || strcmp(arg, "A") == 0) { s.type = arg[0]; ftps_send_line(c, "200 Type set to %s", arg); }
            else ftps_send_line(c, "504 Unsupported TYPE");
            continue;
        }
        if (strcmp(verb, "PWD") == 0) {
            ftps_send_line(c, "257 \"/%s\" is current directory", s.cwd[0] ? s.cwd : "");
            continue;
        }
        if (strcmp(verb, "CWD") == 0) {
            char rel[1024];
            norm_path(rel, sizeof(rel), s.cwd, arg);
            char fp[1300];
            make_full_path(fp, sizeof(fp), s.root, rel);
            struct stat st;
            if (stat(fp, &st) != 0 || !(st.st_mode & S_IFDIR)) { ftps_send_line(c, "550 No such directory"); continue; }
            snprintf(s.cwd, sizeof(s.cwd), "%s", rel);
            LOG_INFO("CWD %s (user %s)", rel, s.user);
            ftps_send_line(c, "250 Directory changed to /%s", s.cwd);
            continue;
        }
        if (strcmp(verb, "SIZE") == 0) {
            char rel[1024];
            norm_path(rel, sizeof(rel), s.cwd, arg);
            if (rel[0] == '\0') { ftps_send_line(c, "550 Invalid path"); continue; }
            char fp[1300];
            make_full_path(fp, sizeof(fp), s.root, rel);
            struct stat st;
            if (stat(fp, &st) == 0) ftps_send_line(c, "213 %lld", (long long)st.st_size);
            else ftps_send_line(c, "550 File not found");
            continue;
        }
        if (strcmp(verb, "PASV") == 0) {
            if (use_tls && !c->tls_established) { ftps_send_line(c, "530 TLS required"); continue; }
            if (!s.authed) { ftps_send_line(c, "530 Not logged in"); continue; }
            uint16_t port;
            if (open_data_listener(&s, &port) != 0) {
                ftps_send_line(c, "425 Cannot open data port");
                continue;
            }
            uint32_t ip = 0; uint16_t cport = 0;
            if (ftps_getsockname(c, &ip, &cport) != 0) ip = 0;
            if (ip == 0) ip = 0x7F000001;
            ftps_send_line(c, "227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)",
                           (int)((ip >> 24) & 0xFF), (int)((ip >> 16) & 0xFF),
                           (int)((ip >> 8) & 0xFF), (int)(ip & 0xFF),
                           (int)((port >> 8) & 0xFF), (int)(port & 0xFF));
            continue;
        }
        if (strcmp(verb, "EPSV") == 0) {
            if (use_tls && !c->tls_established) { ftps_send_line(c, "530 TLS required"); continue; }
            if (!s.authed) { ftps_send_line(c, "530 Not logged in"); continue; }
            uint16_t port;
            if (open_data_listener(&s, &port) != 0) {
                ftps_send_line(c, "425 Cannot open data port");
                continue;
            }
            ftps_send_line(c, "229 Entering Extended Passive Mode (|||%u|)", (unsigned)port);
            continue;
        }
        if (strcmp(verb, "CDUP") == 0) {
            char rel[1024];
            norm_path(rel, sizeof(rel), s.cwd, "..");
            char fp[1300];
            make_full_path(fp, sizeof(fp), s.root, rel);
            struct stat st;
            if (stat(fp, &st) != 0 || !(st.st_mode & S_IFDIR)) { ftps_send_line(c, "550 No such directory"); continue; }
            snprintf(s.cwd, sizeof(s.cwd), "%s", rel);
            ftps_send_line(c, "250 Directory changed to /%s", s.cwd);
            continue;
        }
        if (strcmp(verb, "REST") == 0) {
            if (strtoull(arg, NULL, 10) == 0) ftps_send_line(c, "350 Restarting at 0");
            else ftps_send_line(c, "502 REST not supported");
            continue;
        }
        if (strcmp(verb, "MLST") == 0) {
            char rel[1024];
            norm_path(rel, sizeof(rel), s.cwd, arg);
            if (rel[0] == '\0') { ftps_send_line(c, "550 Invalid path"); continue; }
            char fp[1300];
            make_full_path(fp, sizeof(fp), s.root, rel);
            struct stat st;
            if (stat(fp, &st) != 0) { ftps_send_line(c, "550 File not found"); continue; }
            char ts[32] = "00000000000000";
            struct tm *tm = localtime(&st.st_mtime);
            if (tm) strftime(ts, sizeof(ts), "%Y%m%d%H%M%S", tm);
            ftps_send_line(c, "250-Listing /%s", rel);
            if (st.st_mode & S_IFDIR)
                ftps_send_line(c, " type=dir;modify=%s; /%s", ts, rel);
            else
                ftps_send_line(c, " type=file;size=%lld;modify=%s; /%s", (long long)st.st_size, ts, rel);
            ftps_send_line(c, "250 End");
            continue;
        }
        if (strcmp(verb, "LIST") == 0 || strcmp(verb, "MLSD") == 0 ||
            strcmp(verb, "RETR") == 0 || strcmp(verb, "STOR") == 0) {
            do_data_command(c, &s, verb, arg);
            continue;
        }
        if (strcmp(verb, "DELE") == 0) {
            if (use_tls && !c->tls_established) { ftps_send_line(c, "530 TLS required"); continue; }
            if (!s.authed) { ftps_send_line(c, "530 Not logged in"); continue; }
            char rel[1024];
            norm_path(rel, sizeof(rel), s.cwd, arg);
            if (rel[0] == '\0') { ftps_send_line(c, "550 Invalid path"); continue; }
            char fp[1300];
            make_full_path(fp, sizeof(fp), s.root, rel);
            struct stat st;
            if (stat(fp, &st) != 0 || (st.st_mode & S_IFDIR)) { ftps_send_line(c, "550 No such file"); continue; }
            if (remove(fp) != 0) { ftps_send_line(c, "550 Failed to delete"); continue; }
            LOG_INFO("deleted: %s", rel);
            ftps_send_line(c, "250 File deleted");
            continue;
        }
        if (strcmp(verb, "SITE") == 0) {
            if (use_tls && !c->tls_established) { ftps_send_line(c, "530 TLS required"); continue; }
            if (!s.authed) { ftps_send_line(c, "530 Not logged in"); continue; }
            char sub[32];
            if (sscanf(arg, "%31s", sub) != 1) { ftps_send_line(c, "501 Syntax error in SITE"); continue; }
            if (_stricmp(sub, "CHMOD") != 0) { ftps_send_line(c, "500 Unknown SITE command"); continue; }
            char *p = arg;
            while (*p == ' ') p++;
            while (*p && *p != ' ') p++;
            while (*p == ' ') p++;
            char *mode_start = p;
            while (*p && *p != ' ') p++;
            if (mode_start == p) { ftps_send_line(c, "501 Missing chmod mode"); continue; }
            char modebuf[8];
            size_t ml = (size_t)(p - mode_start);
            if (ml >= sizeof(modebuf)) ml = sizeof(modebuf) - 1;
            memcpy(modebuf, mode_start, ml); modebuf[ml] = 0;
            while (*p == ' ') p++;
            if (!*p) { ftps_send_line(c, "501 Missing path"); continue; }
            char rel[1024];
            norm_path(rel, sizeof(rel), s.cwd, p);
            if (rel[0] == '\0') { ftps_send_line(c, "550 Invalid path"); continue; }
            char fp[1300];
            make_full_path(fp, sizeof(fp), s.root, rel);
            struct stat st;
            if (stat(fp, &st) != 0 || (st.st_mode & S_IFDIR)) { ftps_send_line(c, "550 No such file"); continue; }
            long mode = strtol(modebuf, NULL, 8);
            if (mode & 0x0140) _chmod(fp, _S_IWRITE);
            else _chmod(fp, _S_IREAD);
            ftps_send_line(c, "200 Chmod ok (%lo)", mode);
            continue;
        }
        if (strcmp(verb, "MKD") == 0) {
            if (use_tls && !c->tls_established) { ftps_send_line(c, "530 TLS required"); continue; }
            if (!s.authed) { ftps_send_line(c, "530 Not logged in"); continue; }
            char rel[1024];
            norm_path(rel, sizeof(rel), s.cwd, arg);
            if (rel[0] == '\0') { ftps_send_line(c, "550 Invalid path"); continue; }
            char fp[1300];
            make_full_path(fp, sizeof(fp), s.root, rel);
            struct stat st;
            if (stat(fp, &st) == 0) { ftps_send_line(c, "550 Path exists"); continue; }
            if (_mkdir(fp) != 0) { ftps_send_line(c, "550 Cannot create directory"); continue; }
            LOG_INFO("created dir: %s", rel);
            ftps_send_line(c, "257 \"%s\" directory created", rel);
            continue;
        }
        if (strcmp(verb, "RMD") == 0) {
            if (use_tls && !c->tls_established) { ftps_send_line(c, "530 TLS required"); continue; }
            if (!s.authed) { ftps_send_line(c, "530 Not logged in"); continue; }
            char rel[1024];
            norm_path(rel, sizeof(rel), s.cwd, arg);
            if (rel[0] == '\0') { ftps_send_line(c, "550 Invalid path"); continue; }
            char fp[1300];
            make_full_path(fp, sizeof(fp), s.root, rel);
            struct stat st;
            if (stat(fp, &st) != 0 || !(st.st_mode & S_IFDIR)) { ftps_send_line(c, "550 No such directory"); continue; }
            if (_rmdir(fp) != 0) { ftps_send_line(c, "550 Cannot remove directory (not empty?)"); continue; }
            LOG_INFO("removed dir: %s", rel);
            ftps_send_line(c, "250 Directory removed");
            continue;
        }
        if (strcmp(verb, "RNFR") == 0) {
            if (use_tls && !c->tls_established) { ftps_send_line(c, "530 TLS required"); continue; }
            if (!s.authed) { ftps_send_line(c, "530 Not logged in"); continue; }
            char rel[1024];
            norm_path(rel, sizeof(rel), s.cwd, arg);
            if (rel[0] == '\0') { ftps_send_line(c, "550 Invalid path"); continue; }
            char fp[1300];
            make_full_path(fp, sizeof(fp), s.root, rel);
            struct stat st;
            if (stat(fp, &st) != 0) { ftps_send_line(c, "550 No such file or directory"); continue; }
            snprintf(s.rnfr, sizeof(s.rnfr), "%s", rel);
            s.has_rnfr = 1;
            ftps_send_line(c, "350 Rename source ready");
            continue;
        }
        if (strcmp(verb, "RNTO") == 0) {
            if (use_tls && !c->tls_established) { ftps_send_line(c, "530 TLS required"); continue; }
            if (!s.authed) { ftps_send_line(c, "530 Not logged in"); continue; }
            if (!s.has_rnfr) { ftps_send_line(c, "503 RNFR required first"); continue; }
            char rel[1024];
            norm_path(rel, sizeof(rel), s.cwd, arg);
            if (rel[0] == '\0') { ftps_send_line(c, "550 Invalid path"); continue; }
            char sfp[1300], dfp[1300];
            make_full_path(sfp, sizeof(sfp), s.root, s.rnfr);
            make_full_path(dfp, sizeof(dfp), s.root, rel);
            s.has_rnfr = 0;
            struct stat st;
            if (stat(dfp, &st) == 0) { ftps_send_line(c, "550 Destination exists"); continue; }
            if (rename(sfp, dfp) != 0) { ftps_send_line(c, "550 Rename failed"); continue; }
            LOG_INFO("renamed: %s -> %s", s.rnfr, rel);
            ftps_send_line(c, "250 Rename successful");
            continue;
        }
        if (strcmp(verb, "QUIT") == 0) {
            LOG_INFO("QUIT %s", s.user);
            ftps_send_line(c, "221 Bye");
            break;
        }
        LOG_INFO("unknown command: %s from %s", verb, s.user);
        ftps_send_line(c, "502 Command not implemented: %s", verb);
    }

    if (s.data_listener) ftps_destroy(s.data_listener);
    ftps_close(c);
    ftps_destroy(c);
    return 0;
}

int main(int argc, char *argv[]) {
    printf("FTPS server starting...\n");
    fflush(stdout);
    
    const char *config_path = "config.json";

    config_defaults();

    if (argc > 1) {
        char *endptr;
        long port_val = strtol(argv[1], &endptr, 10);
        if (*endptr == '\0') {
            if (port_val > 0 && port_val < 65536) g_config.port = (int)port_val;
        } else {
            config_path = argv[1];
            config_defaults();
        }
    }
    if (argc > 2) {
        strncpy(g_config.root, argv[2], sizeof(g_config.root) - 1);
        g_config.root[sizeof(g_config.root) - 1] = 0;
    }

    load_config(config_path);
    int errors = validate_config();
    if (errors > 0) {
        LOG_ERROR("config has %d error(s), using defaults for invalid values", errors);
    }

    log_init(g_config.log_output);

    LOG_INFO("=== FTPS server starting ===");
    LOG_INFO("port: %d", g_config.port);
    LOG_INFO("root: %s", g_config.root);
    LOG_INFO("passive ports: %d-%d", g_config.passive_port_start, g_config.passive_port_end);
    LOG_INFO("control_timeout: %ds, data_timeout: %ds, pasv_timeout: %ds",
             g_config.control_timeout, g_config.data_timeout, g_config.pasv_timeout);
    LOG_INFO("username: %s, tls: %s", g_config.username, g_config.use_tls ? "enabled" : "disabled");

    FTPS_Conn *ctl = ftps_create();
    if (!ctl) {
        LOG_ERROR("failed to create FTPS control connection");
        log_close();
        return 1;
    }
    if (ftps_listen(ctl, NULL, g_config.port) != 0) {
        LOG_ERROR("cannot listen on port %d", g_config.port);
        ftps_destroy(ctl);
        log_close();
        return 1;
    }
    LOG_INFO("listening on port %d", g_config.port);

    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    uint8_t keyder[TLS_RSA_MAX_CERT_SIZE];
    int keyder_len = 0;
    RSAKey pub;
    if (g_config.use_tls) {
        if (tls_pem_to_der(g_config.cert_file, g_cert, &g_cert_len, (int)sizeof(g_cert)) == 0 &&
            tls_pem_to_der(g_config.key_file, keyder, &keyder_len, (int)sizeof(keyder)) == 0 &&
            tls_rsa_parse_private_der(&g_key, keyder, keyder_len) == 0 &&
            tls_rsa_parse_public_der(&pub, g_cert, g_cert_len) == 0 &&
            memcmp(pub.n, g_key.n, TLS_RSA_MODULUS_BYTES) == 0) {
            g_has_identity = 1;
            LOG_INFO("loaded server identity from %s / %s", g_config.cert_file, g_config.key_file);
        } else {
            LOG_WARN("could not load %s/%s - generating self-signed cert", g_config.cert_file, g_config.key_file);
        }

        const char *ver_str = (g_config.tls_version == 1) ? "1.2" : (g_config.tls_version == 2) ? "1.3" : "auto";
        LOG_INFO("tls_version: %s", ver_str);
    }

    const char *log_str = (g_config.log_output == 1) ? "console" : (g_config.log_output == 2) ? "file" : "both";
    LOG_INFO("log_output: %s (%d)", log_str, g_config.log_output);

    for (;;) {
        FTPS_Conn *client = ftps_accept(ctl);
        if (!client) continue;
        LOG_INFO("client connected");
        handle_session(client, g_config.root, g_config.use_tls, g_config.tls_version);
        LOG_INFO("client disconnected");
    }

    ftps_destroy(ctl);
    log_close();
    return 0;
}
