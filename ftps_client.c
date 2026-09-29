/*
 * Git: https://github.com/crypery
 * Author: https://crypery.com
 * License: GNU AGPL v3 (Affero GPL)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ftps.h"

#define MAX_LINE 4096

static int parse_pasv(const char *line, int *port) {
    const char *p = strchr(line, '(');
    if (!p) return -1;
    int h1, h2, h3, h4, p1, p2;
    if (sscanf(p, "(%d,%d,%d,%d,%d,%d)", &h1, &h2, &h3, &h4, &p1, &p2) != 6) return -1;
    *port = p1 * 256 + p2;
    return 0;
}

static int reply(FTPS_Conn *c, char *buf, int buflen) {
    int n = ftps_recv_line(c, buf, buflen);
    if (n < 0) return -1;
    printf("%s\n", buf);
    return 0;
}

static int expect(FTPS_Conn *c, char *buf, int buflen, const char *prefix) {
    if (reply(c, buf, buflen) != 0) return -1;
    return (strncmp(buf, prefix, strlen(prefix)) == 0) ? 0 : -1;
}

/* request a passive-mode port (no connection yet) */
static int pasv_port(FTPS_Conn *c, char *buf, int buflen, int *port) {
    ftps_send_line(c, "PASV");
    if (reply(c, buf, buflen) != 0) return -1;
    if (parse_pasv(buf, port) != 0) { printf("bad PASV reply\n"); return -1; }
    return 0;
}

/* connect the passive data port and run the TLS handshake (after "150") */
static FTPS_Conn *open_data_after_150(FTPS_Conn *c, const char *host, int port) {
    (void)c;
    FTPS_Conn *d = ftps_create();
    if (!d || ftps_connect(d, host, port) != 0) { ftps_destroy(d); return NULL; }
    if (ftps_tls_handshake(d) != 0) { printf("data TLS handshake failed\n"); ftps_destroy(d); return NULL; }
    return d;
}

static int do_list(FTPS_Conn *c, const char *host) {
    char buf[MAX_LINE];
    int port;
    if (pasv_port(c, buf, sizeof(buf), &port) != 0) return -1;
    ftps_send_line(c, "LIST");
    if (expect(c, buf, sizeof(buf), "150") != 0) return -1;
    FTPS_Conn *d = open_data_after_150(c, host, port);
    if (!d) return -1;
    char out[8192];
    int n;
    while ((n = ftps_recv(d, out, sizeof(out) - 1)) > 0) {
        out[n] = 0;
        fputs(out, stdout);
    }
    ftps_destroy(d);
    if (reply(c, buf, sizeof(buf)) != 0) return -1;
    return 0;
}

static int do_get(FTPS_Conn *c, const char *host, const char *remote, const char *local) {
    char buf[MAX_LINE];
    int port;
    if (pasv_port(c, buf, sizeof(buf), &port) != 0) return -1;
    ftps_send_line(c, "RETR %s", remote);
    if (expect(c, buf, sizeof(buf), "150") != 0) return -1;
    FTPS_Conn *d = open_data_after_150(c, host, port);
    if (!d) return -1;
    FILE *f = fopen(local, "wb");
    if (!f) { ftps_destroy(d); return -1; }
    char out[16384];
    int n;
    while ((n = ftps_recv(d, out, sizeof(out))) > 0) {
        if (fwrite(out, 1, (size_t)n, f) != (size_t)n) break;
    }
    fclose(f);
    ftps_destroy(d);
    if (reply(c, buf, sizeof(buf)) != 0) return -1;
    printf("saved to %s\n", local);
    return 0;
}

static int do_put(FTPS_Conn *c, const char *host, const char *local, const char *remote) {
    char buf[MAX_LINE];
    int port;
    if (pasv_port(c, buf, sizeof(buf), &port) != 0) return -1;
    ftps_send_line(c, "STOR %s", remote);
    if (expect(c, buf, sizeof(buf), "150") != 0) return -1;
    FTPS_Conn *d = open_data_after_150(c, host, port);
    if (!d) return -1;
    FILE *f = fopen(local, "rb");
    if (!f) { ftps_destroy(d); return -1; }
    char in[16384];
    int n;
    while ((n = (int)fread(in, 1, sizeof(in), f)) > 0) {
        if (ftps_send(d, in, n) != 0) break;
    }
    fclose(f);
    /* Graceful close: send close_notify so the server sees our data followed by
     * a clean TLS end-of-stream, instead of an aborted (possible discard) close. */
    ftps_close(d);
    ftps_destroy(d);
    if (reply(c, buf, sizeof(buf)) != 0) return -1;
    printf("uploaded %s\n", remote);
    return 0;
}

int main(int argc, char *argv[]) {
    const char *host = "localhost";
    int port = 2121;
    const char *user = "ftpuser";
    const char *pass = "ftppass";
    const char *cmd = "list";

    if (argc >= 3) { host = argv[1]; port = atoi(argv[2]); }
    if (argc >= 4) user = argv[3];
    if (argc >= 5) pass = argv[4];
    if (argc >= 6) cmd = argv[5];

    setvbuf(stdout, NULL, _IOLBF, 0);

    FTPS_Conn *c = ftps_create();
    if (!c || ftps_connect(c, host, port) != 0) {
        fprintf(stderr, "cannot connect to %s:%d\n", host, port);
        return 1;
    }

    char buf[MAX_LINE];
    if (expect(c, buf, sizeof(buf), "220") != 0) { fprintf(stderr, "no greeting\n"); return 1; }

    /* upgrade control connection to TLS (explicit FTPS) */
    ftps_send_line(c, "AUTH TLS");
    if (expect(c, buf, sizeof(buf), "234") != 0) { fprintf(stderr, "server refused AUTH TLS\n"); return 1; }
    if (ftps_tls_handshake(c) != 0) {
        fprintf(stderr, "control TLS handshake failed\n");
        return 1;
    }
    printf("TLS established (control channel)\n");

    ftps_send_line(c, "USER %s", user);
    if (expect(c, buf, sizeof(buf), "331") != 0) return 1;
    ftps_send_line(c, "PASS %s", pass);
    if (expect(c, buf, sizeof(buf), "230") != 0) return 1;

    ftps_send_line(c, "PBSZ 0");
    if (expect(c, buf, sizeof(buf), "200") != 0) return 1;
    ftps_send_line(c, "PROT P");
    if (expect(c, buf, sizeof(buf), "200") != 0) return 1;
    printf("protection: private (TLS data channel)\n");

    int rc = 0;
    if (strcmp(cmd, "list") == 0) {
        rc = do_list(c, host);
    } else if (strcmp(cmd, "get") == 0) {
        const char *remote = (argc >= 7) ? argv[6] : "hello.txt";
        const char *local = (argc >= 8) ? argv[7] : remote;
        rc = do_get(c, host, remote, local);
    } else if (strcmp(cmd, "put") == 0) {
        const char *local = (argc >= 7) ? argv[6] : "hello.txt";
        const char *remote = (argc >= 8) ? argv[7] : local;
        rc = do_put(c, host, local, remote);
    } else {
        fprintf(stderr, "unknown command %s (list|get|put)\n", cmd);
        rc = -1;
    }

    ftps_send_line(c, "QUIT");
    reply(c, buf, sizeof(buf));
    ftps_destroy(c);
    return rc;
}
