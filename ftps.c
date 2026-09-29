/*
 * Git: https://github.com/crypery
 * Author: https://crypery.com
 * License: GNU AGPL v3 (Affero GPL)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "ftps.h"

#ifdef _WIN32
static int ftps_wsa_ready = 0;
static void ftps_ensure_wsa(void) {
    if (!ftps_wsa_ready) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
        ftps_wsa_ready = 1;
    }
}
#else
#include <signal.h>
#endif

static int raw_send_pending(ftps_socket_t fd, const uint8_t *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int r = (int)send(fd, (const char *)(buf + sent), len - sent, 0);
        if (r <= 0) return -1;
        sent += r;
    }
    return sent;
}

/* ============================= TCP ============================= */

FTPS_Conn *ftps_create(void) {
#ifdef _WIN32
    ftps_ensure_wsa();
#else
    signal(SIGPIPE, SIG_IGN);
#endif
    FTPS_Conn *c = (FTPS_Conn *)calloc(1, sizeof(FTPS_Conn));
    if (!c) return NULL;
    c->fd = FTPS_INVALID_SOCKET;
    c->is_server = 0;
    c->tls_version = TLS_VERSION_AUTO;
    return c;
}

void ftps_set_tls_version(FTPS_Conn *c, int version) { c->tls_version = version; }

int ftps_connect(FTPS_Conn *c, const char *host, int port) {
    struct hostent *server;
    struct sockaddr_in a;

    c->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (c->fd == FTPS_INVALID_SOCKET) return -1;

    server = gethostbyname(host);
    if (!server) return -1;

    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    memcpy(&a.sin_addr.s_addr, server->h_addr, (size_t)server->h_length);
    a.sin_port = htons((uint16_t)port);

    if (connect(c->fd, (struct sockaddr *)&a, sizeof(a)) < 0) return -1;
    c->is_server = 0;
    return 0;
}

int ftps_listen(FTPS_Conn *c, const char *bind_ip, int port) {
    struct sockaddr_in a;
    int enable = 1;

    c->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (c->fd == FTPS_INVALID_SOCKET) return -1;

    setsockopt(c->fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&enable, sizeof(enable));

    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    a.sin_addr.s_addr = bind_ip ? inet_addr(bind_ip) : INADDR_ANY;

    if (bind(c->fd, (struct sockaddr *)&a, sizeof(a)) < 0) return -1;
    if (listen(c->fd, 8) < 0) return -1;
    return 0;
}

int ftps_get_local(FTPS_Conn *c, uint32_t *ip, uint16_t *port) {
    struct sockaddr_in a;
    socklen_t len = sizeof(a);
    if (getsockname(c->fd, (struct sockaddr *)&a, &len) < 0) return -1;
    if (ip) *ip = ntohl(a.sin_addr.s_addr);
    if (port) *port = ntohs(a.sin_port);
    return 0;
}

/* Local address of an accepted/connected socket. For a connection accepted on
 * an INADDR_ANY listener this returns the concrete interface address, which is
 * what PASV should advertise so a remote client can reach the data listener. */
int ftps_getsockname(FTPS_Conn *c, uint32_t *ip, uint16_t *port) {
    return ftps_get_local(c, ip, port);
}

FTPS_Conn *ftps_accept(FTPS_Conn *l) {
    struct sockaddr_in a;
    socklen_t len = sizeof(a);
    ftps_socket_t fd = accept(l->fd, (struct sockaddr *)&a, &len);
    if (fd == FTPS_INVALID_SOCKET) return NULL;

    FTPS_Conn *c = ftps_create();
    if (!c) {
        closesocket(fd);
        return NULL;
    }
    c->fd = fd;
    c->is_server = 1;
    return c;
}

int ftps_set_socket_timeout(FTPS_Conn *c, int secs) {
    if (!c || c->fd == FTPS_INVALID_SOCKET || secs < 0) return -1;
    struct timeval tv;
    tv.tv_sec = secs;
    tv.tv_usec = 0;
    setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(c->fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
    return 0;
}

int ftps_wait_in(FTPS_Conn *c, int timeout_ms) {
    if (!c || c->fd == FTPS_INVALID_SOCKET || timeout_ms < 0) return -1;
    if (timeout_ms > 30000) timeout_ms = 30000;
    fd_set rf;
    FD_ZERO(&rf);
    FD_SET(c->fd, &rf);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    return select((int)c->fd + 1, &rf, NULL, NULL, &tv);
}

void ftps_destroy(FTPS_Conn *c) {
    if (!c) return;
    if (c->fd != FTPS_INVALID_SOCKET) {
#ifdef _WIN32
        shutdown(c->fd, SD_BOTH);
        closesocket(c->fd);
#else
        shutdown(c->fd, SHUT_RDWR);
        close(c->fd);
#endif
        c->fd = FTPS_INVALID_SOCKET;
    }
    free(c);
}

int ftps_close(FTPS_Conn *c) {
    if (!c || !c->tls_on || !c->tls_established) return 0;
    uint8_t buf[FTPS_BUF];
    int len = 0;
    if (tls_close(&c->tls, buf, &len) != 0 || len <= 0) return -1;
    return (raw_send_pending(c->fd, buf, len) == len) ? 0 : -1;
}

/* ============================= TLS ============================= */

int ftps_set_identity(FTPS_Conn *c, const RSAKey *key, const uint8_t *cert, int cert_len) {
    if (!c || !key || cert_len < 0 || cert_len > TLS_RSA_MAX_CERT_SIZE) return -1;
    memcpy(&c->identity_key, key, sizeof(RSAKey));
    c->has_identity_key = 1;
    if (cert && cert_len > 0) {
        memcpy(c->identity_cert, cert, (size_t)cert_len);
        c->identity_cert_len = cert_len;
    } else {
        c->identity_cert_len = 0;
    }
    return 0;
}

int ftps_tls_handshake(FTPS_Conn *c) {
    if (c->tls_established) return 0;

    tls_init_context(&c->tls, c->is_server, c->tls_version);
    if (c->has_identity_key) tls_set_rsa_key(&c->tls, &c->identity_key);
    if (c->identity_cert_len > 0) tls_set_certificate(&c->tls, c->identity_cert, c->identity_cert_len);

    for (;;) {
        int rc = tls_handshake_step(&c->tls, c->hs_in, c->hs_in_len, c->out_buf, &c->out_len);

        if (c->out_len > 0) {
            if (raw_send_pending(c->fd, c->out_buf, c->out_len) != c->out_len) return -1;
        }

        if (rc == TLS_RSA_OK) {
            c->tls_on = 1;
            c->tls_established = 1;
            /* The TLS layer stashes any bytes the peer sent immediately after
             * its final handshake message in recv_buffer (e.g. the first record
             * of a STOR payload, or an early command). ftps_recv() only reads the
             * socket, so those bytes must be moved into the raw record buffer now,
             * otherwise a burst upload is seen as an immediate EOF -> 0-byte file. */
            uint32_t leftover = c->tls.recv_buffer.len;
            if (leftover > 0) {
                uint32_t avail = leftover;
                if (avail > (uint32_t)(sizeof(c->rbuf) - c->rbuf_len))
                    avail = (uint32_t)(sizeof(c->rbuf) - c->rbuf_len);
                memcpy(c->rbuf + c->rbuf_len, c->tls.recv_buffer.data, (size_t)avail);
                c->rbuf_len += (int32_t)avail;
                memmove(c->tls.recv_buffer.data,
                        c->tls.recv_buffer.data + avail,
                        (size_t)(c->tls.recv_buffer.len - avail));
                c->tls.recv_buffer.len -= avail;
            }
            c->hs_in_len = 0;
            return 0;
        }
        if (rc == TLS_RSA_ERROR) return -1;
        if (rc == TLS_RSA_HANDSHAKE_DONE) {
            /* this step consumed all buffered handshake input */
            c->hs_in_len = 0;
        }

        /* NEED_MORE_DATA: keep buffered input and read more */
        int room = (int)sizeof(c->hs_in) - c->hs_in_len;
        if (room <= 0) return -1;
        int n = (int)recv(c->fd, (char *)(c->hs_in + c->hs_in_len), room, 0);
        if (n <= 0) return -1;
        c->hs_in_len += n;
    }
}

/* ========================= Transport ============================ */

int ftps_send(FTPS_Conn *c, const void *data, int len) {
    if (!c->tls_on) {
        return raw_send_pending(c->fd, (const uint8_t *)data, len) == len ? 0 : -1;
    }
    const uint8_t *p = (const uint8_t *)data;
    int off = 0;
    int maxchunk = TLS_RSA_MAX_BUFFER - 17;   /* largest plaintext that fits one TLS record */
    while (off < len) {
        int chunk = len - off;
        if (chunk > maxchunk) chunk = maxchunk;
        uint8_t enc[FTPS_BUF];
        int enc_len;
        if (tls_send_application_data(&c->tls, p + off, chunk, enc, &enc_len) != 0) return -1;
        if (raw_send_pending(c->fd, enc, enc_len) != enc_len) return -1;
        off += chunk;
    }
    return 0;
}

/* ensure at least `need` raw bytes are buffered in rbuf */
static int ensure_raw(FTPS_Conn *c, int need) {
    while (c->rbuf_len < need) {
        int n = (int)recv(c->fd, (char *)(c->rbuf + c->rbuf_len),
                          (int)sizeof(c->rbuf) - c->rbuf_len, 0);
        if (n == 0) return -2;   /* clean close */
        if (n < 0) return -1;
        c->rbuf_len += n;
    }
    return 0;
}

int ftps_recv(FTPS_Conn *c, void *buf, int buflen) {
    if (!c->tls_on) {
        int n = (int)recv(c->fd, (char *)buf, buflen, 0);
        if (n < 0) return -1;
        return n;
    }

    /* deliver pending decrypted plaintext first */
    if (c->pbuf_len > c->pbuf_pos) {
        int n = c->pbuf_len - c->pbuf_pos;
        if (n > buflen) n = buflen;
        memcpy(buf, c->pbuf + c->pbuf_pos, (size_t)n);
        c->pbuf_pos += n;
        if (c->pbuf_pos >= c->pbuf_len) { c->pbuf_len = 0; c->pbuf_pos = 0; }
        return n;
    }

    for (;;) {
        int r = ensure_raw(c, 5);
        if (r < 0) return (r == -2) ? 0 : -1;

        uint8_t type = c->rbuf[0];
        int rec_len = (c->rbuf[3] << 8) | c->rbuf[4];
        int total = 5 + rec_len;
        if (total > (int)sizeof(c->rbuf)) return -1;

        r = ensure_raw(c, total);
        if (r < 0) return (r == -2) ? 0 : -1;

        if (type == TLS_RSA_ALERT) {
            c->rbuf_len -= total;
            memmove(c->rbuf, c->rbuf + total, (size_t)c->rbuf_len);
            return 0;   /* treat alert (close_notify) as clean close */
        }

        if (type == TLS_RSA_APPLICATION_DATA) {
            int dec_len;
            int rc = tls_receive_application_data(&c->tls, c->rbuf, total, c->pbuf, &dec_len);
            c->rbuf_len -= total;
            memmove(c->rbuf, c->rbuf + total, (size_t)c->rbuf_len);
            if (rc == TLS_RSA_CLOSED) return 0;   /* encrypted close_notify (TLS 1.3) */
            if (rc != 0 || dec_len <= 0) continue;
            c->pbuf_len = dec_len;
            c->pbuf_pos = 0;
            int n = dec_len;
            if (n > buflen) n = buflen;
            memcpy(buf, c->pbuf, (size_t)n);
            c->pbuf_pos = n;
            return n;
        }

        /* handshake/CCS records after handshake: skip */
        c->rbuf_len -= total;
        memmove(c->rbuf, c->rbuf + total, (size_t)c->rbuf_len);
    }
}

/* ====================== FTP control lines ======================= */

int ftps_send_line(FTPS_Conn *c, const char *fmt, ...) {
    char line[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);

    size_t len = strlen(line);
    char out[2048 + 2];
    if (len > sizeof(out) - 3) len = sizeof(out) - 3;
    memcpy(out, line, len);
    out[len++] = '\r';
    out[len++] = '\n';
    return ftps_send(c, out, (int)len);
}

int ftps_recv_line(FTPS_Conn *c, char *buf, int buflen) {
    int pos = 0;
    for (;;) {
        char ch;
        int r = ftps_recv(c, &ch, 1);
        if (r < 0) return -1;
        if (r == 0) break;
        if (ch == '\n') break;
        if (ch == '\r') continue;
        if (pos < buflen - 1) buf[pos++] = ch;
    }
    buf[pos] = 0;
    return pos;
}
