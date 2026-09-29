/*
 * Git: https://github.com/crypery
 * Author: https://crypery.com
 * License: GNU AGPL v3 (Affero GPL)
 */

#ifndef FTPS_H
#define FTPS_H

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
    #include <winsock2.h>
    #pragma comment (lib, "ws2_32.lib")
    typedef SOCKET ftps_socket_t;
    typedef int socklen_t;
    #define FTPS_INVALID_SOCKET INVALID_SOCKET
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netdb.h>
    #include <unistd.h>
    typedef int ftps_socket_t;
    #define FTPS_INVALID_SOCKET (-1)
    #define closesocket(x) close(x)
#endif

#include "tls.h"

#define FTPS_BUF (64 * 1024)

/* FTPS_Conn is a TLS-capable stream connection:
 *   - control and data connections of FTPS both use it;
 *   - before "AUTH TLS" the connection is plain TCP,
 *   - after ftps_tls_handshake() all I/O goes over TLS 1.2 (ECDHE-RSA-AES128-GCM-SHA256).
 */
typedef struct ftps_conn {
    int is_server;                 /* 0 = client, 1 = server (TLS role) */
    ftps_socket_t fd;
    TLSContext tls;
    int tls_on;                    /* TLS layer active */
    int tls_established;           /* TLS handshake completed */
    uint8_t hs_in[FTPS_BUF];       /* handshake input accumulation */
    int hs_in_len;
    uint8_t rbuf[FTPS_BUF];        /* raw TLS record bytes received but not yet decrypted */
    int rbuf_len;
    uint8_t pbuf[FTPS_BUF];        /* decrypted plaintext pending delivery */
    int pbuf_len;
    int pbuf_pos;
    uint8_t out_buf[FTPS_BUF];
    int out_len;
    RSAKey identity_key;             /* optional pre-loaded server identity */
    int has_identity_key;
    uint8_t identity_cert[TLS_RSA_MAX_CERT_SIZE];
    int identity_cert_len;
    int tls_version;               /* TLS_VERSION_AUTO / _12 / _13 */
    void *user;                    /* app-defined per-connection state */
} FTPS_Conn;

/* --- TCP ------------------------------------------------------------- */

/* Create a connection object (also initialises WinSock once). */
FTPS_Conn *ftps_create(void);

/* TCP connect (client role). */
int ftps_connect(FTPS_Conn *c, const char *host, int port);

/* Bind + listen. port 0 selects an ephemeral port. bind_ip may be NULL. */
int ftps_listen(FTPS_Conn *c, const char *bind_ip, int port);

/* Local bound address of a listener (for PASV). */
int ftps_get_local(FTPS_Conn *c, uint32_t *ip, uint16_t *port);

/* Local address of an accepted/connected socket (concrete interface).
 * Use to advertise a reachable IP for PASV/EPSV. */
int ftps_getsockname(FTPS_Conn *c, uint32_t *ip, uint16_t *port);

/* Accept a pending connection (returns a new object, server role). */
FTPS_Conn *ftps_accept(FTPS_Conn *listener);

/* Set recv/send timeouts (seconds) on the socket so no blocking I/O can hang
 * the single-threaded server forever. -1 leaves the socket unchanged. */
int ftps_set_socket_timeout(FTPS_Conn *c, int secs);

/* Poll the socket for readability. Returns 1 if readable, 0 on timeout,
 * -1 on error. Use before a blocking accept/recv to bound the wait. */
int ftps_wait_in(FTPS_Conn *c, int timeout_ms);

/* Shut down + close socket and free the object. */
void ftps_destroy(FTPS_Conn *c);

/* Send a TLS close_notify alert so the peer sees a graceful closure instead
 * of "The TLS connection was non-properly terminated". No-op if TLS is off
 * or not yet established. Call before ftps_destroy(). */
int ftps_close(FTPS_Conn *c);

/* --- TLS ------------------------------------------------------------- */

/* Run the TLS 1.2 handshake on this connection (client or server role
 * according to is_server). Returns 0 on success, -1 on failure. */
int ftps_tls_handshake(FTPS_Conn *c);

/* Install a pre-loaded RSA private key + certificate as the server identity
 * (used by the TLS handshake on this connection). */
int ftps_set_identity(FTPS_Conn *c, const RSAKey *key, const uint8_t *cert, int cert_len);

/* Set the TLS protocol selection (TLS_VERSION_AUTO / TLS_VERSION_12 /
 * TLS_VERSION_13) used by the handshake on this connection. Call before
 * ftps_tls_handshake(). Defaults to TLS_VERSION_AUTO. */
void ftps_set_tls_version(FTPS_Conn *c, int version);

/* --- Transport ------------------------------------------------------- */

/* Send len bytes (plain or TLS depending on state). Returns 0 / -1. */
int ftps_send(FTPS_Conn *c, const void *data, int len);

/* Receive up to buflen bytes. Returns bytes read, 0 on clean close, -1 on error.
 * In TLS mode the record layer is transparently reassembled. */
int ftps_recv(FTPS_Conn *c, void *buf, int buflen);

/* --- FTP control-line helpers ---------------------------------------- */

/* Send a "xxx ...\r\n" line. */
int ftps_send_line(FTPS_Conn *c, const char *fmt, ...);

/* Read one CRLF-terminated line (CR stripped). Returns line length or -1. */
int ftps_recv_line(FTPS_Conn *c, char *buf, int buflen);

#endif
