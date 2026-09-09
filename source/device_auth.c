// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_auth.h"

#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "socket.h"

union u_sockaddr {
    struct sockaddr addr;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
};

// Same conversion as socket_impl.c's convert_sockaddr(), kept local since
// this client doesn't otherwise touch struct socket_impl/its per-conn array
// (those MOBILE_MAX_CONNECTIONS slots are reserved for the emulated game).
static struct sockaddr *convert_sockaddr(socklen_t *addrlen, union u_sockaddr *u_addr, const struct mobile_addr *addr)
{
    if (addr->type == MOBILE_ADDRTYPE_IPV4) {
        const struct mobile_addr4 *addr4 = (struct mobile_addr4 *)addr;
        memset(&u_addr->addr4, 0, sizeof(u_addr->addr4));
        u_addr->addr4.sin_family = AF_INET;
        u_addr->addr4.sin_port = htons(addr4->port);
        memcpy(&u_addr->addr4.sin_addr.s_addr, addr4->host,
            sizeof(struct in_addr));
        *addrlen = sizeof(struct sockaddr_in);
        return &u_addr->addr;
    } else if (addr->type == MOBILE_ADDRTYPE_IPV6) {
        const struct mobile_addr6 *addr6 = (struct mobile_addr6 *)addr;
        memset(&u_addr->addr6, 0, sizeof(u_addr->addr6));
        u_addr->addr6.sin6_family = AF_INET6;
        u_addr->addr6.sin6_port = htons(addr6->port);
        memcpy(&u_addr->addr6.sin6_addr.s6_addr, addr6->host,
            sizeof(struct in6_addr));
        *addrlen = sizeof(struct sockaddr_in6);
        return &u_addr->addr;
    }
    *addrlen = 0;
    return NULL;
}

static bool is_unreserved(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return true;
    if (c >= 'a' && c <= 'z') return true;
    if (c >= '0' && c <= '9') return true;
    return c == '-' || c == '_' || c == '.' || c == '~';
}

// Percent-encodes <ppp_id> into <out>, which must have room for at least
// ppp_id_size * 3 bytes. ppp_id is an arbitrary, non-NUL-terminated byte
// string as far as the protocol is concerned, so this doesn't assume it's
// already URL-safe.
static unsigned encode_ppp_id(char *out, const unsigned char *ppp_id, unsigned ppp_id_size)
{
    static const char hex[] = "0123456789ABCDEF";
    unsigned pos = 0;
    for (unsigned i = 0; i < ppp_id_size; i++) {
        unsigned char c = ppp_id[i];
        if (is_unreserved(c)) {
            out[pos++] = (char)c;
        } else {
            out[pos++] = '%';
            out[pos++] = hex[c >> 4];
            out[pos++] = hex[c & 0xf];
        }
    }
    return pos;
}

static unsigned encode_hex(char *out, const unsigned char *data, unsigned size)
{
    static const char hex[] = "0123456789abcdef";
    for (unsigned i = 0; i < size; i++) {
        out[i * 2] = hex[data[i] >> 4];
        out[i * 2 + 1] = hex[data[i] & 0xf];
    }
    return size * 2;
}

static struct device_auth_request *find_free_slot(struct device_auth_state *state)
{
    for (unsigned i = 0; i < DEVICE_AUTH_MAX_PENDING; i++) {
        if (state->pending[i].sock == INVALID_SOCKET) return &state->pending[i];
    }
    return NULL;
}

static void request_close(struct device_auth_request *req)
{
    socket_close(req->sock);
    req->sock = INVALID_SOCKET;
}

// Reports failure for a query awaiting mobile_device_auth_query_result()
// (a no-op for anything else), then closes. Every way a request can end
// without a clean 200 response goes through here, so the core always gets
// exactly one answer per accepted mobile_func_device_auth_query() call.
static void request_fail(struct device_auth_request *req)
{
    if (req->is_query) mobile_device_auth_query_result(req->adapter, NULL, 0);
    request_close(req);
}

void device_auth_init(struct device_auth_state *state)
{
    for (unsigned i = 0; i < DEVICE_AUTH_MAX_PENDING; i++) {
        state->pending[i].sock = INVALID_SOCKET;
    }
}

void device_auth_stop(struct device_auth_state *state)
{
    for (unsigned i = 0; i < DEVICE_AUTH_MAX_PENDING; i++) {
        if (state->pending[i].sock != INVALID_SOCKET) request_fail(&state->pending[i]);
    }
}

// Opens a non-blocking socket and starts connecting it to the device-auth
// server, filling <host> (at least SOCKET_STRADDR_MAXLEN bytes) with its
// address for the Host: header. Returns INVALID_SOCKET on failure.
static SOCKET device_auth_connect(const unsigned char *addr_ipv4, char *host, unsigned host_size)
{
    struct mobile_addr4 addr = {
        .type = MOBILE_ADDRTYPE_IPV4,
        .port = DEVICE_AUTH_DEFAULT_PORT,
    };
    memcpy(addr.host, addr_ipv4, sizeof(addr.host));

    union u_sockaddr u_addr;
    socklen_t sock_addrlen;
    struct sockaddr *sock_addr = convert_sockaddr(&sock_addrlen, &u_addr,
        (struct mobile_addr *)&addr);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        socket_perror("[device-auth] socket");
        return INVALID_SOCKET;
    }
    if (socket_setblocking(sock, 0) == -1) {
        socket_close(sock);
        return INVALID_SOCKET;
    }

    socket_straddr(host, host_size, sock_addr, sock_addrlen);

    // Kick off the (non-blocking) connect right away; device_auth_poll()
    // will pick up on its progress from here.
    connect(sock, sock_addr, sock_addrlen);
    return sock;
}

void device_auth_notify(struct device_auth_state *state, enum mobile_device_auth_action action, const unsigned char *ppp_id, unsigned ppp_id_size, uint64_t counter, const unsigned char *sig, const unsigned char *addr_ipv4, const char *device)
{
    if (ppp_id_size > 0x20) return;

    struct device_auth_request *req = find_free_slot(state);
    if (!req) {
        fprintf(stderr, "[device-auth] Too many requests in flight, dropping one\n");
        return;
    }

    char host[SOCKET_STRADDR_MAXLEN] = {0};
    SOCKET sock = device_auth_connect(addr_ipv4, host, sizeof(host));
    if (sock == INVALID_SOCKET) return;

    // Build the request line/headers directly into the pending slot.
    char *p = req->data;
    char *end = req->data + sizeof(req->data);
    p += snprintf(p, (size_t)(end - p), "GET /api/adapter/device-auth?ppp_id=");
    p += encode_ppp_id(p, ppp_id, ppp_id_size);
    if (device) p += snprintf(p, (size_t)(end - p), "&device=%s", device);
    p += snprintf(p, (size_t)(end - p), "&action=%s&counter=%" PRIu64 "&sig=",
        action == MOBILE_DEVICE_AUTH_AUTHORIZE ? "authorize" : "deauthorize",
        counter);
    p += encode_hex(p, sig, MOBILE_DEVICE_AUTH_SIG_SIZE);
    unsigned line_len = (unsigned)(p - req->data);
    p += snprintf(p, (size_t)(end - p),
        " HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host);
    req->length = (unsigned)(p - req->data);
    req->sent = 0;
    req->draining = false;
    req->started = time(NULL);
    req->is_query = false;

    // TEMPORARY (integration-testing phase): log every outgoing request.
    fprintf(stderr, "[device-auth] -> %.*s (connecting to %s)\n",
        (int)line_len, req->data, host);

    req->sock = sock;
}

bool device_auth_query_notify(struct device_auth_state *state, struct mobile_adapter *adapter, const unsigned char *addr_ipv4, const unsigned char *ppp_id, unsigned ppp_id_size, const unsigned char *sig, const char *device)
{
    if (ppp_id_size > 0x20) return false;

    struct device_auth_request *req = find_free_slot(state);
    if (!req) {
        fprintf(stderr, "[device-auth] Too many requests in flight, dropping query\n");
        return false;
    }

    char host[SOCKET_STRADDR_MAXLEN] = {0};
    SOCKET sock = device_auth_connect(addr_ipv4, host, sizeof(host));
    if (sock == INVALID_SOCKET) return false;

    char *p = req->data;
    char *end = req->data + sizeof(req->data);
    p += snprintf(p, (size_t)(end - p), "GET /api/adapter/device-auth?ppp_id=");
    p += encode_ppp_id(p, ppp_id, ppp_id_size);
    if (device) p += snprintf(p, (size_t)(end - p), "&device=%s", device);
    p += snprintf(p, (size_t)(end - p), "&action=query&sig=");
    p += encode_hex(p, sig, MOBILE_DEVICE_AUTH_SIG_SIZE);
    unsigned line_len = (unsigned)(p - req->data);
    p += snprintf(p, (size_t)(end - p),
        " HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host);
    req->length = (unsigned)(p - req->data);
    req->sent = 0;
    req->draining = false;
    req->started = time(NULL);
    req->is_query = true;
    req->adapter = adapter;
    req->response_len = 0;

    fprintf(stderr, "[device-auth] -> %.*s (connecting to %s)\n",
        (int)line_len, req->data, host);

    req->sock = sock;
    return true;
}

// Splits a raw HTTP/1.x response into its status code and body, if it
// parses as one at all: a status line, headers, a blank line, then the
// body. Returns false (leaving *status/*body/*body_len untouched) for
// anything that doesn't look like that -- there's no partial credit here,
// since the caller only ever wants a clean 200 or nothing.
static bool parse_http_response(const unsigned char *data, unsigned size, int *status, const unsigned char **body, unsigned *body_len)
{
    // Skip to the first space (the end of "HTTP/1.x"), then read the
    // 3-digit status right after it, rather than assuming exact offsets.
    unsigned i = 0;
    while (i < size && data[i] != ' ') i++;
    if (i + 4 > size) return false;
    i++;
    if (data[i] < '0' || data[i] > '9' ||
            data[i + 1] < '0' || data[i + 1] > '9' ||
            data[i + 2] < '0' || data[i + 2] > '9') {
        return false;
    }
    *status = (data[i] - '0') * 100 + (data[i + 1] - '0') * 10 +
        (data[i + 2] - '0');

    for (unsigned j = 0; j + 4 <= size; j++) {
        if (data[j] == '\r' && data[j + 1] == '\n' &&
                data[j + 2] == '\r' && data[j + 3] == '\n') {
            *body = data + j + 4;
            *body_len = size - (j + 4);
            return true;
        }
    }
    return false;
}

static void request_poll_drain(struct device_auth_request *req)
{
    if (difftime(time(NULL), req->started) > DEVICE_AUTH_DRAIN_TIMEOUT_SECONDS) {
        fprintf(stderr, "[device-auth] timed out draining response, "
            "closing anyway\n");
        request_fail(req);
        return;
    }

    // A plain authorize/deauthorize discards whatever's there: only the
    // HTTP status matters, and the server already tolerates missed/
    // duplicate events via its TTL, so there's no need to actually parse
    // it. A query instead buffers it, to hand the body to
    // mobile_device_auth_query_result() once it's complete. Either way we
    // read until EOF (rather than closing right away) so the server sees a
    // clean disconnect after writing its response, instead of us hanging
    // up on it mid-write.
    for (;;) {
        char buf[256];
        int rc;
        if (req->is_query) {
            unsigned space = (unsigned)sizeof(req->response) - req->response_len;
            if (space == 0) {
                fprintf(stderr, "[device-auth] query response too large, "
                    "dropping\n");
                request_fail(req);
                return;
            }
            if (space > sizeof(buf)) space = sizeof(buf);
            rc = recv(req->sock, buf, (int)space, 0);
        } else {
            rc = recv(req->sock, buf, sizeof(buf), 0);
        }
        if (rc == SOCKET_ERROR) {
            if (socket_geterror() == SOCKET_EWOULDBLOCK) return;
            request_fail(req);
            return;
        }
        if (rc == 0) {
            if (req->is_query) {
                int status;
                const unsigned char *body;
                unsigned body_len;
                if (parse_http_response(req->response, req->response_len,
                        &status, &body, &body_len) && status == 200) {
                    mobile_device_auth_query_result(req->adapter, body,
                        body_len);
                } else {
                    fprintf(stderr, "[device-auth] query response wasn't "
                        "a clean 200, reporting failure\n");
                    mobile_device_auth_query_result(req->adapter, NULL, 0);
                }
            } else {
                // TEMPORARY (integration-testing phase): confirm delivery.
                fprintf(stderr, "[device-auth] <- response drained, "
                    "closing\n");
            }
            request_close(req);
            return;
        }
        if (req->is_query) {
            memcpy(req->response + req->response_len, buf, (unsigned)rc);
            req->response_len += (unsigned)rc;
        }
    }
}

static void request_poll(struct device_auth_request *req)
{
    if (req->draining) {
        request_poll_drain(req);
        return;
    }

    if (difftime(time(NULL), req->started) > DEVICE_AUTH_TIMEOUT_SECONDS) {
        fprintf(stderr, "[device-auth] request timed out, giving up\n");
        request_fail(req);
        return;
    }

    if (req->sent == 0) {
        // Still connecting?
        int rc = socket_isconnected(req->sock);
        if (rc < 0) {
            fprintf(stderr, "[device-auth] connect failed: ");
            socket_perror(NULL);
            request_fail(req);
            return;
        }
        if (rc == 0) return;
    }

    while (req->sent < req->length) {
        int rc = send(req->sock, req->data + req->sent,
            (int)(req->length - req->sent), 0);
        if (rc == SOCKET_ERROR) {
            if (socket_geterror() == SOCKET_EWOULDBLOCK) return;
            fprintf(stderr, "[device-auth] send failed: ");
            socket_perror(NULL);
            request_fail(req);
            return;
        }
        req->sent += (unsigned)rc;
    }

    // Request fully handed to the kernel to send. Switch to draining the
    // response instead of closing right away (see request_poll_drain()).
    fprintf(stderr, "[device-auth] <- request fully sent, "
        "draining response\n");
    req->draining = true;
    req->started = time(NULL);
}

void device_auth_poll(struct device_auth_state *state)
{
    for (unsigned i = 0; i < DEVICE_AUTH_MAX_PENDING; i++) {
        if (state->pending[i].sock != INVALID_SOCKET) request_poll(&state->pending[i]);
    }
}

unsigned device_auth_collect_sockets(struct device_auth_state *state, SOCKET *out, unsigned max)
{
    unsigned count = 0;
    for (unsigned i = 0; i < DEVICE_AUTH_MAX_PENDING && count < max; i++) {
        if (state->pending[i].sock != INVALID_SOCKET) out[count++] = state->pending[i].sock;
    }
    return count;
}
