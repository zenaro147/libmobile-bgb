// SPDX-License-Identifier: GPL-3.0-or-later
#include "dns_resolve.h"

#include <string.h>
#include <stdio.h>

#include "socket.h"

#define DNS_HEADER_SIZE 12

union u_sockaddr {
    struct sockaddr addr;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
};

// Same conversion as socket_impl.c's convert_sockaddr()/device_auth.c's
// copy, kept local for the same reason: this doesn't touch struct
// socket_impl's per-conn array.
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

// Encodes <hostname> as a sequence of length-prefixed labels, NUL-like
// terminated by a zero-length label, same wire format as core/dns.c's
// dns_make_name().
static unsigned encode_name(unsigned char *out, const char *hostname)
{
    unsigned char *plen = out;
    unsigned char *pdat = plen + 1;
    unsigned count = 0;

    for (const char *c = hostname; *c; c++) {
        if (*c == '.') {
            *plen = (unsigned char)count;
            count = 0;
            plen = pdat++;
        } else {
            *pdat++ = (unsigned char)*c;
            count++;
        }
    }
    *plen = (unsigned char)count;
    *pdat++ = 0;
    return (unsigned)(pdat - out);
}

// Measures the length, in bytes, of the name field found at <offset>,
// without following compression pointers (RFC1035 4.1.4) -- only their
// fixed 2-byte cost is counted, which is all that's needed to skip past a
// name we don't need to decode. Same approach as core/dns.c's
// dns_name_len().
static int name_field_len(const unsigned char *data, unsigned size, unsigned offset)
{
    if (offset + 1 > size) return -1;

    const unsigned char *p = data + offset;
    for (;;) {
        if (!*p) {
            p++;
            break;
        } else if ((*p & 0xC0) == 0xC0) {
            unsigned pos = (unsigned)(p - data);
            if (pos + 2 > size) return -1;
            return (int)(pos + 2 - offset);
        } else if ((*p & 0xC0) == 0x00) {
            unsigned len = *p++;
            if ((unsigned)(p - data) + len + 1 > size) return -1;
            p += len;
        } else {
            return -1;
        }
    }
    return (int)(p - (data + offset));
}

static void build_query(struct dns_resolve_state *state)
{
    unsigned char *data = state->query;

    // Header: ID, flags (standard query, recursion desired), 1 question
    data[0] = (state->query_id >> 8) & 0xFF;
    data[1] = state->query_id & 0xFF;
    static const unsigned char header[] = {
        0x01, 0x00,
        0, 1,
        0, 0,
        0, 0,
        0, 0,
    };
    memcpy(data + 2, header, sizeof(header));

    unsigned offset = DNS_HEADER_SIZE;
    offset += encode_name(data + offset, state->hostname);

    data[offset++] = 0; data[offset++] = 1;  // QTYPE = A
    data[offset++] = 0; data[offset++] = 1;  // QCLASS = IN

    state->query_len = offset;
}

static bool send_to_server(struct dns_resolve_state *state)
{
    if (state->sock != INVALID_SOCKET) {
        socket_close(state->sock);
        state->sock = INVALID_SOCKET;
    }

    const struct mobile_addr *addr = &state->servers[state->server_index];
    int family = addr->type == MOBILE_ADDRTYPE_IPV4 ? AF_INET : AF_INET6;

    SOCKET sock = socket(family, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) {
        socket_perror("[dns-resolve] socket");
        return false;
    }
    if (socket_setblocking(sock, 0) == -1) {
        socket_close(sock);
        return false;
    }

    union u_sockaddr u_addr;
    socklen_t addrlen;
    struct sockaddr *sockaddr = convert_sockaddr(&addrlen, &u_addr, addr);
    // Connecting the UDP socket lets us use send()/recv() below, and makes
    // the kernel filter out responses from anyone but this DNS server.
    if (connect(sock, sockaddr, addrlen) == SOCKET_ERROR) {
        socket_perror("[dns-resolve] connect");
        socket_close(sock);
        return false;
    }

    if (send(sock, (char *)state->query, (int)state->query_len, 0) == SOCKET_ERROR) {
        socket_perror("[dns-resolve] send");
        socket_close(sock);
        return false;
    }

    state->sock = sock;
    state->sent_at = time(NULL);

    char server_str[SOCKET_STRADDR_MAXLEN] = {0};
    socket_straddr(server_str, sizeof(server_str), sockaddr, addrlen);
    fprintf(stderr, "[dns-resolve] Query sent to %s\n", server_str);
    return true;
}

static void try_next_server_or_fail(struct dns_resolve_state *state)
{
    fprintf(stderr, "[dns-resolve] No response within %ds\n",
        DNS_RESOLVE_TIMEOUT_SECONDS);
    state->server_index++;
    if (state->server_index < state->server_count && send_to_server(state)) {
        return;
    }
    if (state->sock != INVALID_SOCKET) {
        socket_close(state->sock);
        state->sock = INVALID_SOCKET;
    }
    fprintf(stderr, "[dns-resolve] Giving up, could not resolve %s\n",
        state->hostname);
    state->done = true;
    state->success = false;
}

void dns_resolve_start(struct dns_resolve_state *state, const char *hostname, const struct mobile_addr *dns1, const struct mobile_addr *dns2)
{
    memset(state, 0, sizeof(*state));
    state->sock = INVALID_SOCKET;
    state->hostname = hostname;

    if (dns1 && dns1->type != MOBILE_ADDRTYPE_NONE) {
        state->servers[state->server_count++] = *dns1;
    }
    if (dns2 && dns2->type != MOBILE_ADDRTYPE_NONE) {
        state->servers[state->server_count++] = *dns2;
    }
    if (state->server_count == 0) {
        state->done = true;
        state->success = false;
        return;
    }

    state->query_id = (unsigned short)(time(NULL) & 0xFFFF);
    build_query(state);

    // TEMPORARY (integration-testing phase): trace the lookup.
    fprintf(stderr, "[dns-resolve] Looking up %s (%u server(s) configured)\n",
        hostname, state->server_count);

    state->server_index = 0;
    if (!send_to_server(state)) {
        state->done = true;
        state->success = false;
    }
}

// Parses <state->sock>'s pending datagram. Returns true if a usable answer
// (or a definitive negative one) was found, meaning the caller should stop
// polling this server; false to keep waiting.
static bool handle_response(struct dns_resolve_state *state)
{
    unsigned char buf[512];
    int len = recv(state->sock, (char *)buf, sizeof(buf), 0);
    if (len <= 0) return false;
    unsigned size = (unsigned)len;

    if (size < DNS_HEADER_SIZE) return false;
    if ((unsigned)(buf[0] << 8 | buf[1]) != state->query_id) return false;

    unsigned flags = buf[2] << 8 | buf[3];
    if ((flags & 0xFB0F) != 0x8100) {
        // A well-formed, correctly-IDed error response (e.g. NXDOMAIN):
        // no point retrying the other server, this one's authoritative.
        fprintf(stderr, "[dns-resolve] Error response (flags=0x%04x)\n", flags);
        state->done = true;
        state->success = false;
        return true;
    }

    unsigned qdcount = buf[4] << 8 | buf[5];
    unsigned ancount = buf[6] << 8 | buf[7];
    if (qdcount != 1 || ancount < 1) {
        fprintf(stderr, "[dns-resolve] Unexpected response "
            "(qdcount=%u ancount=%u)\n", qdcount, ancount);
        state->done = true;
        state->success = false;
        return true;
    }

    // Skip the question section: it's an exact echo of what we sent.
    unsigned offset = DNS_HEADER_SIZE + (state->query_len - DNS_HEADER_SIZE);
    if (offset > size) {
        state->done = true;
        state->success = false;
        return true;
    }

    for (unsigned i = 0; i < ancount; i++) {
        int name_len = name_field_len(buf, size, offset);
        if (name_len < 0) break;
        unsigned info = offset + (unsigned)name_len;
        if (info + 10 > size) break;

        unsigned type = buf[info] << 8 | buf[info + 1];
        unsigned class = buf[info + 2] << 8 | buf[info + 3];
        unsigned rdlength = buf[info + 8] << 8 | buf[info + 9];
        unsigned rdata = info + 10;
        if (rdata + rdlength > size) break;

        if (type == 1 && class == 1 && rdlength == 4) {  // A / IN
            struct mobile_addr4 *result = (struct mobile_addr4 *)&state->result;
            result->type = MOBILE_ADDRTYPE_IPV4;
            memcpy(result->host, buf + rdata, sizeof(result->host));
            state->done = true;
            state->success = true;
            fprintf(stderr, "[dns-resolve] %s resolved to %u.%u.%u.%u\n",
                state->hostname, result->host[0], result->host[1],
                result->host[2], result->host[3]);
            return true;
        }

        offset = rdata + rdlength;
    }

    fprintf(stderr, "[dns-resolve] Response had no usable A record\n");
    state->done = true;
    state->success = false;
    return true;
}

void dns_resolve_poll(struct dns_resolve_state *state)
{
    if (state->done) return;

    if (socket_hasdata(state->sock) > 0) {
        if (handle_response(state)) {
            if (state->sock != INVALID_SOCKET) {
                socket_close(state->sock);
                state->sock = INVALID_SOCKET;
            }
            return;
        }
    }

    if (difftime(time(NULL), state->sent_at) > DNS_RESOLVE_TIMEOUT_SECONDS) {
        try_next_server_or_fail(state);
    }
}

unsigned dns_resolve_collect_sockets(struct dns_resolve_state *state, SOCKET *out, unsigned max)
{
    if (state->done || state->sock == INVALID_SOCKET || max == 0) return 0;
    out[0] = state->sock;
    return 1;
}
