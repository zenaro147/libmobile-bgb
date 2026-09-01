// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <stdbool.h>
#include <time.h>

#include <mobile.h>

#include "socket.h"

// Not a general-purpose resolver: just enough to look up a single, fixed
// hostname's A record against the same DNS1/DNS2 servers already
// configured for the emulated game's own DNS traffic (--dns1/--dns2),
// since the frontend's real OS resolver has no reason to know about that
// (private, REON-only) zone. Tries DNS1 first, falls back to DNS2 if it
// doesn't answer in time, same as the core's own DNS client.
#define DNS_RESOLVE_TIMEOUT_SECONDS 3

struct dns_resolve_state {
    bool done;
    bool success;
    struct mobile_addr result;

    const char *hostname;
    struct mobile_addr servers[2];
    unsigned server_count;
    unsigned server_index;

    SOCKET sock;
    unsigned char query[300];
    unsigned query_len;
    unsigned short query_id;
    time_t sent_at;
};

// Starts resolving <hostname>'s A record. <dns1>/<dns2> may be NULL or
// unconfigured (type MOBILE_ADDRTYPE_NONE); if neither is usable,
// state->done and !state->success are set immediately.
void dns_resolve_start(struct dns_resolve_state *state, const char *hostname, const struct mobile_addr *dns1, const struct mobile_addr *dns2);

// Progresses the lookup. Never blocks. No-op once state->done is set.
void dns_resolve_poll(struct dns_resolve_state *state);

// Appends the socket currently in flight (if any) to <out>, up to <max>
// entries, for inclusion in the main loop's socket_wait() call. Returns
// the number of sockets appended (0 or 1).
unsigned dns_resolve_collect_sockets(struct dns_resolve_state *state, SOCKET *out, unsigned max);
