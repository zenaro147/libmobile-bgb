// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include <mobile.h>

#include "socket.h"

// How many device-auth HTTP requests may be in flight at once. Authorize and
// a quick follow-up deauthorize are the only realistic overlap, so this only
// needs a little headroom.
#define DEVICE_AUTH_MAX_PENDING 4

// Longest request line/headers we ever generate, see device_auth.c
#define DEVICE_AUTH_REQUEST_MAXLEN 512

// Drop a stuck connection (e.g. a firewall silently dropping the SYN)
// after this many seconds, so it doesn't hold up a pending slot forever.
#define DEVICE_AUTH_TIMEOUT_SECONDS 10

// Once the request is fully sent, how long to wait for the server to
// finish writing its response and close, before giving up on draining it.
// Closing the socket without doing this can send the server a RST instead
// of a clean FIN if any response bytes are already queued unread, which is
// exactly what shows up server-side as a client that hung up early.
#define DEVICE_AUTH_DRAIN_TIMEOUT_SECONDS 3

// The device-auth contract is plain HTTP, no TLS.
#define DEVICE_AUTH_DEFAULT_PORT 80

struct device_auth_request {
    SOCKET sock;
    char data[DEVICE_AUTH_REQUEST_MAXLEN];
    unsigned length;
    unsigned sent;
    bool draining;
    time_t started;
};

struct device_auth_state {
    struct device_auth_request pending[DEVICE_AUTH_MAX_PENDING];
};

// Initializes the device-auth client. Always enabled: the core only ever
// calls the triggering callback once a device_auth_key has been
// provisioned and the server's address has been resolved, so there's
// nothing left for us to gate on.
void device_auth_init(struct device_auth_state *state);

// Closes any sockets still in flight. Best-effort: in-flight requests are
// simply abandoned, relying on the server-side authorization TTL as a
// safety net.
void device_auth_stop(struct device_auth_state *state);

// Signs and enqueues a device-auth HTTP request. Never blocks: only copies
// the already-signed fields into a pending slot and kicks off a
// non-blocking connect(), matching the requirement that
// mobile_func_update_device_auth must not block. <addr_ipv4> is the
// already-resolved server address (MOBILE_HOSTLEN_IPV4 bytes) the core
// hands us -- we no longer resolve anything ourselves.
void device_auth_notify(struct device_auth_state *state, enum mobile_device_auth_action action, const unsigned char *ppp_id, unsigned ppp_id_size, uint64_t counter, const unsigned char *sig, const unsigned char *addr_ipv4);

// Progresses any in-flight connect()/send() calls. Must be called
// periodically (e.g. once per main loop iteration); never blocks.
void device_auth_poll(struct device_auth_state *state);

// Appends the sockets currently in flight to <out> (up to <max> of them),
// so they can be included in the main loop's socket_wait() call. Returns
// the number of sockets appended.
unsigned device_auth_collect_sockets(struct device_auth_state *state, SOCKET *out, unsigned max);
