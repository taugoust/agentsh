//go:build ignore
// +build ignore

// SPDX-License-Identifier: Apache-2.0
#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <linux/errno.h>

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef SOCK_STREAM
#define SOCK_STREAM 1
#endif
#ifndef SOCK_DGRAM
#define SOCK_DGRAM 2
#endif

// Data emitted per connect attempt
struct connect_event {
    __u64 ts_ns;
    __u64 cookie;
    __u32 pid;
    __u32 tgid;
    __u16 sport;
    __u16 dport;
    __u8  family; // AF_INET / AF_INET6
    __u8  protocol; // IPPROTO_TCP, IPPROTO_UDP, or another socket protocol
    __u8  pad[6];
    union {
        __u32 ipv4;
        __u8  ipv6[16];
    } dst;
    __u8  blocked; // 1 if denied by ebpf
    __u8  _pad2[7];
};

// Extracted context values to avoid passing ctx after modification
struct ctx_info {
    __u64 cgroup_id;
    __u8  family;
    __u16 dport;
    __u32 ipv4;
    __u8  ipv6[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB
} events SEC(".maps");

struct allow_key {
    __u64 cgroup_id;
    __u8 family;
    __u8 protocol; // IPPROTO_TCP or IPPROTO_UDP, 0 = any
    __u16 dport;
    __u8 addr[16];
};

// map size tunables (overridable at compile time via -D)
#ifndef ALLOWLIST_MAX_ENTRIES
#define ALLOWLIST_MAX_ENTRIES 1024
#endif
#ifndef DENYLIST_MAX_ENTRIES
#define DENYLIST_MAX_ENTRIES ALLOWLIST_MAX_ENTRIES
#endif
#ifndef LPM_MAX_ENTRIES
#define LPM_MAX_ENTRIES 1024
#endif
#ifndef LPM_DENY_MAX_ENTRIES
#define LPM_DENY_MAX_ENTRIES LPM_MAX_ENTRIES
#endif
#ifndef DEFAULT_DENY_MAX_ENTRIES
#define DEFAULT_DENY_MAX_ENTRIES 1024
#endif

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, ALLOWLIST_MAX_ENTRIES);
    __type(key, struct allow_key);
    __type(value, __u8);
} allowlist SEC(".maps");

// Deny rules must not be evicted: losing a deny entry while default-allow is
// active would fail open. A full regular hash rejects the update instead.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, DENYLIST_MAX_ENTRIES);
    __type(key, struct allow_key);
    __type(value, __u8);
} denylist SEC(".maps");

// Policy state must never be evicted while links remain attached. A regular
// hash fails a new registration when full; an LRU hash could silently evict an
// older cgroup's default-deny entry and turn that cgroup into default-allow.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, DEFAULT_DENY_MAX_ENTRIES);
    __type(key, __u64); // cgroup id
    __type(value, __u8);
} default_deny SEC(".maps");

// LPM selectors precede the address so a CIDR prefix can still be bound to an
// exact protocol and port. Protocol 0 and dport 0 are represented by explicit
// fallback lookups; they are never implicit byte-prefix wildcards.
struct lpm4_key {
    __u32 prefixlen;
    __u32 pad0;
    __u64 cgroup_id;
    __u8 protocol;
    __u8 pad1;
    __u16 dport;
    __u32 addr;
};
struct lpm6_key {
    __u32 prefixlen;
    __u32 pad0;
    __u64 cgroup_id;
    __u8 protocol;
    __u8 pad1;
    __u16 dport;
    __u8 addr[16];
    __u8 pad2[4];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, LPM_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm4_key);
    __type(value, __u8);
} lpm4_allow SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, LPM_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm6_key);
    __type(value, __u8);
} lpm6_allow SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, LPM_DENY_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm4_key);
    __type(value, __u8);
} lpm4_deny SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, LPM_DENY_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm6_key);
    __type(value, __u8);
} lpm6_deny SEC(".maps");

static __always_inline int emit_event(struct ctx_info *info, __u8 protocol, bool blocked) {
    struct connect_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    __builtin_memset(ev, 0, sizeof(*ev));
    ev->ts_ns = bpf_ktime_get_ns();
    // Generate unique cookie for pending approval tracking using random values
    ev->cookie = ((__u64)bpf_get_prandom_u32() << 32) | bpf_get_prandom_u32();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->pid = (__u32)pid_tgid;
    ev->tgid = pid_tgid >> 32;
    ev->sport = 0;
    ev->dport = info->dport;
    ev->family = info->family;
    ev->protocol = protocol;
    ev->blocked = blocked ? 1 : 0;

    if (info->family == AF_INET) {
        ev->dst.ipv4 = info->ipv4;
    } else if (info->family == AF_INET6) {
        __builtin_memcpy(ev->dst.ipv6, info->ipv6, 16);
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

static __always_inline bool is_denied(struct ctx_info *info, __u8 protocol) {
    struct allow_key key = {};
    key.cgroup_id = info->cgroup_id;
    key.family = info->family;
    key.protocol = protocol;
    key.dport = info->dport;
    if (info->family == AF_INET) {
        __builtin_memcpy(key.addr, &info->ipv4, 4);
    } else if (info->family == AF_INET6) {
        __builtin_memcpy(key.addr, info->ipv6, 16);
    }

    // Check exact protocol+port, protocol+any-port, any-protocol+port, and
    // any-protocol+any-port in that order.
    __u8 *val = bpf_map_lookup_elem(&denylist, &key);
    if (val)
        return true;
    if (info->dport != 0) {
        key.dport = 0;
        val = bpf_map_lookup_elem(&denylist, &key);
        if (val)
            return true;
    }
    if (protocol != 0) {
        key.protocol = 0;
        key.dport = info->dport;
        val = bpf_map_lookup_elem(&denylist, &key);
        if (val)
            return true;
        if (info->dport != 0) {
            key.dport = 0;
            val = bpf_map_lookup_elem(&denylist, &key);
            if (val)
                return true;
        }
    }

    // LPM query keys always use the maximum prefix. Stored keys use the fixed
    // selector prefix plus their address prefix. Any protocol/port entries are
    // matched by explicit zero-selector fallbacks.
    if (info->family == AF_INET) {
        struct lpm4_key lk = {};
        lk.cgroup_id = info->cgroup_id;
        lk.protocol = protocol;
        lk.dport = info->dport;
        __builtin_memcpy(&lk.addr, &info->ipv4, 4);
        lk.prefixlen = 32 + 64 + 8 + 8 + 16 + 32;
        val = bpf_map_lookup_elem(&lpm4_deny, &lk);
        if (val)
            return true;
        if (info->dport != 0) {
            lk.dport = 0;
            val = bpf_map_lookup_elem(&lpm4_deny, &lk);
            if (val)
                return true;
        }
        if (protocol != 0) {
            lk.protocol = 0;
            lk.dport = info->dport;
            val = bpf_map_lookup_elem(&lpm4_deny, &lk);
            if (val)
                return true;
            if (info->dport != 0) {
                lk.dport = 0;
                val = bpf_map_lookup_elem(&lpm4_deny, &lk);
                if (val)
                    return true;
            }
        }
    } else if (info->family == AF_INET6) {
        struct lpm6_key lk = {};
        lk.cgroup_id = info->cgroup_id;
        lk.protocol = protocol;
        lk.dport = info->dport;
        __builtin_memcpy(&lk.addr, info->ipv6, 16);
        lk.prefixlen = 32 + 64 + 8 + 8 + 16 + 128;
        val = bpf_map_lookup_elem(&lpm6_deny, &lk);
        if (val)
            return true;
        if (info->dport != 0) {
            lk.dport = 0;
            val = bpf_map_lookup_elem(&lpm6_deny, &lk);
            if (val)
                return true;
        }
        if (protocol != 0) {
            lk.protocol = 0;
            lk.dport = info->dport;
            val = bpf_map_lookup_elem(&lpm6_deny, &lk);
            if (val)
                return true;
            if (info->dport != 0) {
                lk.dport = 0;
                val = bpf_map_lookup_elem(&lpm6_deny, &lk);
                if (val)
                    return true;
            }
        }
    }
    return false;
}

static __always_inline bool allow(struct ctx_info *info, __u8 protocol) {
    struct allow_key key = {};
    key.cgroup_id = info->cgroup_id;
    key.family = info->family;
    key.protocol = protocol;
    key.dport = info->dport;
    if (info->family == AF_INET) {
        __builtin_memcpy(key.addr, &info->ipv4, 4);
    } else if (info->family == AF_INET6) {
        __builtin_memcpy(key.addr, info->ipv6, 16);
    }

    __u8 *val = bpf_map_lookup_elem(&allowlist, &key);
    if (val)
        return true;
    if (info->dport != 0) {
        key.dport = 0;
        val = bpf_map_lookup_elem(&allowlist, &key);
        if (val)
            return true;
    }
    if (protocol != 0) {
        key.protocol = 0;
        key.dport = info->dport;
        val = bpf_map_lookup_elem(&allowlist, &key);
        if (val)
            return true;
        if (info->dport != 0) {
            key.dport = 0;
            val = bpf_map_lookup_elem(&allowlist, &key);
            if (val)
                return true;
        }
    }

    if (info->family == AF_INET) {
        struct lpm4_key lk = {};
        lk.cgroup_id = info->cgroup_id;
        lk.protocol = protocol;
        lk.dport = info->dport;
        __builtin_memcpy(&lk.addr, &info->ipv4, 4);
        lk.prefixlen = 32 + 64 + 8 + 8 + 16 + 32;
        val = bpf_map_lookup_elem(&lpm4_allow, &lk);
        if (val)
            return true;
        if (info->dport != 0) {
            lk.dport = 0;
            val = bpf_map_lookup_elem(&lpm4_allow, &lk);
            if (val)
                return true;
        }
        if (protocol != 0) {
            lk.protocol = 0;
            lk.dport = info->dport;
            val = bpf_map_lookup_elem(&lpm4_allow, &lk);
            if (val)
                return true;
            if (info->dport != 0) {
                lk.dport = 0;
                val = bpf_map_lookup_elem(&lpm4_allow, &lk);
                if (val)
                    return true;
            }
        }
    } else if (info->family == AF_INET6) {
        struct lpm6_key lk = {};
        lk.cgroup_id = info->cgroup_id;
        lk.protocol = protocol;
        lk.dport = info->dport;
        __builtin_memcpy(&lk.addr, info->ipv6, 16);
        lk.prefixlen = 32 + 64 + 8 + 8 + 16 + 128;
        val = bpf_map_lookup_elem(&lpm6_allow, &lk);
        if (val)
            return true;
        if (info->dport != 0) {
            lk.dport = 0;
            val = bpf_map_lookup_elem(&lpm6_allow, &lk);
            if (val)
                return true;
        }
        if (protocol != 0) {
            lk.protocol = 0;
            lk.dport = info->dport;
            val = bpf_map_lookup_elem(&lpm6_allow, &lk);
            if (val)
                return true;
            if (info->dport != 0) {
                lk.dport = 0;
                val = bpf_map_lookup_elem(&lpm6_allow, &lk);
                if (val)
                    return true;
            }
        }
    }
    return false;
}

// default_deny values form a small fail-closed policy state machine:
//   0 / missing: default allow
//   1: default deny, subject to exact allow rules
//   2: policy update locked; deny all traffic regardless of allow rules
// Userspace writes state 2 before changing any allow/deny entry and only
// publishes state 0 or 1 after the complete replacement succeeds.
static __always_inline __u8 policy_state(void) {
    __u64 k = bpf_get_current_cgroup_id();
    __u8 *v = bpf_map_lookup_elem(&default_deny, &k);
    if (!v)
        return 0;
    return *v > 2 ? 2 : *v;
}

// The connect hooks are reached by more than TCP. Preserve the socket's actual
// protocol in map lookups so an exact TCP proxy rule cannot authorize UDP or a
// different transport merely because its address and port happen to match.
static __always_inline __u8 socket_protocol(struct bpf_sock_addr *ctx) {
    __u32 protocol = ctx->protocol;
    if (protocol == 0) {
        if (ctx->type == SOCK_STREAM)
            return IPPROTO_TCP;
        if (ctx->type == SOCK_DGRAM)
            return IPPROTO_UDP;
        return 0;
    }
    if (protocol > 255)
        return 0;
    return (__u8)protocol;
}

SEC("cgroup/connect4")
int handle_connect4(struct bpf_sock_addr *ctx) {
    // user_ip4 is stored in network byte order. Copying the loaded __u32 back
    // into the key preserves those exact bytes on both little- and big-endian
    // hosts; userspace must not add a byte-swapped compatibility rule.
    __u32 ip4 = ctx->user_ip4;
    __u32 port = ctx->user_port;
    __u8 protocol = socket_protocol(ctx);

    struct ctx_info info = {};
    info.cgroup_id = bpf_get_current_cgroup_id();
    info.family = AF_INET;
    info.dport = bpf_ntohs(port);
    info.ipv4 = ip4;

    __u8 state = policy_state();
    bool denied = false;
    if (state == 2) {
        denied = true;
    } else if (is_denied(&info, protocol)) {
        denied = true;
    } else if (state == 1 && !allow(&info, protocol)) {
        denied = true;
    }
    emit_event(&info, protocol, denied);
    return denied ? 0 : 1;
}

SEC("cgroup/connect6")
int handle_connect6(struct bpf_sock_addr *ctx) {
    // Read ctx values into local variables
    __u32 port = ctx->user_port;
    __u8 protocol = socket_protocol(ctx);
    __u32 ip6_0 = ctx->user_ip6[0];
    __u32 ip6_1 = ctx->user_ip6[1];
    __u32 ip6_2 = ctx->user_ip6[2];
    __u32 ip6_3 = ctx->user_ip6[3];

    struct ctx_info info = {};
    info.cgroup_id = bpf_get_current_cgroup_id();
    info.family = AF_INET6;
    info.dport = bpf_ntohs(port);
    __u32 *dst = (__u32 *)info.ipv6;
    dst[0] = ip6_0;
    dst[1] = ip6_1;
    dst[2] = ip6_2;
    dst[3] = ip6_3;

    __u8 state = policy_state();
    bool denied = false;
    if (state == 2) {
        denied = true;
    } else if (is_denied(&info, protocol)) {
        denied = true;
    } else if (state == 1 && !allow(&info, protocol)) {
        denied = true;
    }
    emit_event(&info, protocol, denied);
    return denied ? 0 : 1;
}

// UDP sendmsg hooks
SEC("cgroup/sendmsg4")
int handle_sendmsg4(struct bpf_sock_addr *ctx) {
    __u32 ip4 = ctx->user_ip4;
    __u32 port = ctx->user_port;
    __u8 protocol = socket_protocol(ctx);

    struct ctx_info info = {};
    info.cgroup_id = bpf_get_current_cgroup_id();
    info.family = AF_INET;
    info.dport = bpf_ntohs(port);
    info.ipv4 = ip4;

    __u8 state = policy_state();
    bool denied = false;
    if (state == 2) {
        denied = true;
    } else if (is_denied(&info, protocol)) {
        denied = true;
    } else if (state == 1 && !allow(&info, protocol)) {
        denied = true;
    }
    emit_event(&info, protocol, denied);
    return denied ? 0 : 1;
}

SEC("cgroup/sendmsg6")
int handle_sendmsg6(struct bpf_sock_addr *ctx) {
    __u32 port = ctx->user_port;
    __u8 protocol = socket_protocol(ctx);
    __u32 ip6_0 = ctx->user_ip6[0];
    __u32 ip6_1 = ctx->user_ip6[1];
    __u32 ip6_2 = ctx->user_ip6[2];
    __u32 ip6_3 = ctx->user_ip6[3];

    struct ctx_info info = {};
    info.cgroup_id = bpf_get_current_cgroup_id();
    info.family = AF_INET6;
    info.dport = bpf_ntohs(port);
    __u32 *dst = (__u32 *)info.ipv6;
    dst[0] = ip6_0;
    dst[1] = ip6_1;
    dst[2] = ip6_2;
    dst[3] = ip6_3;

    __u8 state = policy_state();
    bool denied = false;
    if (state == 2) {
        denied = true;
    } else if (is_denied(&info, protocol)) {
        denied = true;
    } else if (state == 1 && !allow(&info, protocol)) {
        denied = true;
    }
    emit_event(&info, protocol, denied);
    return denied ? 0 : 1;
}

char LICENSE[] SEC("license") = "Apache-2.0";
