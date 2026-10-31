// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once
#include "nftpp/expr.hpp"
#include "nftpp/types.hpp"
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nf_conntrack_tuple_common.h>
#include <optional>
#include <stdexcept>

namespace nftpp::detail
{

    struct NatParams
    {
        uint32_t type;
        uint32_t family;
        std::optional<uint32_t> min_addr_reg;
        std::optional<uint32_t> max_addr_reg;
        std::optional<uint32_t> min_port_reg;
        std::optional<uint32_t> max_port_reg;
    };

    // payload: load packet header bytes onto a register
    Expr make_payload(uint32_t base, uint32_t offset, uint32_t len, uint32_t dreg);

    // compare / transform register contents
    Expr make_cmp(uint32_t sreg, uint32_t op, const void *data, uint32_t len);
    Expr make_bitwise(uint32_t sreg, uint32_t dreg, const void *mask, const void *xor_val, uint32_t len);

    // immediate: load a constant onto a register
    Expr make_immediate_data(uint32_t dreg, const void *data, uint32_t len);
    Expr make_immediate_verdict(uint32_t verdict);

    // meta: packet metadata (mark, iifname, ...)
    Expr make_meta_load(uint32_t key, uint32_t dreg);
    Expr make_meta_set(uint32_t key, uint32_t sreg);

    // ct: conntrack
    static_assert(static_cast<int>(CtDirection::Original) == IP_CT_DIR_ORIGINAL);
    static_assert(static_cast<int>(CtDirection::Reply) == IP_CT_DIR_REPLY);

    enum class CtDirectionRule
    {
        Required,
        Optional,
        Forbidden
    };

    constexpr CtDirectionRule ct_direction_rule(uint32_t key)
    {
        switch (key)
        {
        // Per-direction tuple fields: a connection has TWO tuples (original + reply),
        // so the kernel must be told which one. Omitting direction -> EINVAL.
        case NFT_CT_SRC: // (legacy, family-dependent length; prefer *_IP / *_IP6)
        case NFT_CT_DST:
        case NFT_CT_SRC_IP:
        case NFT_CT_DST_IP:
        case NFT_CT_SRC_IP6:
        case NFT_CT_DST_IP6:
        case NFT_CT_PROTO_SRC: // port / ICMP id / GRE key
        case NFT_CT_PROTO_DST:
            return CtDirectionRule::Required;

        // Per-direction counters: direction picks one side; omitted = both summed.
        case NFT_CT_BYTES:
        case NFT_CT_PKTS:
        case NFT_CT_AVGPKT:
        // Zones can be per-direction; omitted = applies to both.
        case NFT_CT_ZONE:
        // Accepted for compatibility but ignored (same value in both tuples).
        case NFT_CT_L3PROTOCOL:
        case NFT_CT_PROTOCOL:
            return CtDirectionRule::Optional;

        // Whole-connection fields: stored ONCE in struct nf_conn, not per tuple.
        // Passing a direction -> EINVAL.
        case NFT_CT_STATE:      // new / established / related / invalid / untracked
        case NFT_CT_DIRECTION:  // which way THIS packet travels (it IS the direction)
        case NFT_CT_STATUS:     // IPS_* bits: seen-reply, assured, src-nat, dst-nat...
        case NFT_CT_MARK:       // one connmark shared by both directions
        case NFT_CT_SECMARK:    // security mark (SELinux)
        case NFT_CT_EXPIRATION: // time left before the entry times out
        case NFT_CT_HELPER:     // attached helper name (ftp, sip, pptp...)
        case NFT_CT_LABELS:     // 128-bit label bitmap
        case NFT_CT_ID:         // unique conntrack id
            return CtDirectionRule::Forbidden;

        // Unknown / future keys: forbid a direction by default (safest).
        default:
            return CtDirectionRule::Forbidden;
        }
    }

    constexpr CtDirectionRule ct_set_direction_rule(uint32_t key)
    {
        switch (key)
        {
        case NFT_CT_ZONE:
            return CtDirectionRule::Optional;

        case NFT_CT_MARK:
        case NFT_CT_LABELS:
        case NFT_CT_EVENTMASK:
        case NFT_CT_SECMARK:
            return CtDirectionRule::Forbidden;

        default:
            throw std::invalid_argument("ct key is not settable");
        }
    }

    constexpr bool has_ports(L4Proto p) noexcept
    {
        switch (p)
        {
        case L4Proto::TCP:
        case L4Proto::UDP:
        case L4Proto::DCCP:
        case L4Proto::SCTP:
        case L4Proto::UDPLITE:
            return true;
        }
        return false; // Cases like ICMP
    }

    Expr make_ct_load(uint32_t key, uint32_t dreg, std::optional<CtDirection> direction = std::nullopt);
    Expr make_ct_set(uint32_t key, uint32_t sreg, std::optional<CtDirection> dir = std::nullopt);

    // nat
    Expr make_nat(NatParams &details);
    Expr make_masq(uint32_t flags = 0,
                   std::optional<uint32_t> reg_proto_min = std::nullopt,
                   std::optional<uint32_t> reg_proto_max = std::nullopt);

    // limit
    Expr make_limit(uint32_t rate_per_second, RateLimitType type, uint32_t burst = 0, bool over = false);

    Expr make_reject(uint32_t type, uint8_t code);

    Expr make_range(uint32_t sreg, uint32_t op, const void *lo, uint32_t lo_sz, const void *hi, uint32_t hi_sz);
}
