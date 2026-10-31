// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once
#include <cstdint>
#include <optional>

#include <linux/netfilter/nf_tables.h> // self-contained, safe to expose
#include <netinet/in.h>

namespace nftpp
{

    struct PortRange
    {
        uint16_t min;
        uint16_t max;
        PortRange(uint16_t lo) : min(lo), max(lo) {}
        PortRange(uint16_t lo, uint16_t hi) : min(lo), max(hi) {}
    };

    struct NatTarget
    {
        std::optional<std::string> addr_min; // empty = keep the address (port-only dnat)
        std::optional<std::string> addr_max; // empty = single address
        std::optional<PortRange> ports;      // empty = keep the port
        uint32_t flags = 0;                  // persistent, random, fully-random…

        static NatTarget parse(std::string_view spec); // nft-style string, see below
    };

    enum class L4Proto : uint8_t
    {
        TCP = IPPROTO_TCP,        // 6
        UDP = IPPROTO_UDP,        // 17
        DCCP = IPPROTO_DCCP,      // 33
        SCTP = IPPROTO_SCTP,      // 132
        UDPLITE = IPPROTO_UDPLITE // 136
    };

    static_assert(sizeof(L4Proto) == 1);

    struct PortRange
    {
        uint16_t min;
        uint16_t max;
    };

    struct NatTarget
    {
        std::optional<std::string> addr_min; // empty = keep the address (port-only dnat)
        std::optional<std::string> addr_max; // empty = single address
        std::optional<PortRange> ports;      // empty = keep the port
        uint32_t flags = 0;
    };

    enum class BitMatch
    {
        All,
        Any,
        None
    };

    enum class RateLimitType
    {
        Bytes = NFT_LIMIT_PKT_BYTES,
        Packets = NFT_LIMIT_PKTS
    };

    // IP_CT_DIR_ORIGINAL / IP_CT_DIR_REPLY from <linux/netfilter/nf_conntrack_tuple_common.h>.
    // Not included here: it drags in <linux/in.h>, which clashes with glibc's <netinet/in.h> in user code.
    // Checked against the kernel values in src/expr_builders.hpp.
    enum class CtDirection
    {
        Original = 0,
        Reply = 1
    };
}
