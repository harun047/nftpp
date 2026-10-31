// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

#include <libnftnl/rule.h>
#include <linux/netfilter/nf_conntrack_common.h>

#include "nftpp/expr.hpp"
#include "nftpp/types.hpp"

namespace nftpp
{
    // ct state bits (what "ct state" matches), see nf_conntrack_common.h
    // NF_CT_STATE_BIT(ctinfo) = 1 << (ctinfo + 1)
    constexpr uint32_t CT_STATE_INVALID = NF_CT_STATE_INVALID_BIT;                // 1 << 0
    constexpr uint32_t CT_STATE_ESTABLISHED = NF_CT_STATE_BIT(IP_CT_ESTABLISHED); // 1 << 1
    constexpr uint32_t CT_STATE_RELATED = NF_CT_STATE_BIT(IP_CT_RELATED);         // 1 << 2
    constexpr uint32_t CT_STATE_NEW = NF_CT_STATE_BIT(IP_CT_NEW);                 // 1 << 3
    constexpr uint32_t CT_STATE_UNTRACKED = NF_CT_STATE_UNTRACKED_BIT;            // 1 << 6

    // ct status bits (what "ct status" matches), see enum ip_conntrack_status
    constexpr uint32_t CT_STATUS_EXPECTED = IPS_EXPECTED;     // 1 << 0
    constexpr uint32_t CT_STATUS_SEEN_REPLY = IPS_SEEN_REPLY; // 1 << 1
    constexpr uint32_t CT_STATUS_ASSURED = IPS_ASSURED;       // 1 << 2
    constexpr uint32_t CT_STATUS_CONFIRMED = IPS_CONFIRMED;   // 1 << 3
    constexpr uint32_t CT_STATUS_SNAT = IPS_SRC_NAT;          // 1 << 4
    constexpr uint32_t CT_STATUS_DNAT = IPS_DST_NAT;          // 1 << 5

    class Rule
    {
    private:
        nftnl_rule *m_rule;
        std::string m_table;
        std::string m_chain;

        void add(Expr e);

        // shared by match_iifname / match_oifname: exact match, or prefix match with trailing '*'
        Rule &match_ifname_impl(uint32_t metaKey, const std::string &ifname);

        void add_bit_match(uint32_t sreg, uint32_t mask, BitMatch match);

        int parse_prefix(const std::string &cidr);
        in_addr &parse_ip(const std::string &ip);

        in6_addr &parse_ip6(const std::string &ip6);
        bool is_ip6(const std::string &cidr);

    public:
        Rule(const std::string &table, const std::string &chain)
            : m_rule(nftnl_rule_alloc()), m_table(table), m_chain(chain)
        {
            if (!m_rule)
            {
                throw std::runtime_error("nftnl_rule_alloc() failed! Could not init m_rule");
            }

            nftnl_rule_set_str(m_rule, NFTNL_RULE_TABLE, m_table.c_str());
            nftnl_rule_set_str(m_rule, NFTNL_RULE_CHAIN, m_chain.c_str());
        }

        ~Rule()
        {
            if (m_rule != nullptr)
            {
                nftnl_rule_free(m_rule);
            }
        }

        Rule(const Rule &) = delete;
        Rule &operator=(const Rule &) = delete;

        Rule(Rule &&other) noexcept
            : m_rule(other.m_rule),
              m_table(std::move(other.m_table)),
              m_chain(std::move(other.m_chain))
        {
            other.m_rule = nullptr;
        }

        Rule &operator=(Rule &&other) noexcept
        {
            if (this != &other)
            {
                if (m_rule != nullptr)
                {
                    nftnl_rule_free(m_rule);
                }
                m_rule = other.m_rule;
                other.m_rule = nullptr;

                m_table = std::move(other.m_table);
                m_chain = std::move(other.m_chain);
            }
            return *this;
        }

        nftnl_rule *native_handle() const { return m_rule; }
        const std::string &table() const { return m_table; }
        const std::string &chain() const { return m_chain; }

        // ---- interface matches ----
        // "eth0" = exact match, "ppp*" = prefix match. Name must be 1-15 chars according to the #define IF_NAMESIZE 16 in net/if.h
        Rule &match_iifname(const std::string &ifname);
        Rule &match_oifname(const std::string &ifname);

        // ---- conntrack matches ----
        // matches if specified bits in the mask are set or not, e.g. CT_STATE_ESTABLISHED | CT_STATE_RELATED / CT_STATE_NEW / CT_STATE_INVALID
        Rule &match_ct_state(uint32_t stateMask, BitMatch match = BitMatch::Any);

        // matches if specified bits in the mask are set or not, e.g CT_STATUS_DNAT / CT_STATUS_SNAT / CT_STATUS_
        Rule &match_ct_status(uint32_t statusMask, BitMatch match = BitMatch::Any);
        // which way THIS packet travels: Original (client->server) or Reply(server-client). See nftpp::CtDirection in nftpp/types.hpp
        Rule &match_ct_direction(CtDirection direction);

        // ---- rate limiting ----
        // specify the type i.e packets or bytes, and whether the reverse i.e NLM_F_INV is true by setting over to true...
        Rule &match_rate_limit(uint32_t rate_per_second, RateLimitType type,
                               uint32_t burst = 0, bool over = false);

        // ---- packet mark ----
        // default mask = exact match on the whole mark (read-only, so safe as a default)
        Rule &match_mark(uint32_t mark, uint32_t mask = 0xffffffff);
        // replaces the WHOLE mark
        Rule &set_mark(uint32_t mark);
        // changes only the masked bits, keeps the rest. mask required, must be non-zero.
        Rule &set_mark_bits(uint32_t mark, uint32_t mask);

        // ---- connection mark ----
        Rule &match_ct_mark(uint32_t mark, uint32_t mask = 0xffffffff);
        // replaces the WHOLE ct mark
        Rule &set_ct_mark(uint32_t mark);
        // changes only the masked bits of the ct mark, keeps the rest
        Rule &set_ct_mark_bits(uint32_t mark, uint32_t mask);

        // ---- connmark save / restore ----
        // ct mark = packet mark
        Rule &save_mark();
        // packet mark = ct mark
        Rule &restore_mark();

        // ---- NAT ----
        Rule &masquerade(uint32_t flags = 0, std::optional<PortRange> ports = std::nullopt);

        Rule &accept();
        Rule &reject();
        Rule &drop();

        Rule &reject_tcp_reset();

        Rule &match_proto(L4Proto proto);
        Rule &match_ip(const std::string &ip4, uint32_t offset);
        Rule &match_ip6(const std::string &ip6, uint32_t offset);

        Rule &match_src_ip(const std::string &ip);
        Rule &match_dst_ip(const std::string &ip);
        Rule &match_src_ip6(const std::string &ip6);
        Rule &match_dst_ip6(const std::string &ip6);
        Rule &match_dport(uint16_t dport, L4Proto proto);
        Rule &match_dport_range(uint16_t lo, uint16_t hi, L4Proto proto);
        Rule &dnat_ip(const std::string &ip4);
        Rule &dnat_ip6(const std::string &ip6);

        Rule &match_src_addr(const std::string &cidr);
        Rule &match_dst_addr(const std::string &cidr);

        Rule &dnat_ipv4();
    };

}