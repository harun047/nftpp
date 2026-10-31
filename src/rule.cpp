// SPDX-License-Identifier: GPL-2.0-or-later

#include <optional>

#include "nftpp/rule.hpp"
#include "expr_builders.hpp"

#include <arpa/inet.h> // glibc net headers must precede the <linux/...> ones pulled in by expr_builders.hpp
#include <net/if.h>    // IFNAMSIZ (basically 16)

namespace
{
    void validate_mark_mask(uint32_t mark, uint32_t mask)
    {
        if (mask == 0)
            throw std::invalid_argument("mask is 0: no bits would change");
        if (mark & ~mask)
            throw std::invalid_argument("mark has bits outside the mask");
    }
}

namespace nftpp
{

    void Rule::add(Expr e)
    {
        nftnl_rule_add_expr(m_rule, e.release());
    }

    // ---- interface matches ----

    Rule &Rule::match_ifname_impl(uint32_t metaKey, const std::string &ifname)
    {
        if (ifname.empty() || ifname.size() >= IFNAMSIZ)
            throw std::invalid_argument("interface name must be 1-15 characters");

        add(detail::make_meta_load(metaKey, NFT_REG_1));

        if (ifname.back() == '*') // "ppp*" -> prefix match, no NULL TERMINATOR
            add(detail::make_cmp(NFT_REG_1, NFT_CMP_EQ, ifname.data(), ifname.size() - 1));
        else // exact match, include NULL TERMINATOR
            add(detail::make_cmp(NFT_REG_1, NFT_CMP_EQ, ifname.c_str(), ifname.size() + 1));

        return *this;
    }

    Rule &Rule::match_iifname(const std::string &ifname)
    {
        return match_ifname_impl(NFT_META_IIFNAME, ifname);
    }

    Rule &Rule::match_oifname(const std::string &ifname)
    {
        return match_ifname_impl(NFT_META_OIFNAME, ifname);
    }

    // ---- conntrack matches ----

    void Rule::add_bit_match(uint32_t sreg, uint32_t mask, BitMatch match)
    {

        uint32_t xor_val = 0;
        uint32_t zero = 0;
        add(detail::make_bitwise(sreg, NFT_REG_2, &mask, &xor_val, sizeof(mask)));

        switch (match)
        {
        case BitMatch::Any: // at least one masked bit set
            add(detail::make_cmp(NFT_REG_2, NFT_CMP_NEQ, &zero, sizeof(zero)));
            break;
        case BitMatch::All: // every masked bit set
            add(detail::make_cmp(NFT_REG_2, NFT_CMP_EQ, &mask, sizeof(mask)));
            break;
        case BitMatch::None: // no masked bit set
            add(detail::make_cmp(NFT_REG_2, NFT_CMP_EQ, &zero, sizeof(zero)));
            break;
        }
    }

    Rule &Rule::match_ct_state(uint32_t stateMask, BitMatch match)
    {
        if (stateMask == 0)
            throw std::invalid_argument("state mask is 0");
        if (match == BitMatch::All && (stateMask & (stateMask - 1)))
            throw std::invalid_argument("ct state is exclusive: All with multiple states never matches");

        add(detail::make_ct_load(NFT_CT_STATE, NFT_REG_1));
        add_bit_match(NFT_REG_1, stateMask, match);
        return *this;
    }

    Rule &Rule::match_ct_status(uint32_t statusMask, BitMatch match)
    {
        if (statusMask == 0)
            throw std::invalid_argument("status mask is 0");

        add(detail::make_ct_load(NFT_CT_STATUS, NFT_REG_1));
        add_bit_match(NFT_REG_1, statusMask, match);
        return *this;
    }

    Rule &Rule::match_ct_direction(CtDirection direction)
    {
        uint8_t dir = static_cast<uint8_t>(direction);

        add(detail::make_ct_load(NFT_CT_DIRECTION, NFT_REG_1)); // 1 byte: 0 = original, 1 = reply
        add(detail::make_cmp(NFT_REG_1, NFT_CMP_EQ, &dir, sizeof(dir)));

        return *this;
    }

    // ---- rate limiting ----

    Rule &Rule::match_rate_limit(uint32_t rate_per_second, RateLimitType type, uint32_t burst, bool over)
    {
        add(detail::make_limit(rate_per_second, type, burst, over));

        return *this;
    }

    // ---- NAT ----

    Rule &Rule::masquerade(uint32_t flags, std::optional<PortRange> ports) // no "= 0" here: defaults belong in the header only
    {
        std::optional<uint32_t> rmin, rmax; // min and max registers

        if (ports)
        {
            if (ports->min > ports->max)
                throw std::invalid_argument("Invalid port range for masquerade: min > max");

            uint16_t lo = htons(ports->min);
            uint16_t hi = htons(ports->max);
            add(detail::make_immediate_data(NFT_REG_1, &lo, sizeof(lo)));
            add(detail::make_immediate_data(NFT_REG_2, &hi, sizeof(hi)));

            rmin = NFT_REG_1;
            rmax = NFT_REG_2;
        }

        add(detail::make_masq(flags, rmin, rmax));
        return *this;
    }

    // ---- packet mark ----

    Rule &Rule::match_mark(uint32_t mark, uint32_t mask)
    {
        validate_mark_mask(mark, mask);

        add(detail::make_meta_load(NFT_META_MARK, NFT_REG_1));
        if (mask != 0xffffffff) // full mask: AND changes nothing, skip it
        {
            uint32_t xor_val = 0;
            add(detail::make_bitwise(NFT_REG_1, NFT_REG_1, &mask, &xor_val, sizeof(mask)));
        }
        add(detail::make_cmp(NFT_REG_1, NFT_CMP_EQ, &mark, sizeof(mark)));

        return *this;
    }

    Rule &Rule::set_mark(uint32_t mark)
    {
        add(detail::make_immediate_data(NFT_REG_1, &mark, sizeof(mark)));
        add(detail::make_meta_set(NFT_META_MARK, NFT_REG_1));
        return *this;
    }

    Rule &Rule::set_mark_bits(uint32_t mark, uint32_t mask)
    {
        validate_mark_mask(mark, mask);
        if (mask == 0xffffffff)
            return set_mark(mark); // own every bit: plain overwrite

        uint32_t keep = ~mask;
        add(detail::make_meta_load(NFT_META_MARK, NFT_REG_1));
        add(detail::make_bitwise(NFT_REG_1, NFT_REG_1, &keep, &mark, sizeof(keep)));
        add(detail::make_meta_set(NFT_META_MARK, NFT_REG_1));
        return *this;
    }

    // ---- connection mark ----

    Rule &Rule::match_ct_mark(uint32_t mark, uint32_t mask)
    {
        validate_mark_mask(mark, mask);

        add(detail::make_ct_load(NFT_CT_MARK, NFT_REG_1));
        if (mask != 0xffffffff)
        {
            uint32_t xor_val = 0;
            add(detail::make_bitwise(NFT_REG_1, NFT_REG_1, &mask, &xor_val, sizeof(mask)));
        }
        add(detail::make_cmp(NFT_REG_1, NFT_CMP_EQ, &mark, sizeof(mark)));

        return *this;
    }

    Rule &Rule::set_ct_mark(uint32_t mark)
    {
        add(detail::make_immediate_data(NFT_REG_1, &mark, sizeof(mark)));
        add(detail::make_ct_set(NFT_CT_MARK, NFT_REG_1));
        return *this;
    }

    Rule &Rule::set_ct_mark_bits(uint32_t mark, uint32_t mask)
    {
        validate_mark_mask(mark, mask);
        if (mask == 0xffffffff)
            return set_ct_mark(mark);

        uint32_t keep = ~mask;
        add(detail::make_ct_load(NFT_CT_MARK, NFT_REG_1));
        add(detail::make_bitwise(NFT_REG_1, NFT_REG_1, &keep, &mark, sizeof(keep)));
        add(detail::make_ct_set(NFT_CT_MARK, NFT_REG_1));
        return *this;
    }

    // ---- connmark save / restore ----

    Rule &Rule::save_mark()
    {
        add(detail::make_meta_load(NFT_META_MARK, NFT_REG_1));
        add(detail::make_ct_set(NFT_CT_MARK, NFT_REG_1));
        return *this;
    }

    Rule &Rule::restore_mark()
    {
        add(detail::make_ct_load(NFT_CT_MARK, NFT_REG_1));
        add(detail::make_meta_set(NFT_META_MARK, NFT_REG_1));
        return *this;
    }

    Rule &Rule::accept()
    {
        add(detail::make_immediate_verdict(NF_ACCEPT));
        return *this;
    }

    Rule &Rule::drop()
    {
        add(detail::make_immediate_verdict(NF_DROP));
        return *this;
    }

    Rule &Rule::reject()
    {

        add(detail::make_reject(NFT_REJECT_ICMPX_UNREACH, NFT_REJECT_ICMPX_PORT_UNREACH));
        return *this;
    }

    Rule &Rule::reject_tcp_reset()
    {
        add(detail::make_reject(NFT_REJECT_TCP_RST, 0));
        return *this;
    }

    Rule &Rule::match_proto(L4Proto proto)
    {
        if (!detail::has_ports(proto))
            throw std::invalid_argument("match_proto: protocol has no ports");

        // compare protocols
        add(detail::make_meta_load(NFT_META_L4PROTO, NFT_REG_1));
        add(detail::make_cmp(NFT_REG_1, NFT_CMP_EQ, &proto, sizeof(proto)));

        return *this;
    }

    Rule &Rule::match_dport(uint16_t dport, L4Proto proto)
    {

        if (dport == 0)
            throw std::invalid_argument("match_dport: port 0 is reserved");

        match_proto(proto);
        // compare ports
        const uint16_t be_dport = htons(dport); // grab the byte order equivalent
        add(detail::make_payload(NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2, NFT_REG_1));
        add(detail::make_cmp(NFT_REG_1, NFT_CMP_EQ, &be_dport, sizeof(be_dport)));

        return *this;
    }

    Rule &Rule::match_dport_range(uint16_t lo, uint16_t hi, L4Proto proto)
    {
        if (lo > hi)
            throw std::invalid_argument("match_dport_range: lo > hi");
        if (lo == hi)
            return match_dport(lo, proto);

        match_proto(proto);

        add(detail::make_payload(NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2, NFT_REG_1));
        add(detail::make_range(NFT_REG_1, NFT_RANGE_EQ, &lo, sizeof(lo), &hi, sizeof(hi)));

        return *this;
    }

    int parse_prefix(const std::string &cidr)
    {
        size_t slash_pos = cidr.find("/");
        std::string ip = cidr.substr(0, slash_pos);
        return (slash_pos == std::string::npos) ? 128 : std::stoi(cidr.substr(slash_pos + 1));
    }

    in_addr &Rule::parse_ip(const std::string &ip)
    {
        size_t slash_pos = ip.find("/");
        std::string ip = ip.substr(0, slash_pos);

        in_addr addr{};
        if (inet_pton(AF_INET, ip.c_str(), &addr) != 1)
        {
            throw std::invalid_argument("Bad IPV4 address: " + ip);
        }

        return addr;
    }

    Rule &Rule::match_ip(const std::string &ip4, uint32_t offset)
    {

        if (ip4.empty())
            throw std::runtime_error("Invalid ip address string");

        const in_addr addr = parse_ip(ip4);
        const uint8_t prefix = parse_prefix(ip4);

        const uint32_t netmask = htonl(~uint32_t{0} << (32 - prefix));
        const uint32_t nfproto = NFPROTO_IPV4;
        const uint32_t target = addr.s_addr & netmask;
        const uint32_t zero = 0;

        add(detail::make_meta_load(NFT_META_NFPROTO, NFT_REG_1));
        add(detail::make_cmp(NFT_REG_1, NFT_CMP_EQ, &nfproto, sizeof(nfproto)));

        add(detail::make_payload(NFT_PAYLOAD_NETWORK_HEADER, offset, 4, NFT_REG_1));
        add(detail::make_bitwise(NFT_REG_1, NFT_REG_1, &netmask, &zero, sizeof(netmask)));
        add(detail::make_cmp(NFT_REG_1, NFT_CMP_EQ, &target, sizeof(target)));

        return *this;
    }

    Rule &Rule::match_src_ip(const std::string &ip)
    {
        return match_ip(ip, 12);
    }

    Rule &Rule::match_dst_ip(const std::string &ip)
    {
        return match_ip(ip, 16);
    }

    in6_addr &Rule::parse_ip6(const std::string &ip6)
    {

        size_t slash_pos = ip6.find("/");
        std::string ip = ip6.substr(0, slash_pos);
        in6_addr a{};
        if (inet_pton(AF_INET6, ip.c_str(), &a) != 1)
        {
            throw std::invalid_argument("Bad IPV6 address: " + ip6);
        }
    }

    Rule &Rule::match_ip6(const std::string &ip6, uint32_t offset)
    {
        if (ip6.empty())
            throw std::runtime_error("Invalid ip address string");

        const int prefix = parse_prefix(ip6);
        const in6_addr addr = parse_ip6(ip6);

        in6_addr netmask{};
        const int full = prefix / 8;
        const int rem = prefix % 8;
        for (int i = 0; i < full; ++i)
        {
            netmask.s6_addr[i] = 0xff;
        }

        if (rem)
            netmask.s6_addr[full] = static_cast<uint8_t>(0xff << (8 - rem));

        const uint8_t nfproto = NFPROTO_IPV6;
        in6_addr zero{};
        in6_addr target{};

        for (int i = 0; i < 16; ++i)
        {
            target.s6_addr[i] = addr.s6_addr[i] & netmask.s6_addr[i];
        }

        add(detail::make_meta_load(NFT_META_NFPROTO, NFT_REG_1));
        add(detail::make_cmp(NFT_REG_1, NFT_CMP_EQ, &nfproto, sizeof(nfproto)));

        add(detail::make_payload(NFT_PAYLOAD_NETWORK_HEADER, offset, 16, NFT_REG_1));
        add(detail::make_bitwise(NFT_REG_1, NFT_REG_1, &netmask, &zero, sizeof(zero)));
        add(detail::make_cmp(NFT_REG_1, NFT_CMP_EQ, &target, sizeof(target)));

        return *this;
    }

    Rule &Rule::match_src_ip6(const std::string &ip6)
    {
        return match_ip6(ip6, 8);
    }

    Rule &Rule::match_dst_ip6(const std::string &ip6)
    {
        return match_ip6(ip6, 24);
    }

    bool Rule::is_ip6(const std::string &cidr)
    {
        return cidr.find(":") != std::string::npos;
    }

    Rule &Rule::match_src_addr(const std::string &cidr)
    {
        return is_ip6(cidr) ? match_src_ip6(cidr) : match_src_ip(cidr);
    }

    Rule &Rule::match_dst_addr(const std::string &cidr)
    {
        return is_ip6(cidr) ? match_dst_ip6(cidr) : match_dst_ip(cidr);
    }

    Rule &Rule::dnat_ip(const std::string &ip4)
    {
    }

    Rule &Rule::dnat_ip6(const std::string &ip6) {}
}