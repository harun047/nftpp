// SPDX-License-Identifier: GPL-2.0-or-later

#include <stdexcept>
#include <optional>

#include "expr_builders.hpp"

namespace nftpp::detail
{

    Expr make_payload(uint32_t base, uint32_t offset, uint32_t len, uint32_t dreg)
    {
        nftnl_expr *e = nftnl_expr_alloc("payload");
        if (!e)
            throw std::runtime_error("nftnl_expr_alloc(payload) failed!");
        Expr expr(e);

        nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_BASE, base);
        nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_OFFSET, offset);
        nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_LEN, len);
        nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_DREG, dreg);

        return expr;
    }

    Expr make_cmp(uint32_t sreg, uint32_t op, const void *data, uint32_t len)
    {
        nftnl_expr *e = nftnl_expr_alloc("cmp");
        if (!e)
            throw std::runtime_error("nftnl_expr_alloc(cmp) failed");
        Expr expr(e);

        nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_SREG, sreg);
        nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_OP, op);
        if (nftnl_expr_set_data(e, NFTNL_EXPR_CMP_DATA, data, len) < 0)
            throw std::runtime_error("nftnl_expr_set(cmp data) failed");

        return expr;
    }

    Expr make_bitwise(uint32_t sreg, uint32_t dreg, const void *mask, const void *xor_val, uint32_t len)
    {
        nftnl_expr *e = nftnl_expr_alloc("bitwise");
        if (!e)
            throw std::runtime_error("nftnl_expr_alloc(bitwise) failed");
        Expr expr(e);

        nftnl_expr_set_u32(e, NFTNL_EXPR_BITWISE_SREG, sreg);
        nftnl_expr_set_u32(e, NFTNL_EXPR_BITWISE_DREG, dreg);
        nftnl_expr_set_u32(e, NFTNL_EXPR_BITWISE_LEN, len);
        if (nftnl_expr_set(e, NFTNL_EXPR_BITWISE_MASK, mask, len) < 0)
            throw std::runtime_error("nftnl_expr_set(bitwise mask) failed");
        if (nftnl_expr_set(e, NFTNL_EXPR_BITWISE_XOR, xor_val, len) < 0)
            throw std::runtime_error("nftnl_expr_set(bitwise xor) failed");

        return expr;
    }

    Expr make_immediate_data(uint32_t dreg, const void *data, uint32_t len)
    {
        nftnl_expr *e = nftnl_expr_alloc("immediate");
        if (!e)
            throw std::runtime_error("nftnl_expr_alloc(immediate) [data] failed!");
        Expr expr(e);

        nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_DREG, dreg);
        if (nftnl_expr_set_data(e, NFTNL_EXPR_IMM_DATA, data, len) < 0)
            throw std::runtime_error("nftnl_expr_set(immediate data) failed");

        return expr;
    }

    Expr make_immediate_verdict(uint32_t verdict)
    {
        nftnl_expr *e = nftnl_expr_alloc("immediate");
        if (!e)
            throw std::runtime_error("nftnl_expr_alloc(immediate) [verdict] failed!");
        Expr expr(e);

        nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
        nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_VERDICT, verdict);

        return expr;
    }

    Expr make_meta_load(uint32_t key, uint32_t dreg)
    {
        nftnl_expr *e = nftnl_expr_alloc("meta");
        if (!e)
            throw std::runtime_error("nftnl_expr_alloc(meta) failed");
        Expr expr(e);

        nftnl_expr_set_u32(e, NFTNL_EXPR_META_KEY, key);
        nftnl_expr_set_u32(e, NFTNL_EXPR_META_DREG, dreg);

        return expr;
    }

    Expr make_meta_set(uint32_t key, uint32_t sreg)
    {
        nftnl_expr *e = nftnl_expr_alloc("meta");
        if (!e)
            throw std::runtime_error("nftnl_expr_alloc(meta) failed");
        Expr expr(e);

        nftnl_expr_set_u32(e, NFTNL_EXPR_META_KEY, key);
        nftnl_expr_set_u32(e, NFTNL_EXPR_META_SREG, sreg);

        return expr;
    }

    Expr make_ct_load(uint32_t key, uint32_t dreg, std::optional<CtDirection> direction)
    {

        if (key == NFT_CT_SRC || key == NFT_CT_DST)
            throw std::invalid_argument(
                "NFT_CT_SRC/DST have family-dependent length; "
                "use NFT_CT_SRC_IP/DST_IP (IPv4) or NFT_CT_SRC_IP6/DST_IP6 (IPv6)");

        switch (ct_direction_rule(key))
        {
        case CtDirectionRule::Required:
            if (!direction)
            {
                throw std::runtime_error("ct key requires a direction (Original/Reply)");
            }
            break;
        case CtDirectionRule::Forbidden:
            if (direction)
                throw std::runtime_error("ct key does not require a direction");
            break;

        case CtDirectionRule::Optional:
            break;
        }

        nftnl_expr *e = nftnl_expr_alloc("ct");
        if (!e)
            throw std::runtime_error("nftnl_expr_alloc(ct) failed");
        Expr expr(e);

        nftnl_expr_set_u32(e, NFTNL_EXPR_CT_KEY, key);
        nftnl_expr_set_u32(e, NFTNL_EXPR_CT_DREG, dreg);
        if (direction)
            nftnl_expr_set_u8(e, NFTNL_EXPR_CT_DIR, static_cast<uint8_t>(*direction));

        return expr;
    }

    Expr make_ct_set(uint32_t key, uint32_t sreg,
                     std::optional<CtDirection> dir)
    {
        if (ct_set_direction_rule(key) == CtDirectionRule::Forbidden && dir)
            throw std::invalid_argument("ct key does not take a direction");

        nftnl_expr *e = nftnl_expr_alloc("ct");
        if (!e)
            throw std::runtime_error("nftnl_expr_alloc(ct) failed");
        Expr expr(e);

        nftnl_expr_set_u32(e, NFTNL_EXPR_CT_KEY, key);
        nftnl_expr_set_u32(e, NFTNL_EXPR_CT_SREG, sreg);
        if (dir)
            nftnl_expr_set_u8(e, NFTNL_EXPR_CT_DIR, static_cast<uint8_t>(*dir));

        return expr;
    }

    Expr make_nat(NatParams &params)
    {
        nftnl_expr *e = nftnl_expr_alloc("nat");
        if (!e)
            throw std::runtime_error("nftnl_expr_alloc(nat) failed!");
        Expr expr(e);

        auto [type, family, min_addr_reg, max_addr_reg, min_port_reg, max_port_reg] = params;

        nftnl_expr_set_u32(e, NFTNL_EXPR_NAT_TYPE, type);
        nftnl_expr_set_u32(e, NFTNL_EXPR_NAT_FAMILY, family);
        nftnl_expr_set_u32(e, NFTNL_EXPR_NAT_REG_ADDR_MIN, min_addr_reg);

        if (max_addr_reg)
            nftnl_expr_set_u32(e, NFTNL_EXPR_NAT_REG_ADDR_MAX, *max_addr_reg);

        if (min_port_reg)
            nftnl_expr_set_u32(e, NFTNL_EXPR_NAT_REG_PROTO_MIN, *min_port_reg);

        if (max_port_reg)
            nftnl_expr_set_u32(e, NFTNL_EXPR_NAT_REG_PROTO_MAX, *max_port_reg);

        return expr;
    }

    Expr make_masq(uint32_t flags = 0,
                   std::optional<uint32_t> reg_proto_min = std::nullopt,
                   std::optional<uint32_t> reg_proto_max = std::nullopt)
    {
        nftnl_expr *e = nftnl_expr_alloc("masq");
        if (!e)
            throw std::runtime_error("nftnl_expr_alloc(masq) failed");
        Expr expr(e);

        if (flags)
            nftnl_expr_set_u32(e, NFTNL_EXPR_MASQ_FLAGS, flags);
        if (reg_proto_min)
            nftnl_expr_set_u32(e, NFTNL_EXPR_MASQ_REG_PROTO_MIN, *reg_proto_min);
        if (reg_proto_max)
            nftnl_expr_set_u32(e, NFTNL_EXPR_MASQ_REG_PROTO_MAX, *reg_proto_max);

        return expr;
    }

    Expr make_limit(uint32_t rate_per_second, RateLimitType type, uint32_t burst = 0, bool over = false)
    {
        nftnl_expr *e = nftnl_expr_alloc("limit");
        if (!e)
            throw std::runtime_error("nftnl_expr_alloc(limit) failed");

        Expr expr(e);

        nftnl_expr_set_u32(e, NFTNL_EXPR_LIMIT_RATE, rate_per_second);
        nftnl_expr_set_u32(e, NFTNL_EXPR_LIMIT_UNIT, 1);
        nftnl_expr_set_u32(e, NFTNL_EXPR_LIMIT_TYPE, static_cast<uint32_t>(type));
        nftnl_expr_set_u32(e, NFTNL_EXPR_LIMIT_BURST, burst);
        nftnl_expr_set_u32(e, NFTNL_EXPR_LIMIT_FLAGS, over ? NFT_LIMIT_F_INV : 0);

        return expr;
    }

    Expr make_reject(uint32_t type, uint8_t code)
    {
        nftnl_expr *e = nftnl_expr_alloc("reject");
        if (!e)
            throw std::runtime_error("nftnl_expr_alloc(reject) failed");

        Expr expr(e);

        nftnl_expr_set_u32(e, NFTNL_EXPR_REJECT_TYPE, type);
        nftnl_expr_set_u32(e, NFTNL_EXPR_REJECT_CODE, code);

        return expr;
    }

    Expr make_range(uint32_t sreg, uint32_t op, const void *lo, uint32_t lo_sz, const void *hi, uint32_t hi_sz)
    {
        nftnl_expr *e = nftnl_expr_alloc("range");
        if (!e)
            throw std::runtime_error("nftnl_expr_alloc(range) failed");

        Expr expr(e);

        nftnl_expr_set_u32(e, NFTNL_EXPR_RANGE_SREG, sreg);
        nftnl_expr_set_u32(e, NFTNL_EXPR_RANGE_OP, op);
        nftnl_expr_set_data(e, NFTNL_EXPR_RANGE_FROM_DATA, lo, lo_sz);
        nftnl_expr_set_data(e, NFTNL_EXPR_RANGE_TO_DATA, hi, hi_sz);

        return expr;
    }
}