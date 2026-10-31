// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once
#include <string>
#include <stdexcept>
#include <optional>
#include <deque>
#include "rule.hpp"

#include <libnftnl/chain.h>

namespace nftpp
{

    class Chain
    {
    public:
        // enums defined in the <linux/netfilter.h> header
        struct BaseConfig
        {
            std::string type; // "filter", "nat", "route"
            uint32_t hooknum; // NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN, NF_INET_FORWARD, NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING
            int32_t priority;
            std::optional<uint32_t> policy; // NF_ACCEPT/NF_DROP
        };

        Chain(const std::string &name, const std::string &table)
            : m_name(name), m_table(table), m_chain(nftnl_chain_alloc())

        {
            if (!m_chain)
            {
                throw std::runtime_error("nftnl_chain_alloc() failed! Could not init m_chain");
            }

            nftnl_chain_set_str(m_chain, NFTNL_CHAIN_NAME, m_name.c_str());
            nftnl_chain_set_str(m_chain, NFTNL_CHAIN_TABLE, m_table.c_str());
        }

        ~Chain()
        {
            if (m_chain != nullptr)
                nftnl_chain_free(m_chain);
        } // Destructor

        Chain(const Chain &) = delete;                 // delete copy constructor
        Chain &operator=(const Chain &other) = delete; // delete copy assignment

        Chain(Chain &&other) noexcept
            : m_chain(other.m_chain),
              m_name(std::move(other.m_name)),
              m_table(std::move(other.m_table)),
              m_base(std::move(other.m_base)),
              m_rules(std::move(other.m_rules))
        {
            other.m_chain = nullptr;
        }

        Chain &operator=(Chain &&other) noexcept
        {
            if (this != &other)
            {
                if (m_chain = nullptr)
                {
                    nftnl_chain_free(m_chain);
                }
                m_chain = other.m_chain;
                other.m_chain = nullptr;
                m_table = std::move(other.m_table);
                m_name = std::move(other.m_name);
                m_base = std::move(other.m_base);
                m_rules = std::move(other.m_rules);
            }

            return *this;
        }

        void make_base(const BaseConfig &cfg)
        {

            nftnl_chain_set_str(m_chain, NFTNL_CHAIN_TYPE, cfg.type.c_str());
            nftnl_chain_set_u32(m_chain, NFTNL_CHAIN_HOOKNUM, cfg.hooknum);
            nftnl_chain_set_s32(m_chain, NFTNL_CHAIN_PRIO, cfg.priority);
            if (cfg.policy)
            {
                nftnl_chain_set_u32(m_chain, NFTNL_CHAIN_POLICY, *cfg.policy);
            }

            m_base = cfg; // set m_base
        }

        nftnl_chain *native_handle() const { return m_chain; }
        const std::string &name() const { return m_name; }
        const std::string &table() const { return m_table; }

        const std::deque<Rule> &rules() const
        {
            return m_rules;
        }

        Rule &rule()
        {
            m_rules.emplace_back(m_table, m_name);
            return m_rules.back();
        }

        bool is_base() const { return m_base.has_value(); }

    private:
        nftnl_chain *m_chain;
        std::string m_table;
        std::string m_name;
        std::optional<BaseConfig> m_base;
        std::deque<Rule> m_rules;
    };

}