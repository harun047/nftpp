// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <deque>
#include <string>
#include "chain.hpp"

#include <libnftnl/table.h>

namespace nftpp
{

    class Table
    {

    private:
        nftnl_table *m_table;
        uint32_t m_family;
        std::string m_name;
        std::deque<Chain> m_chains;

    public:
        Table(const std::string &name, uint32_t family)
            : m_table(nftnl_table_alloc()), m_name(name), m_family(family)
        {
            if (!m_table)
            {
                throw std::runtime_error("nftnl_table_alloc() failed! Could not init m_table.");
            }

            nftnl_table_set_u32(m_table, NFTNL_TABLE_FAMILY, m_family);
            nftnl_table_set_str(m_table, NFTNL_TABLE_NAME, m_name.c_str());
        }

        ~Table()
        {
            if (m_table != nullptr)
                nftnl_table_free(m_table);
        }

        Table(const Table &) = delete;
        Table &operator=(const Table &) = delete;

        Table(Table &&other) noexcept
            : m_table(other.m_table),
              m_family(other.m_family),
              m_name(std::move(other.m_name)),
              m_chains(std::move(other.m_chains))
        {
            other.m_table = nullptr;
        }

        Table &operator=(Table &&other) noexcept
        {
            if (this != &other)
            {
                nftnl_table_free(m_table);
                m_table = other.m_table;
                m_name = std::move(other.m_name);
                m_family = other.m_family;
                m_chains = std::move(other.m_chains);

                other.m_table = nullptr;
            }

            return *this;
        }

        const uint32_t family() const { return m_family; }

        nftnl_table *native_handle() const { return m_table; }

        const std::deque<Chain> &chains() const { return m_chains; }
    };

}
