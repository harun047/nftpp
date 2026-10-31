// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include "batch.hpp"
#include "table.hpp"

namespace nftpp
{

    class Firewall
    {
    private:
        Table m_table;

    public:
        Firewall(const std::string &table_name, uint32_t family)
            : m_table(table_name, family)
        {
        }

        explicit Firewall(Table table)
            : m_table(std::move(table))
        {
        }
        Firewall(const Firewall &) = delete;
        Firewall &operator=(const Firewall &) = delete;
        Firewall(Firewall &&) noexcept = default;
        Firewall &operator=(Firewall &&) noexcept = default;

        Table &table() { return m_table; }
    };
}