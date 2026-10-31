// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstdio> // must precede #include <libnftnl/expr.h>. It uses FILE and forgets to include stdio.h
#include <libnftnl/expr.h>

namespace nftpp
{

    class Expr
    {
    private:
        nftnl_expr *m_expr;

    public:
        // no implicit conversion. Expr owns pointer until desctructor/release call
        explicit Expr(nftnl_expr *expr) : m_expr(expr) {}

        ~Expr()
        {
            if (m_expr != nullptr)
            {
                nftnl_expr_free(m_expr);
            }
        }

        Expr(const Expr &) = delete;            // delete copy constructor
        Expr &operator=(const Expr &) = delete; // delete copy assignment

        // move constructor
        Expr(Expr &&other) noexcept : m_expr(other.m_expr)
        {
            other.m_expr = nullptr;
        }

        // move assignment
        Expr &operator=(Expr &&other) noexcept
        {
            if (this != &other)
            {
                if (m_expr != nullptr)
                {
                    nftnl_expr_free(m_expr);
                }
                m_expr = other.m_expr;
                other.m_expr = nullptr;
            }
            return *this;
        }

        nftnl_expr *native_handle() const { return m_expr; }

        // cedes ownership of nftnl_expr... caller is responsible for clean up
        [[nodiscard]] nftnl_expr *release()
        {
            nftnl_expr *tmp = m_expr;
            m_expr = nullptr;
            return tmp;
        }
    };

}