// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once
#include <time.h>
#include <stdexcept>
#include <unistd.h>

#include <libmnl/libmnl.h>
#include <libnftnl/batch.h>

#include "nftpp/table.hpp"

namespace nftpp
{
    class Batch
    {
    private:
        nftnl_batch *m_batch;
        mnl_socket *m_socket;
        uint32_t m_seq;

        const size_t BATCH_PAGE_SIZE = getpagesize() * 32;            // 128 KB pages
        const size_t BATCH_OVERRUN_SIZE = UINT16_MAX + getpagesize(); // covers max_msg_size

    public:
        Batch()
            : m_batch(nftnl_batch_alloc(BATCH_PAGE_SIZE, BATCH_OVERRUN_SIZE)),
              m_socket(mnl_socket_open(NETLINK_NETFILTER)),
              m_seq(time(NULL))
        {
            if (!m_batch)
                throw std::runtime_error("nftnl_batch_alloc() failed! Could not allocate m_batch");

            if (!m_socket)
                throw std::runtime_error("mnl_socket_open() failed");

            mnl_socket_bind(m_socket, 0, MNL_SOCKET_AUTOPID);
        }

        ~Batch()
        {
            if (m_batch)
                nftnl_batch_free(m_batch);
        }

        void commit(const Table &table);
    };
}