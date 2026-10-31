// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include "nftpp/batch.hpp"
#include <libmnl/libmnl.h>
#include <system_error>
#include <poll.h>

#include <vector>

namespace
{

    void ensure_sndbuf(int fd, size_t needed)
    {

        int current = 0;
        socklen_t len = sizeof(current);
        if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &current, &len) < 0) // grab the current send-buffer size
        {
            int err = errno;
            throw std::system_error(err, std::generic_category(), "getsockopt(SO_SNDBUF) failed");
        }

        if (static_cast<size_t>(current) > needed)
            return; // send buffer can hold batch

        int want = static_cast<int>(needed);
        // try to raise the send buffer size (kernel doubles it as much times as is required to meet want size)
        if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &want, sizeof(want)) == 0)
            return;

        // if SNDBUFFORCE did not succeed, fallback to the /proc/sys/net/core/wmem_max size
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &want, sizeof(want));

        // check if this SO_SNDBUF succeeded
        if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &current, &len) < 0)
        {
            int err = errno;
            throw std::system_error(err, std::generic_category(), "getsockopt(SO_SNDBUF) failed");
        }

        // if still less than needed, throw!
        if (static_cast<size_t>(current) < needed)
        {
            throw std::system_error(EMSGSIZE, std::generic_category(),
                                    "batch is " + std::to_string(needed) +
                                        " bytes but socket send buffer is only " + std::to_string(current));
        }
    }
}

namespace nftpp
{

    void Batch::commit(const Table &table)
    {
        int fd = mnl_socket_get_fd(m_socket);
        char *buf = static_cast<char *>(nftnl_batch_buffer(m_batch)); // grab the current pointer

        nftnl_batch_begin(buf, m_seq++);
        nftnl_batch_update(m_batch);

        buf = static_cast<char *>(nftnl_batch_buffer(m_batch));

        // serialize the table... the function internally ORs our flag with NLM_F_REQUEST
        nlmsghdr *nlh = nftnl_table_nlmsg_build_hdr(buf, NFT_MSG_NEWTABLE, table.family(), NLM_F_CREATE, m_seq++);
        nftnl_table_nlmsg_build_payload(nlh, table.native_handle());
        nftnl_batch_update(m_batch);

        // update the internal current pointer
        buf = static_cast<char *>(nftnl_batch_buffer(m_batch));

        for (const Chain &c : table.chains())
        {
            nlmsghdr *nlh = nftnl_chain_nlmsg_build_hdr(buf, NFT_MSG_NEWCHAIN, table.family(), NLM_F_CREATE, m_seq++);
            nftnl_chain_nlmsg_build_payload(nlh, c.native_handle());
            nftnl_batch_update(m_batch);
            buf = static_cast<char *>(nftnl_batch_buffer(m_batch));

            for (const Rule &r : c.rules())
            {
                nlmsghdr *nlh = nftnl_rule_nlmsg_build_hdr(buf, NFT_MSG_NEWRULE, table.family(), NLM_F_CREATE, m_seq++);
                nftnl_rule_nlmsg_build_payload(nlh, r.native_handle());
                nftnl_batch_update(m_batch);
                buf = static_cast<char *>(nftnl_batch_buffer(m_batch));
            }
        }

        nftnl_batch_end(buf, m_seq++);
        nftnl_batch_update(m_batch);

        // get the iov len
        size_t iov_count = static_cast<size_t>(nftnl_batch_iovec_len(m_batch));
        long iov_max = sysconf(_SC_IOV_MAX); // check system's max iov count

        if (iov_count > iov_max) // throw if pages count exceed the sys max. Kernel returns the EMSGSIZE error
        {
            throw std::system_error(EMSGSIZE, std::generic_category(),
                                    "batch too large: " + std::to_string(iov_count) +
                                        " pages, max " + std::to_string(iov_max));
        }

        std::vector<iovec> iov(iov_count);

        nftnl_batch_iovec(m_batch, iov.data(), static_cast<uint32_t>(iov_count));

        // build iovec msg
        msghdr msg{};
        msg.msg_iovlen = iov_count;
        msg.msg_iov = iov.data();

        // ensure the kernel send buffer size can hold our total buffer size
        size_t total = 0;
        for (const auto &v : iov)
        {
            total += v.iov_len;
        }

        // throws if total batch size is still greater than send buffer size
        ensure_sndbuf(fd, total);

        if (sendmsg(fd, &msg, 0) < 0)
        {
            int err = errno;
            throw std::system_error(err, std::generic_category(), "sendmsg() failed");
        }

        char rbuf[MNL_SOCKET_BUFFER_SIZE]; // receive buffer

        // poll the socket with zero timeout (checks and returns immediately)
        // the kernel runs the nftables instructions inside the sendmsg sys call... by the time it returns, if there are errors, they should already be in the queue.

        int first_error = 0; // 0 means "nothing written down yet"
        uint32_t failed_seq = 0;

        while (true)
        {

            pollfd pfd{};
            pfd.fd = fd;
            pfd.events = POLLIN;

            int ready = poll(&pfd, 1, 0);

            if (ready < 0)
            {
                if (errno == EINTR) // e.g SIGINT, SIGTERM ... a signal interrupt
                    continue;
                int err = errno;
                throw std::system_error(err, std::generic_category(), "poll() failed");
            }

            // timeout expired. receive queue is empty (POLLIN). No more replies. Implied success
            if (ready == 0)
                break;

            // something is in the queue at this point
            int ret = mnl_socket_recvfrom(m_socket, rbuf, sizeof(rbuf)); // ret is the size of bytes in the receive queue
            if (ret < 0)
            {
                int err = errno;
                throw std::system_error(err, std::generic_category(), "recvfrom() failed");
            }

            // walk the datagram... there could be several messages in one datagram
            int len = ret;
            for (const nlmsghdr *nlh = reinterpret_cast<const nlmsghdr *>(rbuf);
                 mnl_nlmsg_ok(nlh, len); nlh = mnl_nlmsg_next(nlh, &len))
            {
                if (nlh->nlmsg_type != NLMSG_ERROR)
                    continue;

                if (mnl_nlmsg_get_payload_len(nlh) < sizeof(nlmsgerr))
                    continue;

                const auto *msg_err = static_cast<const nlmsgerr *>(mnl_nlmsg_get_payload(nlh));
                if (msg_err->error != 0 && first_error == 0)
                {
                    first_error = msg_err->error;
                    failed_seq = msg_err->msg.nlmsg_seq; // which message failed
                }
            }
        }
        if (first_error != 0)
        {
            throw std::system_error(-first_error, std::generic_category(),
                                    "kernel rejected batch at message seq " + std::to_string(failed_seq));
        }
    }
}