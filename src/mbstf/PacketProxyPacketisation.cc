/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Packet ProxyPacketisation base class
 ******************************************************************************
 * Copyright: (C)2026 British Broadcasting Corporation
 * Author(s): David Waring <david.waring2@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "ogs-core.h"
#include "ogs-sbi.h"

#include "common.hh"
#include "PacketPacketisation.hh"
#include "utilities.hh"

#include "PacketProxyPacketisation.hh"

MBSTF_NAMESPACE_START

// public:

bool PacketProxyPacketisation::modifyPacket(Packet &buffer)
{
    auto opt_src_str = m_ssm.sourceAddress();
    if (!opt_src_str) return false; // Need a source address

    auto src_str = opt_src_str.value();
    auto dest_str = m_ssm.destinationAddress();
    auto port = m_ssm.port();

    auto src_addr = make_shared_sockaddr(AF_UNSPEC, src_str, port);
    if (!src_addr) return false;
    auto dest_addr = make_shared_sockaddr(src_addr->sa_family, dest_str, port);
    if (!dest_addr) return false;

    if (src_addr->sa_family == AF_INET) {
        auto src_sin = std::reinterpret_pointer_cast<struct sockaddr_in>(src_addr);
        auto dest_sin = std::reinterpret_pointer_cast<struct sockaddr_in>(dest_addr);

        buffer.setEncapsulatedUdpHeader(&src_sin->sin_addr, port, &dest_sin->sin_addr, port);
        return true;
    } else if (src_addr->sa_family == AF_INET6) {
        auto src_sin6 = std::reinterpret_pointer_cast<struct sockaddr_in6>(src_addr);
        auto dest_sin6 = std::reinterpret_pointer_cast<struct sockaddr_in6>(dest_addr);

        buffer.setEncapsulatedUdpHeader(&src_sin6->sin6_addr, port, &dest_sin6->sin6_addr, port);
        return true;
    }

    return false;
}

bool PacketProxyPacketisation::start()
{
    // Always started
    return true;
}

bool PacketProxyPacketisation::isStarted()
{
    // Always started
    return true;
}

bool PacketProxyPacketisation::stop()
{
    // We don't stop the packetisation as it's a throughput
    return true;
}

bool PacketProxyPacketisation::flush()
{
    // No queue, packetisation is always flushed
    return true;
}

bool PacketProxyPacketisation::reconfigure()
{
    // No resources to change
    return true;
}

// private:

void PacketProxyPacketisation::ssmToAddrs()
{
    m_srcAddr.reset();
    m_destAddr.reset();
    auto opt_src_str = m_ssm.sourceAddress();
    if (!opt_src_str) return;

    auto src_str = opt_src_str.value();
    auto dest_str = m_ssm.destinationAddress();
    auto port = m_ssm.port();

    // At the end of this m_srcAddr & m_destAddr will both have the same address family or will both be nullptr

    // Find any IPv4 or IPv6 address for the source
    m_srcAddr = make_shared_sockaddr(AF_UNSPEC, src_str, port);
    // If unresolvable return wil both addresses as nullptr
    if (!m_srcAddr) return;

    // Find a destination address of the same family as the source address
    m_destAddr = make_shared_sockaddr(m_srcAddr->sa_family, dest_str, port);
    if (!m_destAddr) {
        // if unable to find, then we try the other way around...
        m_srcAddr.reset();
        // get any IPv4 or IPv6 address for destination
        m_destAddr = make_shared_sockaddr(AF_UNSPEC, dest_str, port);
        // If unresolvable then return with both addresses as nullptr
        if (!m_destAddr) return;
        // Find a source address of the same family as the destination address
        m_srcAddr = make_shared_sockaddr(m_destAddr->sa_family, src_str, port);
        // If unable to find, then we give up and return with both addresses as nullptr
        if (!m_srcAddr) m_destAddr.reset();
    }

    if (m_srcAddr) {
        if (m_srcAddr->sa_family == AF_INET) {
            mtu(m_outerMTU - sizeof(iphdr) - sizeof(udphdr));
        } else if (m_srcAddr->sa_family == AF_INET) {
            mtu(m_outerMTU - sizeof(ip6_hdr) - sizeof(udphdr));
        }
    }
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
