#ifndef _MBS_TF_PACKET_MTU_HH_
#define _MBS_TF_PACKET_MTU_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: sizing the packets of a packet-mode session
 ******************************************************************************
 * Copyright: (C)2026 British Broadcasting Corporation
 * License: 5G-MAG Public License v1
 ******************************************************************************/
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include <optional>
#include <string>

#include "common.hh"

MBSTF_NAMESPACE_START

/** The largest IP packet that fits a path of the given MTU once it is carried in the tunnel to the MB-UPF: the path MTU
 * less the IP header of the outer packet (20 octets for IPv4, 40 for IPv6), its UDP header (8) and GTP_HEADER_SIZE.
 * The packet goes to the MB-UPF in a UDP datagram and the MB-UPF puts it in a GTP-U packet to the gNB. */
inline int inner_packet_mtu(int path_mtu, bool tunnel_is_ipv6)
{
    return path_mtu - static_cast<int>(tunnel_is_ipv6 ? sizeof(ip6_hdr) : sizeof(iphdr)) -
           static_cast<int>(sizeof(udphdr)) - GTP_HEADER_SIZE;
}

/** Whether the tunnel's address, as written, is an IPv6 one; an absent address is taken as IPv4. */
inline bool tunnel_address_is_ipv6(const std::optional<std::string> &tunnel_ip)
{
    return tunnel_ip.has_value() && tunnel_ip->find(':') != std::string::npos;
}

MBSTF_NAMESPACE_STOP

#endif /* _MBS_TF_PACKET_MTU_HH_ */
