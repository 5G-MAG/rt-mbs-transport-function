/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Packet class
 ******************************************************************************
 * Copyright: (C)2026 British Broadcasting Corporation
 * Author(s): David Waring <david.waring2@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

#include <array>
#include <cstdint>
#include <vector>

#include "ogs-core.h"
#include "ogs-sbi.h"

#include "common.hh"

#include "Packet.hh"

MBSTF_NAMESPACE_START

static int g_rawIcmpv4Socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
static int g_rawIcmpv6Socket = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);

Packet::Packet()
    :m_packet(std::max(sizeof(iphdr), sizeof(ip6_hdr)) + sizeof(udphdr))
    ,m_originalPayloadOffset(std::max(sizeof(iphdr), sizeof(ip6_hdr)) + sizeof(udphdr))
    ,m_payloadOffset(std::max(sizeof(iphdr), sizeof(ip6_hdr)) + sizeof(udphdr))
    ,m_payloadEndOffset(std::max(sizeof(iphdr), sizeof(ip6_hdr)) + sizeof(udphdr))
    ,m_encapsulatedIpOffset(0)
    ,m_encapsulatedUdpOffset(0)
    ,m_encapsulatedPayloadOffset(0)
    ,m_fragmentOffset(0)
    ,m_moreFragments(false)
    ,m_haveEncapsulation(false)
    ,m_originalIfc(-1)
    ,m_originalSourceAddress()
    ,m_originalSourceAddressLen(0)
    ,m_originalDestinationAddress()
    ,m_originalDestinationAddressLen(0)
{
}

Packet::Packet(const uint8_t *buffer, size_t buffer_size, bool encapsulated_hdrs)
    :m_packet()
    ,m_originalPayloadOffset(encapsulated_hdrs?0:(std::max(sizeof(iphdr), sizeof(ip6_hdr)) + sizeof(udphdr)))
    ,m_payloadOffset(encapsulated_hdrs?0:(std::max(sizeof(iphdr), sizeof(ip6_hdr)) + sizeof(udphdr)))
    ,m_payloadEndOffset((encapsulated_hdrs?0:(std::max(sizeof(iphdr), sizeof(ip6_hdr)) + sizeof(udphdr))) + buffer_size)
    ,m_encapsulatedIpOffset(0)
    ,m_encapsulatedUdpOffset(0)
    ,m_encapsulatedPayloadOffset(0)
    ,m_fragmentOffset(0)
    ,m_moreFragments(false)
    ,m_haveEncapsulation(encapsulated_hdrs)
    ,m_originalIfc(-1)
    ,m_originalSourceAddress()
    ,m_originalSourceAddressLen(0)
    ,m_originalDestinationAddress()
    ,m_originalDestinationAddressLen(0)
{
    m_packet.reserve((encapsulated_hdrs?0:(std::max(sizeof(iphdr), sizeof(ip6_hdr)) + sizeof(udphdr))) + buffer_size);
    if (m_payloadOffset) m_packet.insert(m_packet.begin(), m_payloadOffset, 0);
    m_packet.insert(m_packet.end(), buffer, buffer + buffer_size);
    if (m_haveEncapsulation) {
        m_encapsulatedIpOffset = m_payloadOffset;
        const struct iphdr *ip = reinterpret_cast<const struct iphdr*>(buffer);
        if (ip->version == 4) {
            m_encapsulatedUdpOffset = m_encapsulatedIpOffset + ip->ihl * 4;
        } else if (ip->version == 6) {
            m_encapsulatedUdpOffset = m_encapsulatedIpOffset + sizeof(ip6_hdr);
            for (const struct ip6_ext *ip6e = reinterpret_cast<const struct ip6_ext*>(buffer + sizeof(ip6_hdr));
                 ip6e->ip6e_nxt != IPPROTO_UDP;
                 ip6e = reinterpret_cast<const struct ip6_ext*>(reinterpret_cast<const uint8_t*>(ip6e) + ip6e->ip6e_len)) {
                m_encapsulatedUdpOffset += ip6e->ip6e_len;
            }
        }
        if (m_encapsulatedUdpOffset) m_encapsulatedPayloadOffset = m_encapsulatedUdpOffset + sizeof(udphdr);
    }
}

Packet::Packet(struct msghdr *msg, const std::shared_ptr<struct sockaddr> &listen_address, bool encapsulated_hdrs)
    :m_packet()
    ,m_originalPayloadOffset(encapsulated_hdrs?0:(std::max(sizeof(iphdr), sizeof(ip6_hdr)) + sizeof(udphdr)))
    ,m_payloadOffset(encapsulated_hdrs?0:(std::max(sizeof(iphdr), sizeof(ip6_hdr)) + sizeof(udphdr)))
    ,m_payloadEndOffset((encapsulated_hdrs?0:(std::max(sizeof(iphdr), sizeof(ip6_hdr)) + sizeof(udphdr))) + msg->msg_iov->iov_len)
    ,m_encapsulatedIpOffset(0)
    ,m_encapsulatedUdpOffset(0)
    ,m_encapsulatedPayloadOffset(0)
    ,m_fragmentOffset(0)
    ,m_moreFragments(false)
    ,m_haveEncapsulation(encapsulated_hdrs)
    ,m_originalIfc(-1)
    ,m_originalSourceAddress()
    ,m_originalSourceAddressLen(0)
    ,m_originalDestinationAddress()
    ,m_originalDestinationAddressLen(0)
{
    auto *buffer = reinterpret_cast<const uint8_t*>(msg->msg_iov->iov_base);
    auto buffer_len = msg->msg_iov->iov_len;
    m_packet.reserve((encapsulated_hdrs?0:(std::max(sizeof(iphdr), sizeof(ip6_hdr)) + sizeof(udphdr))) + buffer_len);
    if (m_payloadOffset) m_packet.insert(m_packet.begin(), m_payloadOffset, 0);
    m_packet.insert(m_packet.end(), buffer, buffer + buffer_len);
    if (m_haveEncapsulation) {
        m_encapsulatedIpOffset = m_payloadOffset;
        const struct iphdr *ip = reinterpret_cast<const struct iphdr*>(buffer);
        if (ip->version == 4) {
            m_encapsulatedUdpOffset = m_encapsulatedIpOffset + ip->ihl * 4;
        } else if (ip->version == 6) {
            m_encapsulatedUdpOffset = m_encapsulatedIpOffset + sizeof(ip6_hdr);
            for (const struct ip6_ext *ip6e = reinterpret_cast<const struct ip6_ext*>(buffer + sizeof(ip6_hdr));
                 ip6e->ip6e_nxt != IPPROTO_UDP;
                 ip6e = reinterpret_cast<const struct ip6_ext*>(reinterpret_cast<const uint8_t*>(ip6e) + ip6e->ip6e_len)) {
                m_encapsulatedUdpOffset += ip6e->ip6e_len;
            }
        }
        if (m_encapsulatedUdpOffset) m_encapsulatedPayloadOffset = m_encapsulatedUdpOffset + sizeof(udphdr);
    }
    if (msg->msg_namelen > 0) {
        m_originalSourceAddress = std::reinterpret_pointer_cast<struct sockaddr>(std::make_shared<uint8_t[]>(msg->msg_namelen));
        m_originalSourceAddressLen = msg->msg_namelen;
        memcpy(m_originalSourceAddress.get(), msg->msg_name, msg->msg_namelen);
    }
    for (auto cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
            struct in_pktinfo pkt_info;
            memcpy(&pkt_info, CMSG_DATA(cmsg), sizeof(pkt_info));
            auto ipv4_addr = std::make_shared<struct sockaddr_in>();
            ipv4_addr->sin_family = AF_INET;
            ipv4_addr->sin_addr = pkt_info.ipi_addr;
            ipv4_addr->sin_port = listen_address?std::reinterpret_pointer_cast<struct sockaddr_in>(listen_address)->sin_port:0;
            m_originalIfc = pkt_info.ipi_ifindex;
            m_originalDestinationAddress = std::reinterpret_pointer_cast<struct sockaddr>(ipv4_addr);
            m_originalDestinationAddressLen = sizeof(struct sockaddr_in);
        } else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
            struct in6_pktinfo pkt_info;
            memcpy(&pkt_info, CMSG_DATA(cmsg), sizeof(pkt_info));
            auto ipv6_addr = std::make_shared<struct sockaddr_in6>();
            ipv6_addr->sin6_family = AF_INET6;
            ipv6_addr->sin6_addr = pkt_info.ipi6_addr;
            ipv6_addr->sin6_port = listen_address?std::reinterpret_pointer_cast<struct sockaddr_in6>(listen_address)->sin6_port:0;
            m_originalIfc = pkt_info.ipi6_ifindex;
            m_originalDestinationAddress = std::reinterpret_pointer_cast<struct sockaddr>(ipv6_addr);
            m_originalDestinationAddressLen = sizeof(struct sockaddr_in6);
        }
    }
}

Packet::Packet(const Packet &other)
    :m_packet(other.m_packet)
    ,m_originalPayloadOffset(other.m_originalPayloadOffset)
    ,m_payloadOffset(other.m_payloadOffset)
    ,m_payloadEndOffset(other.m_payloadEndOffset)
    ,m_encapsulatedIpOffset(other.m_encapsulatedIpOffset)
    ,m_encapsulatedUdpOffset(other.m_encapsulatedUdpOffset)
    ,m_encapsulatedPayloadOffset(other.m_encapsulatedPayloadOffset)
    ,m_fragmentOffset(other.m_fragmentOffset)
    ,m_moreFragments(other.m_moreFragments)
    ,m_haveEncapsulation(other.m_haveEncapsulation)
    ,m_originalIfc(other.m_originalIfc)
    ,m_originalSourceAddress(other.m_originalSourceAddress)
    ,m_originalSourceAddressLen(other.m_originalSourceAddressLen)
    ,m_originalDestinationAddress(other.m_originalDestinationAddress)
    ,m_originalDestinationAddressLen(other.m_originalDestinationAddressLen)
{
}

Packet::Packet(Packet &&other)
    :m_packet(std::move(other.m_packet))
    ,m_originalPayloadOffset(other.m_originalPayloadOffset)
    ,m_payloadOffset(other.m_payloadOffset)
    ,m_payloadEndOffset(other.m_payloadEndOffset)
    ,m_encapsulatedIpOffset(other.m_encapsulatedIpOffset)
    ,m_encapsulatedUdpOffset(other.m_encapsulatedUdpOffset)
    ,m_encapsulatedPayloadOffset(other.m_encapsulatedPayloadOffset)
    ,m_fragmentOffset(other.m_fragmentOffset)
    ,m_moreFragments(other.m_moreFragments)
    ,m_haveEncapsulation(other.m_haveEncapsulation)
    ,m_originalIfc(other.m_originalIfc)
    ,m_originalSourceAddress(std::move(other.m_originalSourceAddress))
    ,m_originalSourceAddressLen(other.m_originalSourceAddressLen)
    ,m_originalDestinationAddress(std::move(other.m_originalDestinationAddress))
    ,m_originalDestinationAddressLen(other.m_originalDestinationAddressLen)
{
}

Packet &Packet::operator=(const Packet &other)
{
    m_packet = other.m_packet;
    m_payloadOffset = other.m_payloadOffset;
    m_payloadEndOffset = other.m_payloadEndOffset;
    m_encapsulatedIpOffset = other.m_encapsulatedIpOffset;
    m_encapsulatedUdpOffset = other.m_encapsulatedUdpOffset;
    m_encapsulatedPayloadOffset = other.m_encapsulatedPayloadOffset;
    m_fragmentOffset = other.m_fragmentOffset;
    m_moreFragments = other.m_moreFragments;
    m_haveEncapsulation = other.m_haveEncapsulation;
    m_originalIfc = other.m_originalIfc;
    m_originalSourceAddress = other.m_originalSourceAddress;
    m_originalSourceAddressLen = other.m_originalSourceAddressLen;
    m_originalDestinationAddress = other.m_originalDestinationAddress;
    m_originalDestinationAddressLen = other.m_originalDestinationAddressLen;
    return *this;
}

Packet &Packet::operator=(Packet &&other)
{
    m_packet = std::move(other.m_packet);
    m_payloadOffset = other.m_payloadOffset;
    m_payloadEndOffset = other.m_payloadEndOffset;
    m_encapsulatedIpOffset = other.m_encapsulatedIpOffset;
    m_encapsulatedUdpOffset = other.m_encapsulatedUdpOffset;
    m_encapsulatedPayloadOffset = other.m_encapsulatedPayloadOffset;
    m_fragmentOffset = other.m_fragmentOffset;
    m_moreFragments = other.m_moreFragments;
    m_haveEncapsulation = other.m_haveEncapsulation;
    m_originalIfc = other.m_originalIfc;
    m_originalSourceAddress = std::move(other.m_originalSourceAddress);
    m_originalSourceAddressLen = other.m_originalSourceAddressLen;
    m_originalDestinationAddress = std::move(other.m_originalDestinationAddress);
    m_originalDestinationAddressLen = other.m_originalDestinationAddressLen;
    return *this;
}

bool Packet::operator==(const Packet &other) const
{
    return m_fragmentOffset == other.m_fragmentOffset && m_packet == other.m_packet;
}

bool Packet::setEncapsulatedUdpHeader(struct in_addr *source_address, in_port_t source_port,
                                      struct in_addr *dest_address, in_port_t dest_port,
                                      uint8_t ttl, bool do_not_fragment)
{
    size_t payload_start = m_payloadOffset;
    if (m_haveEncapsulation) {
        payload_start = m_encapsulatedPayloadOffset;
    }

    m_encapsulatedPayloadOffset = payload_start;
    m_encapsulatedUdpOffset = m_encapsulatedPayloadOffset - sizeof(udphdr);
    m_encapsulatedIpOffset = m_encapsulatedUdpOffset - sizeof(iphdr);
    m_payloadOffset = m_encapsulatedIpOffset;
    m_haveEncapsulation = true;

    struct iphdr *ip = reinterpret_cast<struct iphdr*>(m_packet.data() + m_encapsulatedIpOffset);
    ip->version = 4;
    ip->ihl = static_cast<uint8_t>(sizeof(iphdr)/4);
    ip->tos = 0;
    ip->id = 0;
    ip->frag_off = htons(do_not_fragment?0x4000:0);
    ip->ttl = ttl;
    ip->protocol = static_cast<uint8_t>(IPPROTO_UDP);
    ip->saddr = source_address->s_addr;
    ip->daddr = dest_address->s_addr;

    struct udphdr *udp = reinterpret_cast<struct udphdr*>(m_packet.data() + m_encapsulatedUdpOffset);
    udp->uh_sport = htons(source_port);
    udp->uh_dport = htons(dest_port);
    udp->uh_sum = 0;
    udp->uh_ulen = htons(static_cast<uint16_t>(m_payloadEndOffset - m_encapsulatedUdpOffset));
    struct {
        struct in_addr saddr;
        struct in_addr daddr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t udp_len;
    } pseudo_ip = {
        ip->saddr,
        ip->daddr,
        0,
        IPPROTO_UDP,
        udp->uh_ulen
    };
    udp->uh_sum = addChecksum(checksum(&pseudo_ip, sizeof(pseudo_ip)), udp, m_payloadEndOffset - m_encapsulatedUdpOffset);
    
    recalculateEncapsulatedSizesAndChecksums();

    return true;
}

bool Packet::setEncapsulatedUdpHeader(struct in6_addr *source_address, in_port_t source_port,
                                      struct in6_addr *dest_address, in_port_t dest_port,
                                      uint8_t ttl)
{
    size_t payload_start = m_payloadOffset;
    if (m_haveEncapsulation) {
        payload_start = m_encapsulatedPayloadOffset;
    }

    m_encapsulatedPayloadOffset = payload_start;
    m_encapsulatedUdpOffset = m_encapsulatedPayloadOffset - sizeof(udphdr);
    m_encapsulatedIpOffset = m_encapsulatedUdpOffset - sizeof(ip6_hdr);
    m_payloadOffset = m_encapsulatedIpOffset;
    m_haveEncapsulation = true;

    struct ip6_hdr *ip = reinterpret_cast<struct ip6_hdr*>(m_packet.data() + m_encapsulatedIpOffset);
    ip->ip6_vfc = 6;
    ip->ip6_nxt = IPPROTO_UDP;
    ip->ip6_hlim = ttl;
    ip->ip6_src = *source_address;
    ip->ip6_dst = *dest_address;

    struct udphdr *udp = reinterpret_cast<struct udphdr*>(m_packet.data() + m_encapsulatedUdpOffset);
    udp->uh_sport = htons(source_port);
    udp->uh_dport = htons(dest_port);
    udp->uh_sum = 0;
    udp->uh_ulen = htons(static_cast<uint16_t>(m_payloadEndOffset - m_encapsulatedUdpOffset));
    struct {
        struct in6_addr saddr;
        struct in6_addr daddr;
        uint32_t udp_len;
        uint16_t zero1;
        uint8_t zero2;
        uint8_t protocol;
    } pseudo_ip = {
        ip->ip6_src,
        ip->ip6_dst,
        htonl(static_cast<uint32_t>(m_payloadEndOffset - m_encapsulatedUdpOffset)),
        0, 0,
        IPPROTO_UDP
    };
    udp->uh_sum = addChecksum(checksum(&pseudo_ip, sizeof(pseudo_ip)), udp, m_payloadEndOffset - m_encapsulatedUdpOffset);

    recalculateEncapsulatedSizesAndChecksums();
    
    return true;
}

int Packet::originalFamily() const
{
    if (!m_originalSourceAddress) return AF_UNSPEC;
    return m_originalSourceAddress->sa_family;
}

int Packet::family() const
{
    if (m_haveEncapsulation) {
        const struct iphdr *ip = reinterpret_cast<const struct iphdr*>(m_packet.data() + m_encapsulatedIpOffset);
        if (ip->version == 4) return AF_INET;
        if (ip->version == 6) return AF_INET6;
    }
    return AF_UNSPEC;
}

bool Packet::doNotFragment() const
{
    if (!m_haveEncapsulation) return false;
    const struct iphdr *ip = reinterpret_cast<const struct iphdr*>(m_packet.data() + m_encapsulatedIpOffset);
    if (ip->version == 6) return true;
    if (ip->version == 4) return (ntohs(ip->frag_off) & 0x4000) != 0;
    return false;
}

uint16_t Packet::addChecksum(uint16_t current_checksum, const void *buffer, size_t buffer_len)
{
    uint64_t next_checksum = checksum(buffer, buffer_len);
    uint64_t result = (~current_checksum & 0xffff) + (~next_checksum & 0xffff);

    while (result > 0xFFFF) {
        result = (result & 0xFFFF) + (result >> 16);
    }

    return ~static_cast<uint16_t>(result);
}

uint16_t Packet::checksum(const void *buffer, size_t buffer_len)
{
    uint64_t result = 0;
    const uint32_t *buf32 = reinterpret_cast<const uint32_t*>(buffer);

    size_t i = buffer_len;
    while (i >= sizeof(uint32_t)) {
        result += *buf32++;
        i -= sizeof(uint32_t);
    }

    if (i > 0) {
        const uint8_t *buf8 = reinterpret_cast<const uint8_t*>(buf32);
        std::array<uint8_t, sizeof(uint32_t)> partial_word;
        size_t j = 0;
        while (i > 0) {
            partial_word[j++] = *buf8++;
            i--;
        }
        result += *reinterpret_cast<const uint32_t*>(partial_word.data());
    }

    while (result > 0xFFFF) {
        result = (result & 0xFFFF) + (result >> 16);
    }

    return ~static_cast<uint16_t>(result);
}

Packet Packet::fragmentData(size_t maximum_size)
{
    auto pl = payload();
    ogs_debug("Create fragment of size %zu from payload %sof size %zu", maximum_size, m_haveEncapsulation?"including encap ":"", pl.size());
    size_t new_payload_size;
    if (m_haveEncapsulation) {
        if (pl.size() > maximum_size) {
            auto hdrs_size = m_encapsulatedUdpOffset - m_encapsulatedIpOffset;
            // fragment payload size must be multiple of 8 unless it's the last packet
            new_payload_size = ((maximum_size - hdrs_size)&~static_cast<size_t>(7)) + hdrs_size;
        } else {
            new_payload_size = pl.size();
        }
    } else {
        if (pl.size() > (maximum_size - sizeof(udphdr) - sizeof(ip6_hdr))) {
            new_payload_size = (maximum_size - sizeof(udphdr) - sizeof(ip6_hdr))&~static_cast<size_t>(7);
        } else {
            new_payload_size = pl.size();
        }
    }

    Packet result{pl.data(), new_payload_size, m_haveEncapsulation};
    result.m_fragmentOffset = m_fragmentOffset;
    result.m_moreFragments = (pl.size() > new_payload_size);

    if (m_haveEncapsulation) {
        // recalculate checksums in headers of new packet
        result.recalculateEncapsulatedSizesAndChecksums();
        
        // reduce this encapsulated payload by size in new packet
        auto pl_remove_start = m_packet.begin() + m_encapsulatedUdpOffset;
        auto pl_remove_end = m_packet.begin() + m_encapsulatedIpOffset + new_payload_size;
        size_t enc_payload_bytes = pl_remove_end - pl_remove_start;
        m_packet.erase(pl_remove_start, pl_remove_end);
        m_payloadEndOffset -= enc_payload_bytes;
        m_fragmentOffset += enc_payload_bytes;
        m_encapsulatedPayloadOffset = m_encapsulatedUdpOffset;
        if (m_payloadEndOffset == m_encapsulatedUdpOffset) {
            // no data left, empty the packet
            m_packet.clear();
            m_encapsulatedIpOffset = m_encapsulatedUdpOffset = m_encapsulatedPayloadOffset = m_payloadEndOffset = m_payloadOffset = 0;
            m_haveEncapsulation = false;
        }
    } else {
        // reduce this payload by size of new packet
        m_packet.erase(m_packet.begin() + m_payloadOffset, m_packet.begin() + m_payloadOffset + new_payload_size);
        m_payloadEndOffset -= new_payload_size;
        m_fragmentOffset += new_payload_size + sizeof(udphdr);
    }

    return result;
}

int Packet::sendICMPNeedSmallerMTU(uint16_t mtu) const
{
    if (m_originalIfc < 0 || !m_originalSourceAddress || !m_originalDestinationAddress) {
        return 0; // return empty when we don't have original packet details
    }

    std::vector<uint8_t> buffer;

    if (m_originalSourceAddress->sa_family == AF_INET) {
        if (g_rawIcmpv4Socket < 0) return 0;
        uint16_t icmpdata[2] = {0, htons(mtu)};
        return sendICMP(3, 4, *reinterpret_cast<uint32_t*>(icmpdata), sizeof(iphdr) + 8);
    } else if (m_originalSourceAddress->sa_family == AF_INET6) {
        if (g_rawIcmpv6Socket < 0) return 0;
        uint32_t icmpdata = htonl(mtu);
        return sendICMP6(2, 0, icmpdata, -1);
    } else {
        ogs_warn("Unknown protocol, cannot send ICMP/ICMP6 packet too big message");
    }

    return 0;
}

// private:

Packet &Packet::recalculateEncapsulatedSizesAndChecksums()
{
    struct iphdr *ip4 = reinterpret_cast<struct iphdr*>(m_packet.data() + m_encapsulatedIpOffset);
    if (ip4->version == 4) {
        ip4->tot_len = htons(static_cast<uint16_t>(m_payloadEndOffset - m_encapsulatedIpOffset));
        ip4->frag_off = htons((ntohs(ip4->frag_off)&0xc000) | (m_moreFragments?0x2000:0) | ((m_fragmentOffset/8)&0x1fff));
        ip4->check = 0;
        ip4->check = checksum(ip4, sizeof(iphdr));
    } else if (ip4->version == 6) {
        struct ip6_hdr *ip6 = reinterpret_cast<struct ip6_hdr*>(ip4);
        ip6->ip6_plen = htons(m_payloadEndOffset - m_encapsulatedIpOffset);
    }
    return *this;
}

int Packet::sendICMP(uint8_t typ, uint8_t code, uint32_t icmpdata, ssize_t original_ip_packet_bytes) const
{
    ogs_debug("ICMP: type=%u, code=%u, data=0x%x", typ, code, icmpdata);

    //  0 0 0 0 0 0 0 0 0 0 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-------+-------+---------------+-------------------------------+
    // |Version| IHL(5)|      TOS      |         Total Length          | IPv4 Header
    // +-------+-------+---------------+-----+-------------------------+
    // |        Identification         |Flags|  Fragment Offset (0)    |
    // +---------------+---------------+-----+-------------------------+
    // |  Time to Live | Protocol (1)  |        Header checksum        |
    // +---------------+---------------+-------------------------------+
    // |                       Source Address                          |
    // +---------------------------------------------------------------+
    // |                     Destination Address                       |
    // +---------------+---------------+-------------------------------+
    // |      Type     |      Code     |           Checksum            | ICMP Header
    // +---------------+---------------+-------------------------------+
    // |  ICMP message specific data                                   |
    // +---------------------------------------------------------------+
    // |  First N bytes of the original message including IP and UDP   :
    // :  headers                                                      :

    if (original_ip_packet_bytes < 0) {
        // use all available space - base size on original packet size
        original_ip_packet_bytes = m_payloadEndOffset - m_originalPayloadOffset - sizeof(iphdr) - sizeof(icmphdr);
    }

    std::vector<uint8_t> packet;
    packet.reserve(sizeof(iphdr) + sizeof(icmphdr) + original_ip_packet_bytes);

    struct iphdr ip;
    ip.version = 4;
    ip.ihl = 5;
    ip.tos = 0;
    ip.id = 0;
    ip.frag_off = 0;
    ip.ttl = 64;
    ip.protocol = IPPROTO_ICMP;
    ip.check = 0;
    auto sin_orig_dst = std::reinterpret_pointer_cast<struct sockaddr_in>(m_originalDestinationAddress);
    ip.saddr = sin_orig_dst->sin_addr.s_addr; // going back from our address
    auto sin_orig_src = std::reinterpret_pointer_cast<struct sockaddr_in>(m_originalSourceAddress);
    ip.daddr = sin_orig_src->sin_addr.s_addr; // going to the original packet source
    //ip.check = checksum(&ip, sizeof(ip));
    packet.insert(packet.end(), reinterpret_cast<uint8_t*>(&ip), reinterpret_cast<uint8_t*>(&ip + 1));

    struct icmphdr icmp;
    icmp.type = typ;
    icmp.code = code;
    icmp.checksum = 0;
    icmp.un.gateway = icmpdata; // gateway used to access full 32 bits, icmpdata not necessarily a gateway address
    packet.insert(packet.end(), reinterpret_cast<uint8_t*>(&icmp), reinterpret_cast<uint8_t*>(&icmp + 1));
    auto icmp_cksum_it = packet.end() - 6;

    // Recreate original IP hdr
    ip.version = 4;
    ip.ihl = 5; // only IP header in this recreation, no extensions. Cannot recreate without access to raw packets
    ip.tos = 0; // may need to get this in a cmsg from recvmsg()
    ip.tot_len = htons(static_cast<uint16_t>(sizeof(iphdr) + sizeof(udphdr) + m_payloadEndOffset - m_originalPayloadOffset));
    ip.id = 0;  // not sure we can access this without reading raw packets
    ip.frag_off = 0; // no access to this without raw packets
    ip.ttl = 64; // may need to get this in a cmsg from recvmsg()
    ip.protocol = IPPROTO_UDP;
    ip.check = 0;
    ip.saddr = sin_orig_src->sin_addr.s_addr; // original source
    ip.daddr = sin_orig_dst->sin_addr.s_addr; // original destination
    ip.check = checksum(&ip, sizeof(ip));
    packet.insert(packet.end(), reinterpret_cast<uint8_t*>(&ip), reinterpret_cast<uint8_t*>(&ip + 1));

    original_ip_packet_bytes -= sizeof(iphdr);

    // Recreate original UDP header
    struct udphdr udp;
    udp.uh_sport = sin_orig_src->sin_port;
    udp.uh_dport = sin_orig_dst->sin_port;
    udp.uh_ulen = htons(static_cast<uint16_t>(sizeof(udphdr) + m_payloadEndOffset - m_originalPayloadOffset));
    udp.uh_sum = 0;

    struct {
        struct in_addr saddr;
        struct in_addr daddr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t udp_len;
    } pseudo_ip = {
        ip.saddr,
        ip.daddr,
        0,
        IPPROTO_UDP,
        udp.uh_ulen
    };

    // fake original checksum for full UDP packet
    udp.uh_sum = addChecksum(addChecksum(checksum(&pseudo_ip, sizeof(pseudo_ip)), &udp, sizeof(udp)), m_packet.data() + m_originalPayloadOffset, m_payloadEndOffset - m_originalPayloadOffset);

    packet.insert(packet.end(), reinterpret_cast<uint8_t*>(&udp), reinterpret_cast<uint8_t*>(&udp + 1));

    original_ip_packet_bytes -= sizeof(udphdr);

    // Add as much packet data as allowed
    if (original_ip_packet_bytes > 0) {
        packet.insert(packet.end(), m_packet.data() + m_originalPayloadOffset, m_packet.data() + std::min(m_originalPayloadOffset + original_ip_packet_bytes, m_payloadEndOffset));
    }

    // Fill in ICMP checksum
    *reinterpret_cast<uint16_t*>(&(*icmp_cksum_it)) = checksum(packet.data() + sizeof(iphdr), packet.size() - sizeof(iphdr));

    return sendto(g_rawIcmpv4Socket, packet.data(), packet.size(), 0, m_originalSourceAddress.get(), m_originalSourceAddressLen);
}

int Packet::sendICMP6(uint8_t typ, uint8_t code, uint32_t icmpdata, ssize_t original_ip_packet_bytes) const
{
    ogs_debug("ICMP6: type=%u, code=%u, data=0x%x", typ, code, icmpdata);

    //  0 0 0 0 0 0 0 0 0 0 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-------+---------------+---------------------------------------+
    // |Version| Traffic class |              Flow label               | IPv6 Header
    // +-------+---------------+-------+---------------+---------------+
    // |        Payload length         | Next Hdr (58) |   Hop limit   |
    // +-------------------------------+---------------+---------------+
    // |                                                               |
    // |                        Source Address                         |
    // |                                                               |
    // |                                                               |
    // +---------------------------------------------------------------+
    // |                                                               |
    // |                     Destination Address                       |
    // |                                                               |
    // |                                                               |
    // +---------------+---------------+-------------------------------+
    // |      Type     |      Code     |         Checksum              | ICMPv6 Header
    // +---------------+---------------+-------------------------------+
    // |  ICMP message specific data                                   |
    // +---------------------------------------------------------------+
    // |  First N bytes of the original message including IPv6 and UDP :
    // :  headers                                                      :

    if (original_ip_packet_bytes < 0) {
        // use all available space - base size on original packet size
        original_ip_packet_bytes = m_payloadEndOffset - m_originalPayloadOffset - sizeof(ip6_hdr) - sizeof(icmp6_hdr);
    }

    std::vector<uint8_t> packet;
    packet.reserve(sizeof(ip6_hdr) + sizeof(icmp6_hdr) + original_ip_packet_bytes);

    auto sin6_orig_src = std::reinterpret_pointer_cast<struct sockaddr_in6>(m_originalSourceAddress);
    auto sin6_orig_dst = std::reinterpret_pointer_cast<struct sockaddr_in6>(m_originalDestinationAddress);

    struct ip6_hdr ip;
    ip.ip6_vfc = 6;
    ip.ip6_nxt = IPPROTO_ICMPV6;
    ip.ip6_hlim = 64;
    ip.ip6_src = sin6_orig_dst->sin6_addr; // going back from our address
    ip.ip6_dst = sin6_orig_src->sin6_addr; // going to the original source
    packet.insert(packet.end(), reinterpret_cast<uint8_t*>(&ip), reinterpret_cast<uint8_t*>(&ip + 1));

    struct icmp6_hdr icmp;
    icmp.icmp6_type = typ;
    icmp.icmp6_code = code;
    icmp.icmp6_cksum = 0;
    icmp.icmp6_data32[0] = icmpdata;
    packet.insert(packet.end(), reinterpret_cast<uint8_t*>(&icmp), reinterpret_cast<uint8_t*>(&icmp + 1));
    auto icmp_cksum_it = packet.end() - 6;

    // Recreate original IPv6 hdr
    ip.ip6_vfc = 6;
    ip.ip6_nxt = IPPROTO_UDP;
    ip.ip6_hlim = 64;
    ip.ip6_src = sin6_orig_src->sin6_addr;
    ip.ip6_dst = sin6_orig_dst->sin6_addr;
    packet.insert(packet.end(), reinterpret_cast<uint8_t*>(&ip), reinterpret_cast<uint8_t*>(&ip + 1));

    original_ip_packet_bytes -= sizeof(ip6_hdr);

    // Recreate original UDP header
    struct udphdr udp;
    udp.uh_sport = sin6_orig_src->sin6_port;
    udp.uh_dport = sin6_orig_dst->sin6_port;
    udp.uh_ulen = htons(static_cast<uint16_t>(sizeof(udphdr) + m_payloadEndOffset - m_originalPayloadOffset));
    udp.uh_sum = 0;

    struct {
        struct in6_addr saddr;
        struct in6_addr daddr;
        uint32_t udp_len;
        uint16_t zero1;
        uint8_t zero2;
        uint8_t protocol;
    } pseudo_ip = {
        ip.ip6_src,
        ip.ip6_dst,
        htonl(static_cast<uint32_t>(sizeof(udphdr) + m_payloadEndOffset - m_originalPayloadOffset)),
        0, 0,
        IPPROTO_UDP
    };

    // fake original checksum for full UDP packet
    udp.uh_sum = addChecksum(addChecksum(checksum(&pseudo_ip, sizeof(pseudo_ip)), &udp, sizeof(udp)), m_packet.data() + m_originalPayloadOffset, m_payloadEndOffset - m_originalPayloadOffset);

    packet.insert(packet.end(), reinterpret_cast<uint8_t*>(&udp), reinterpret_cast<uint8_t*>(&udp + 1));

    original_ip_packet_bytes -= sizeof(udphdr);

    // Add as much packet data as allowed
    if (original_ip_packet_bytes > 0) {
        packet.insert(packet.end(), m_packet.data() + m_originalPayloadOffset, m_packet.data() + std::min(m_originalPayloadOffset + original_ip_packet_bytes, m_payloadEndOffset));
    }

    // Fill in ICMP checksum
    *reinterpret_cast<uint16_t*>(&(*icmp_cksum_it)) = checksum(packet.data() + sizeof(ip6_hdr), packet.size() - sizeof(ip6_hdr));

    return sendto(g_rawIcmpv6Socket, packet.data(), packet.size(), 0, m_originalSourceAddress.get(), m_originalSourceAddressLen);
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
