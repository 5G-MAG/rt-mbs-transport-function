#ifndef _MBS_TF_PACKET_HH_
#define _MBS_TF_PACKET_HH_
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

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "common.hh"

MBSTF_NAMESPACE_START

class Packet {
public:
    class DataView {
    public:
        DataView() :m_ptr(nullptr), m_len(0) {};
        DataView(const uint8_t *data, size_t len) :m_ptr(data), m_len(len) {};
        template<class T>
        DataView(const std::vector<T> &vec, size_t offset, size_t len)
            :m_ptr(reinterpret_cast<const uint8_t*>(vec.data()+std::min(vec.size(),offset)))
            ,m_len(sizeof(T) * std::min(vec.size()-std::min(vec.size(),offset),len))
        {};
        template<class T>
        DataView(const std::vector<T> &vec, size_t offset = 0)
            :m_ptr(reinterpret_cast<const uint8_t*>(vec.data()+std::min(vec.size(),offset)))
            ,m_len(sizeof(T) * (vec.size()-std::min(vec.size(),offset)))
        {};
        template<class CharT>
        DataView(const std::basic_string<CharT> &str) :m_ptr(reinterpret_cast<const uint8_t*>(str.data())), m_len(sizeof(CharT) * str.size()) {};
        template<class CharT>
        DataView(const std::basic_string_view<CharT> &str) :m_ptr(reinterpret_cast<const uint8_t*>(str.data())), m_len(sizeof(CharT) * str.size()) {};
        template<class T, size_t N>
        DataView(const std::array<T,N> &arr) :m_ptr(reinterpret_cast<const uint8_t*>(arr.data())), m_len(sizeof(T)*N) {};

        const uint8_t *begin() const { return m_ptr; };
        const uint8_t *end() const { return m_ptr + m_len; };
        const uint8_t *cbegin() const { return m_ptr; };
        const uint8_t *cend() const { return m_ptr + m_len; };

        size_t size() const { return m_len; };
        const uint8_t *data() const { return m_ptr; };

    private:
        const uint8_t *m_ptr;
        size_t m_len;
    };

    Packet();
    Packet(const uint8_t *buffer, size_t buffer_size, bool encapsulated_hdrs = false);
    Packet(struct msghdr *msg_hdr, const std::shared_ptr<struct sockaddr> &listen_address, bool encapsulated_hdrs = false);
    Packet(const Packet &other);
    Packet(Packet &&other);

    virtual ~Packet() {};

    Packet &operator=(const Packet &other);
    Packet &operator=(Packet &&other);

    bool operator==(const Packet &other) const;

    bool setEncapsulatedUdpHeader(struct in6_addr *source_address, in_port_t source_port, struct in6_addr *dest_address, in_port_t dest_port, uint8_t ttl = 64);
    bool setEncapsulatedUdpHeader(struct in_addr *source_address, in_port_t source_port, struct in_addr *dest_address, in_port_t dest_port, uint8_t ttl = 64, bool do_not_fragment = false);

    size_t size() const { return m_payloadEndOffset - m_payloadOffset; };
    DataView payload() const { return DataView(m_packet, m_payloadOffset, m_payloadEndOffset - m_payloadOffset); };

    int family() const;         // family of the encapsulated packet or AF_UNSPEC if no encapsulation
    int originalFamily() const; // family of original packet, not the encapsulated packet, if known otherwise AF_UNSPEC
    bool doNotFragment() const; // encapsulated doNotFragment flag if IPv4 or true if encapsulated packet is IPv6
    std::shared_ptr<struct sockaddr> originalSourceAddress() const;
    std::shared_ptr<struct sockaddr> originalDestinationAddress() const;
    std::shared_ptr<struct sockaddr> encapsulatedSourceAddress() const;
    std::shared_ptr<struct sockaddr> encapsulatedDestinationAddress() const;

    Packet fragmentData(size_t max_payload_size);

    static uint16_t addChecksum(uint16_t current_checksum, const void *buffer, size_t buffer_len);

    static uint16_t checksum(const void *buffer, size_t buffer_len);

    template<class T>
    static uint16_t checksum(const std::vector<T> &buffer) {
        return checksum(reinterpret_cast<const void*>(buffer.data()), buffer.size() * sizeof(T));
    };

    template<class CharT>
    static uint16_t checksum(const std::basic_string<CharT> &buffer) {
        return checksum(reinterpret_cast<const void*>(buffer.data()), buffer.size() * sizeof(CharT));
    };

    template<class CharT>
    static uint16_t checksum(const std::basic_string_view<CharT> &buffer) {
        return checksum(reinterpret_cast<const void*>(buffer.data()), buffer.size() * sizeof(CharT));
    };

    template<class T, size_t N>
    static uint16_t checksum(const std::array<T,N> &buffer) {
        return checksum(reinterpret_cast<const void*>(buffer.data()), sizeof(T) * N);
    };

    int sendICMPNeedSmallerMTU(uint16_t mtu) const;

private:
    Packet &recalculateEncapsulatedSizesAndChecksums();
    int sendICMP(uint8_t typ, uint8_t code, uint32_t icmpdata, ssize_t original_ip_packet_bytes) const;
    int sendICMP6(uint8_t typ, uint8_t code, uint32_t icmpdata, ssize_t original_ip_packet_bytes) const;

    std::vector<uint8_t> m_packet;
    size_t m_originalPayloadOffset;
    size_t m_payloadOffset;
    size_t m_payloadEndOffset;
    size_t m_encapsulatedIpOffset; // equals m_payloadOffset or 0 if encapsulation not present
    size_t m_encapsulatedUdpOffset; // equals m_encapsulatedIpOffset + sizeof(iphdr) or 0 if encapsulated UDP not present
    size_t m_encapsulatedPayloadOffset; // equals m_encapsulatedUdpOffset + sizeof(udphdr) or 0 if encapsulation not present
    size_t m_fragmentOffset;
    bool m_moreFragments;
    bool m_haveEncapsulation;
    int m_originalIfc;
    std::shared_ptr<struct sockaddr> m_originalSourceAddress;
    socklen_t m_originalSourceAddressLen;
    std::shared_ptr<struct sockaddr> m_originalDestinationAddress;
    socklen_t m_originalDestinationAddressLen;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_PACKET_HH_ */
