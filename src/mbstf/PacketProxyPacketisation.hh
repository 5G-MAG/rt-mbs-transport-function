#ifndef _MBS_TF_PACKET_PROXY_PACKETISATION_HH_
#define _MBS_TF_PACKET_PROXY_PACKETISATION_HH_
/**********************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Packet Proxy Packetisation class
 **********************************************************************************
 * Copyright: (C)2026 British Broadcasting Corporation
 * Author(s): David Waring <david.waring2@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "common.hh"
#include "PacketPacketisation.hh"
#include "SsmPort.hh"

MBSTF_NAMESPACE_START

class PacketProxyPacketisation : public PacketPacketisation {
public:
    PacketProxyPacketisation() = delete;
    PacketProxyPacketisation(uint16_t mtu, const SsmPort &ssm) :PacketPacketisation(mtu), m_outerMTU(mtu), m_ssm(ssm), m_srcAddr(), m_destAddr() {
        ssmToAddrs();
    };
    PacketProxyPacketisation(uint16_t mtu, SsmPort &&ssm) :PacketPacketisation(mtu), m_outerMTU(mtu), m_ssm(std::move(ssm)), m_srcAddr(), m_destAddr() {
        ssmToAddrs();
    };
    PacketProxyPacketisation(const PacketProxyPacketisation &other) = delete;
    PacketProxyPacketisation(PacketProxyPacketisation &&other)
        :PacketPacketisation(std::move(other))
        ,m_ssm(std::move(other.m_ssm))
        ,m_srcAddr(std::move(other.m_srcAddr))
        ,m_destAddr(std::move(other.m_destAddr))
    {};

    virtual ~PacketProxyPacketisation() {};

    PacketProxyPacketisation &operator=(const PacketProxyPacketisation &other) = delete;
    PacketProxyPacketisation &operator=(PacketProxyPacketisation &&other) {
        PacketPacketisation::operator=(std::move(other));
        m_ssm = std::move(other.m_ssm);
        m_srcAddr = std::move(other.m_srcAddr);
        m_destAddr = std::move(other.m_destAddr);
        return *this;
    };

    virtual bool modifyPacket(Packet &buffer);

    PacketProxyPacketisation &ssm(const SsmPort &ssm) { m_ssm = ssm; ssmToAddrs(); return *this; };
    PacketProxyPacketisation &ssm(SsmPort &&ssm) { m_ssm = std::move(ssm); ssmToAddrs(); return *this; };
    const SsmPort &ssm() const { return m_ssm; };
    const std::shared_ptr<struct sockaddr> &sourceSockaddr() const { return m_srcAddr; };
    const std::shared_ptr<struct sockaddr> &destinationSockaddr() const { return m_destAddr; };

    virtual bool start();
    virtual bool isStarted();
    virtual bool stop();
    virtual bool flush();
    virtual bool reconfigure();

private:
    void ssmToAddrs();

    uint16_t m_outerMTU;
    SsmPort m_ssm;
    std::shared_ptr<struct sockaddr> m_srcAddr;
    std::shared_ptr<struct sockaddr> m_destAddr;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_PACKET_PROXY_PACKETISATION_HH_ */
