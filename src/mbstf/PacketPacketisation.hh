#ifndef _MBS_TF_PACKET_PACKETISATION_HH_
#define _MBS_TF_PACKET_PACKETISATION_HH_
/*********************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Packet Packetisation base class
 *********************************************************************************
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
#include "PacketProcessing.hh"

MBSTF_NAMESPACE_START

class PacketPacketisation : public PacketProcessing {
public:
    PacketPacketisation(uint16_t mtu = 1500);
    PacketPacketisation(const PacketPacketisation &other) :m_mtu(other.m_mtu) {};
    PacketPacketisation(PacketPacketisation &&other) :m_mtu(other.m_mtu) {};

    virtual ~PacketPacketisation() {};

    PacketPacketisation &operator=(const PacketPacketisation &other) { m_mtu = other.m_mtu; return *this; };
    PacketPacketisation &operator=(PacketPacketisation &&other) { m_mtu = other.m_mtu; return *this; };

    virtual bool processPacket(Packet &buffer);

    virtual bool start() = 0;
    virtual bool isStarted() = 0;
    virtual bool stop() = 0;
    virtual bool flush() = 0;
    virtual bool reconfigure() = 0;
    virtual bool modifyPacket(Packet &buffer) { return true; };

    uint16_t mtu() const { return m_mtu; };
    PacketPacketisation &mtu(uint16_t mtu);

private:
    uint16_t m_mtu;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_PACKET_PACKETISATION_HH_ */
