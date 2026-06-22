#ifndef _MBS_TF_PACKET_FORWARD_PACKETISATION_HH_
#define _MBS_TF_PACKET_FORWARD_PACKETISATION_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Packet ForwardPacketisation base class
 ******************************************************************************
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

MBSTF_NAMESPACE_START

class PacketForwardPacketisation : public PacketPacketisation {
public:
    PacketForwardPacketisation() = delete;
    PacketForwardPacketisation(uint16_t mtu) :PacketPacketisation(mtu) {};
    PacketForwardPacketisation(const PacketForwardPacketisation &other) = delete;
    PacketForwardPacketisation(PacketForwardPacketisation &&other)
        :PacketPacketisation(std::move(other))
    {};

    virtual ~PacketForwardPacketisation() {};

    PacketForwardPacketisation &operator=(const PacketForwardPacketisation &other) = delete;
    PacketForwardPacketisation &operator=(PacketForwardPacketisation &&other) {
        PacketPacketisation::operator=(std::move(other));
        return *this;
    };

    virtual bool start();
    virtual bool isStarted();
    virtual bool stop();
    virtual bool flush();
    virtual bool reconfigure();

private:
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_PACKET_FORWARD_PACKETISATION_HH_ */
