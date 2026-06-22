/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Packetisation base class
 ******************************************************************************
 * Copyright: (C)2026 British Broadcasting Corporation
 * Author(s): David Waring <david.waring2@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include "ogs-core.h"
#include "ogs-sbi.h"

#include "common.hh"

#include "PacketPacketisation.hh"

MBSTF_NAMESPACE_START

PacketPacketisation::PacketPacketisation(uint16_t mtu)
    :m_mtu(mtu)
{
    ogs_debug("Created packetisation with mtu = %u", m_mtu);
}

bool PacketPacketisation::processPacket(Packet &buffer)
{
    //ogs_debug("Packetising %zu bytes", buffer.size());
    if (modifyPacket(buffer)) {
        if (buffer.size() > m_mtu) {
            ogs_debug("Packetising: Packet too big (%zu > %u) trying fragmentation", buffer.size(), m_mtu);
            if (buffer.doNotFragment()) {
                ogs_debug("Packetising: Do not fragment set, try to send ICMP response");
                sendEvent(PacketEvent::packetTooLargeEvent(m_mtu, buffer));
                return false;
            }

            while (buffer.size() > 0) {
                auto fragment = buffer.fragmentData(mtu());
                ogs_debug("Packetising: Sending fragment of %zu bytes", fragment.size());
                sendPacket(fragment);
            }
        } else {
            sendPacket(buffer);
        }
    } else {
        ogs_warn("Packetising: Packet modification failed, dropping packet");
    }
    return true;
}

PacketPacketisation &PacketPacketisation::mtu(uint16_t mtu)
{
    m_mtu = mtu;

    ogs_debug("Packetisation MTU changed to %u", m_mtu);

    return *this;
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
