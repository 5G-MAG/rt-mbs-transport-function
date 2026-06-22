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

#include "ogs-core.h"
#include "ogs-sbi.h"

#include "common.hh"
#include "PacketPacketisation.hh"

#include "PacketForwardPacketisation.hh"

MBSTF_NAMESPACE_START

// public:

bool PacketForwardPacketisation::start()
{
    // Always started
    return true;
}

bool PacketForwardPacketisation::isStarted()
{
    // Always started
    return true;
}

bool PacketForwardPacketisation::stop()
{
    // We don't stop the packetisation as it's a throughput
    return true;
}

bool PacketForwardPacketisation::flush()
{
    // No queue, packetisation is always flushed
    return true;
}

bool PacketForwardPacketisation::reconfigure()
{
    // No resources to change
    return true;
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
