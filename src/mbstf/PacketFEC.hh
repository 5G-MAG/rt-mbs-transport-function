#ifndef _MBS_TF_PACKET_FEC_HH_
#define _MBS_TF_PACKET_FEC_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Packet FEC base class
 ******************************************************************************
 * Copyright: (C)2026 British Broadcasting Corporation
 * Author(s): David Waring <david.waring2@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include <memory>

#include "common.hh"
#include "PacketProcessing.hh"

MBSTF_NAMESPACE_START

class PacketFEC : public PacketProcessing {
public:
    PacketFEC() :PacketProcessing() {};
    PacketFEC(const PacketFEC &other) = delete;
    PacketFEC(PacketFEC &&other) :PacketProcessing(std::move(other)) {};

    virtual ~PacketFEC() {};

    PacketFEC &operator=(const PacketFEC &) = delete;
    PacketFEC &operator=(PacketFEC &&other) { PacketProcessing::operator=(std::move(other)); return *this; };

    virtual bool start() = 0;
    virtual bool isStarted() = 0;
    virtual bool stop() = 0;
    virtual bool flush() = 0;
    virtual bool reconfigure() = 0;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_PACKET_FEC_HH_ */
