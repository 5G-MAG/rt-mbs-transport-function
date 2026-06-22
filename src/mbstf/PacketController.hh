#ifndef _MBS_TF_PACKET_CONTROLLER_HH_
#define _MBS_TF_PACKET_CONTROLLER_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Packet Controller base class
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
#include <mutex>
#include <list>

#include "common.hh"
#include "Controller.hh"
#include "PacketIngester.hh"
#include "PacketScheduler.hh"

MBSTF_NAMESPACE_START

class DistributionSession;
class PacketPacketisation;
class PacketFEC;

class PacketController : public Controller {
public:
    PacketController() = delete;
    PacketController(DistributionSession &distributionSession);
    PacketController(const PacketController &) = delete;
    PacketController(PacketController &&) = delete;

    virtual ~PacketController();

    PacketController &operator=(const PacketController &) = delete;
    PacketController &operator=(PacketController &&) = delete;

    // Controller virtual functions
    virtual void reconfigure() {
        reconfigurePacketIngester();
        this->reconfigurePacketFEC();
        this->reconfigurePacketPacketisation();
        reconfigurePacketScheduler();
    };

    virtual void establishInactiveInputs(); /* Inactive state for DistSession */
    virtual void establishActiveInputs();   /* Established state for DistSession */
    virtual void activateOutput();          /* Active state for DistSession */
    virtual void deactivateOutput();        /* Deactivating state for DistSession */
    virtual void flushPackagerQueue();      /* Empty packaging queue */

    static void validateDistributionSession(DistributionSession &distribution_session);

protected:
    PacketIngester &packetIngester() { return m_ingester; };
    const PacketIngester &packetIngester() const { return m_ingester; };

    std::shared_ptr<PacketFEC> &packetFEC() { return m_fec; };
    const std::shared_ptr<PacketFEC> &packetFEC() const { return m_fec; };
    const std::shared_ptr<PacketFEC> &packetFEC(PacketFEC *fec);
    const std::shared_ptr<PacketFEC> &packetFEC(const std::shared_ptr<PacketFEC> &fec);
    const std::shared_ptr<PacketFEC> &packetFEC(std::shared_ptr<PacketFEC> &&fec);

    std::shared_ptr<PacketPacketisation> &packetPacketiser() { return m_packetiser; };
    const std::shared_ptr<PacketPacketisation> &packetPacketiser() const { return m_packetiser; };
    const std::shared_ptr<PacketPacketisation> &packetPacketiser(PacketPacketisation *packetiser);
    const std::shared_ptr<PacketPacketisation> &packetPacketiser(const std::shared_ptr<PacketPacketisation> &packetiser);
    const std::shared_ptr<PacketPacketisation> &packetPacketiser(std::shared_ptr<PacketPacketisation> &&packetiser);

    PacketScheduler &packetScheduler() { return m_scheduler; };
    const PacketScheduler &packetScheduler() const { return m_scheduler; };

    virtual void setPacketFEC() = 0;
    virtual void unsetPacketFEC() = 0;
    virtual void reconfigurePacketFEC() = 0;

    virtual void setPacketPacketisation() = 0;
    virtual void unsetPacketPacketisation() = 0;
    virtual void reconfigurePacketPacketisation() = 0;

    virtual bool expectEncapsulatedPackets() const { return false; };

private:
    void reconfigurePacketIngester();
    void reconfigurePacketScheduler();

    PacketIngester m_ingester;
    std::shared_ptr<PacketFEC> m_fec;
    std::shared_ptr<PacketPacketisation> m_packetiser;
    PacketScheduler m_scheduler;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_PACKET_CONTROLLER_HH_ */
