#ifndef _MBS_TF_PACKET_FORWARD_ONLY_CONTROLLER_HH_
#define _MBS_TF_PACKET_FORWARD_ONLY_CONTROLLER_HH_
/**************************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Forward-Only Packet Controller class
 **************************************************************************************
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
#include "PacketController.hh"
#include "PacketIngester.hh"
#include "PacketScheduler.hh"

MBSTF_NAMESPACE_START

class DistributionSession;

class PacketForwardOnlyController : public PacketController {
public:
    PacketForwardOnlyController() = delete;
    PacketForwardOnlyController(DistributionSession &distributionSession);
    PacketForwardOnlyController(const PacketForwardOnlyController &) = delete;
    PacketForwardOnlyController(PacketForwardOnlyController &&) = delete;

    virtual ~PacketForwardOnlyController();

    PacketForwardOnlyController &operator=(const PacketForwardOnlyController &) = delete;
    PacketForwardOnlyController &operator=(PacketForwardOnlyController &&) = delete;

    // Controller virtual functions
    //virtual void reconfigure() //implemented in PacketController
    //virtual void establishInactiveInputs(); //implemented in PacketController
    //virtual void establishActiveInputs(); //implemented in PacketController
    //virtual void activateOutput(); //implemented in PacketController
    //virtual void deactivateOutput(); //implemented in PacketController
    //virtual void flushPacketisationQueue(); //implemented in PacketController

    static unsigned int factoryPriority() { return 100; };

protected:
    virtual void setPacketFEC();
    virtual void unsetPacketFEC();
    virtual void reconfigurePacketFEC();

    virtual void setPacketPacketisation();
    virtual void unsetPacketPacketisation();
    virtual void reconfigurePacketPacketisation();

    virtual bool expectEncapsulatedPackets() const { return true; };

private:
    static void validateForwardOnlyDistributionSession(const DistributionSession &dist_session);
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_PACKET_FORWARD_ONLY_CONTROLLER_HH_ */
