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

#include <netinet/udp.h>

#include <memory>
#include <mutex>
#include <list>

#include "ogs-core.h"
#include "ogs-sbi.h"

#include "common.hh"
#include "ControllerFactory.hh"
#include "DistributionSession.hh"
#include "PacketController.hh"
#include "PacketForwardPacketisation.hh"
#include "PacketIngester.hh"
#include "PacketScheduler.hh"
#include "utilities.hh"
#include "openapi/model/CreateReqData.h"
#include "openapi/model/PktDistributionOperatingMode.h"

#include "PacketForwardOnlyController.hh"

using fiveg_mag_reftools::ModelException;
using fiveg_mag_reftools::ProblemCause;
using reftools::mbstf::PktDistributionOperatingMode;

MBSTF_NAMESPACE_START

// public:

PacketForwardOnlyController::PacketForwardOnlyController(DistributionSession &distributionSession)
    :PacketController(distributionSession)
{
    validateForwardOnlyDistributionSession(distributionSession);
}

PacketForwardOnlyController::~PacketForwardOnlyController()
{
}

// protected:
void PacketForwardOnlyController::setPacketFEC()
{
    // no FEC implemented yet
}

void PacketForwardOnlyController::unsetPacketFEC()
{
    // no FEC implemented yet
}

void PacketForwardOnlyController::reconfigurePacketFEC()
{
    // no FEC implemented yet
}

// Overhead beyond IP level is GTP header size + UDP header size
#define OVERHEAD (2 + sizeof(udphdr))

void PacketForwardOnlyController::setPacketPacketisation()
{
    SsmPort ssm;
    const auto &dist_session = distributionSession();
    const auto &tun_endpoint = dist_session.getTunnelAddr();
    in_port_t tun_port = dist_session.getTunnelPortNumber();
    uint16_t mtu = static_cast<uint16_t>(get_tunnelled_path_mtu(ssm, tun_endpoint, tun_port, GET_MTU_IP_PAYLOAD)) - OVERHEAD;
    ogs_debug("Creating packetiser with MTU = %u", mtu);
    packetPacketiser(new PacketForwardPacketisation(mtu));
}

void PacketForwardOnlyController::unsetPacketPacketisation()
{
    packetPacketiser(nullptr);
}

void PacketForwardOnlyController::reconfigurePacketPacketisation()
{
    auto packetiser = std::dynamic_pointer_cast<PacketForwardPacketisation>(packetPacketiser());
    if (packetiser) {
        SsmPort ssm;
        const auto &dist_session = distributionSession();
        const auto &tun_endpoint = dist_session.getTunnelAddr();
        in_port_t tun_port = dist_session.getTunnelPortNumber();
        uint16_t mtu = static_cast<uint16_t>(get_tunnelled_path_mtu(ssm, tun_endpoint, tun_port, GET_MTU_IP_PAYLOAD)) - OVERHEAD;
        packetiser->mtu(mtu);
        packetiser->reconfigure();
    }
}

// private:

void PacketForwardOnlyController::validateForwardOnlyDistributionSession(const DistributionSession &dist_session)
{
    const auto &create_req_data = dist_session.distributionSessionReqData();
    const auto &dist_sess = create_req_data->getDistSession();
    const auto &pkt_distr_data = dist_sess->getPktDistributionData();

    const auto &pkt_dist_oper_mode = pkt_distr_data.value()->getPktDistributionOperatingMode();
    if (pkt_dist_oper_mode->getValue() != PktDistributionOperatingMode::VAL_PACKET_FORWARD_ONLY) {
        throw std::logic_error("Expected pktDistributionOperatingMode to be PACKET_FORWARD_ONLY");
    }

    // Controller match found, now check the DistSession for Forward-Only irregularities

    const auto &up_traffic_flow_info = dist_sess->getUpTrafficFlowInfo();
    if (up_traffic_flow_info) {
        throw ModelException("upTrafficFlowInfo present in ForwardOnly mode", "PacketForwardOnlyController", "distSession.upTrafficFlowInfo", ProblemCause::OPTIONAL_IE_INCORRECT);
    }
}

namespace {
static const struct init {
    init() {
        ControllerFactory::registerController(new ControllerConstructor<PacketForwardOnlyController>);
    };
} g_init;
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
