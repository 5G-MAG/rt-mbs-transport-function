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

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <memory>
#include <mutex>
#include <list>

#include "common.hh"
#include "App.hh"
#include "Controller.hh"
#include "DistributionSession.hh"
#include "PacketFEC.hh"
#include "PacketIngester.hh"
#include "PacketPacketisation.hh"
#include "PacketScheduler.hh"
#include "SsmPort.hh"
#include "utilities.hh"
#include "openapi/model/CreateReqData.h"
#include "openapi/model/DistSession.h"
#include "openapi/model/PktDistributionData.h"
#include "openapi/model/ModelException.hh"
#include "openapi/model/ProblemCause.hh"
#include "openapi/model/MbStfIngestAddr.h"
#include "openapi/model/TunnelAddress.h"

#include "PacketController.hh"

using fiveg_mag_reftools::ModelException;
using fiveg_mag_reftools::ProblemCause;
using reftools::mbstf::Ipv6Addr;
using reftools::mbstf::MbStfIngestAddr;
using reftools::mbstf::PktIngestMethod;
using reftools::mbstf::TunnelAddress;

MBSTF_NAMESPACE_START

template<class TunAddr>
static std::shared_ptr<struct sockaddr> make_shared_sockaddr(const std::shared_ptr<TunAddr> &tunnel_addr);
static SsmPort make_ssm(const MbStfIngestAddr::AfSsmType::value_type &af_ssm);

PacketController::PacketController(DistributionSession &distributionSession)
    :Controller(distributionSession)
    ,m_ingester()
    ,m_fec()
    ,m_packetiser()
    ,m_scheduler()
{
    validateDistributionSession(distributionSession);
}

PacketController::~PacketController()
{
}

    // Controller virtual functions
void PacketController::establishInactiveInputs()
{
    /* Inactive state for DistSession */

    // stop ingester if it already exists, or create otherwise
    if (m_ingester) {
        m_ingester.stop();
    } else {
        auto &create_req_data = distributionSession().distributionSessionReqData();
        auto &dist_sess = create_req_data->getDistSession();
        auto &pkt_distr_data = dist_sess->getPktDistributionData().value();
        const auto &pkt_ingest_mode = pkt_distr_data->getPktIngestMethod();

        if (!pkt_ingest_mode || pkt_ingest_mode.value()->getValue() == PktIngestMethod::VAL_UNICAST) {
            bool is_encap = expectEncapsulatedPackets();
            std::shared_ptr<struct sockaddr> listen; // leave listening address as any (nullptr)
            const auto &af_egress_tun_addr = pkt_distr_data->getMbStfIngestAddr()->getAfEgressTunAddr();
            if (!af_egress_tun_addr) {
                throw ModelException("Missing AF Egress Tunnel Address for UNICAST ingest mode", "PacketController", "distSession.pktDistributionData.mbStfIngestAddr.afEgressTunAddr", ProblemCause::MANDATORY_IE_MISSING);
            }
            auto remote = make_shared_sockaddr(af_egress_tun_addr.value());
            try {
                m_ingester = PacketIngester(listen, remote, is_encap);
            } catch (const std::error_condition &ex) {
                ogs_error("Unable to create PacketIngester: %s", ex.message().c_str());
                return;
            }
            TunnelAddress local_listening_addr;
            const auto &local_addr = m_ingester.localSockAddr();
            if (local_addr.sa_family == AF_INET) {
                char buf[INET_ADDRSTRLEN];
                const auto *sin = reinterpret_cast<const struct sockaddr_in*>(&local_addr);
                if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf))) {
                    local_listening_addr.setIpv4Addr(std::string(buf));
                }
                local_listening_addr.setPortNumber(ntohs(sin->sin_port));
            } else if (local_addr.sa_family == AF_INET6) {
                char buf[INET6_ADDRSTRLEN];
                const auto *sin6 = reinterpret_cast<const struct sockaddr_in6*>(&local_addr);
                if (inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf))) {
                    local_listening_addr.setIpv6Addr(std::make_shared<Ipv6Addr>(buf));
                }
                local_listening_addr.setPortNumber(ntohs(sin6->sin6_port));
            }
            if (is_encap) {
                auto listen_addr = std::make_shared<MbStfIngestAddr::MbStfIngressTunAddrType::value_type::element_type>();
                listen_addr->setIpv4Addr(local_listening_addr.getIpv4Addr());
                listen_addr->setIpv6Addr(local_listening_addr.getIpv6Addr());
                listen_addr->setPortNumber(local_listening_addr.getPortNumber());
                pkt_distr_data->getMbStfIngestAddr()->setMbStfIngressTunAddr(listen_addr);
            } else {
                auto listen_addr = std::make_shared<MbStfIngestAddr::MbStfListenAddrType::value_type::element_type>();
                listen_addr->setIpv4Addr(local_listening_addr.getIpv4Addr());
                listen_addr->setIpv6Addr(local_listening_addr.getIpv6Addr());
                listen_addr->setPortNumber(local_listening_addr.getPortNumber());
                pkt_distr_data->getMbStfIngestAddr()->setMbStfListenAddr(listen_addr);
            }
        } else if (pkt_ingest_mode && pkt_ingest_mode.value()->getValue() == PktIngestMethod::VAL_MULTICAST) {
            const auto &af_ssm = pkt_distr_data->getMbStfIngestAddr()->getAfSsm();
            if (!af_ssm) {
                throw ModelException("Missing AF SSM Address for MULTICAST ingest mode", "PacketController", "distSession.pktDistributionData.mbStfIngestAddr.afSsm", ProblemCause::MANDATORY_IE_MISSING);
            }
            m_ingester = PacketIngester(make_ssm(af_ssm.value()));
        }
    }
    if (m_fec) m_fec->stop();
    if (m_packetiser) m_packetiser->stop();
    m_scheduler.stop();
}

void PacketController::establishActiveInputs()
{
    /* Established state for DistSession */
    m_ingester.start();
}

void PacketController::activateOutput()
{
    /* Active state for DistSession */
    if (!m_fec) setPacketFEC();
    if (m_fec) m_fec->start();

    if (!m_packetiser) setPacketPacketisation();
    if (m_packetiser) {
        m_packetiser->start();
        if (!m_scheduler) {
            const auto &distribution_session = distributionSession();
            uint64_t abr = static_cast<uint64_t>(distribution_session.getMbr().value_or(BitRate("10Kbps")).bitRate());
            uint64_t burst_bits = m_packetiser->mtu() * 2 * 8; // default to burst of 2 max packet sizes
            size_t max_buffer = App::self().context()->packetModeSchedulingQueueSize;
            std::shared_ptr<TunnelAddress> no_tunnel;
            std::shared_ptr<struct sockaddr> tunnel_endpoint = make_shared_sockaddr(distribution_session.getTunnel().value_or(no_tunnel));
            m_scheduler = PacketScheduler(burst_bits, abr, max_buffer, tunnel_endpoint.get(), m_packetiser.get());
        }
        m_scheduler.start();
    } else {
        ogs_warn("Attempt to go ACTIVE for PacketController without a packetisation");
        // distSession()->setState(inactive_state); <= ???
    }
}

void PacketController::deactivateOutput()
{
    /* Deactivating state for DistSession */
    if (m_fec) m_fec->stop();
    if (m_packetiser) m_packetiser->stop();
    m_scheduler.stop();
}

void PacketController::flushPackagerQueue()
{
    /* Empty packaging queue */
    if (m_fec) m_fec->flush();
    if (m_packetiser) m_packetiser->flush();
    m_scheduler.flush();
}

void PacketController::validateDistributionSession(DistributionSession &distribution_session)
{
    const auto &create_req_data = distribution_session.distributionSessionReqData();
    if (!create_req_data) {
        throw ModelException("CreateReqData missing", "PacketController", std::string(), ProblemCause::MANDATORY_IE_MISSING);
    }
    const auto &dist_session = create_req_data->getDistSession();
    if (!dist_session) {
        throw ModelException("distSession missing", "PacketController", "distSession", ProblemCause::MANDATORY_IE_MISSING);
    }
    const auto &pkt_distr_data = dist_session->getPktDistributionData();
    if (!pkt_distr_data || !pkt_distr_data.value()) {
        // throw logic error to indicate that this Controller is not right for the given distribution session, but another may be
        throw std::logic_error("Packet distribution operating mode requires pktDistributionData");
    }
}

// protected:

const std::shared_ptr<PacketFEC> &PacketController::packetFEC(PacketFEC *fec)
{
    std::shared_ptr<PacketFEC> new_fec{fec};
    return packetFEC(std::move(new_fec));
}

const std::shared_ptr<PacketFEC> &PacketController::packetFEC(const std::shared_ptr<PacketFEC> &fec)
{
    std::shared_ptr<PacketFEC> new_fec{fec};
    return packetFEC(std::move(new_fec));
}

const std::shared_ptr<PacketFEC> &PacketController::packetFEC(std::shared_ptr<PacketFEC> &&fec)
{
    bool started = (m_fec && m_fec->isStarted());
    m_fec = std::move(fec);
    if (m_fec) {
        m_fec->attachSource(&m_ingester);
        if (m_packetiser) {
            m_fec->attachSink(m_packetiser.get());
        } else {
            m_fec->attachSink(&m_scheduler);
        }
        if (started) {
            m_fec->start();
        } else {
            m_fec->stop();
        }
    }
    return m_fec;
}

const std::shared_ptr<PacketPacketisation> &PacketController::packetPacketiser(PacketPacketisation *packetisation)
{
    std::shared_ptr<PacketPacketisation> new_packetisation{packetisation};
    return packetPacketiser(std::move(new_packetisation));
}

const std::shared_ptr<PacketPacketisation> &PacketController::packetPacketiser(const std::shared_ptr<PacketPacketisation> &packetisation)
{
    std::shared_ptr<PacketPacketisation> new_packetisation{packetisation};
    return packetPacketiser(std::move(new_packetisation));
}

const std::shared_ptr<PacketPacketisation> &PacketController::packetPacketiser(std::shared_ptr<PacketPacketisation> &&packetisation)
{
    bool started = (m_packetiser && m_packetiser->isStarted());
    m_packetiser = std::move(packetisation);
    if (m_packetiser) {
        m_packetiser->attachSink(&m_scheduler);
        if (m_fec) {
            m_packetiser->attachSource(m_fec.get());
        } else {
            m_packetiser->attachSource(&m_ingester);
        }
        if (started) {
            m_packetiser->start();
        } else {
            m_packetiser->stop();
        }
    }
    return m_packetiser;
}

// private:

void PacketController::reconfigurePacketIngester()
{
    m_ingester.reconfigure();
}

void PacketController::reconfigurePacketScheduler()
{
    m_scheduler.reconfigure();
}

// Local functions

template<class TunAddr>
static std::shared_ptr<struct sockaddr> make_shared_sockaddr(const std::shared_ptr<TunAddr> &tunnel_addr)
{
    std::shared_ptr<struct sockaddr> ret;

    if (tunnel_addr) {
        std::string hostname;
        int family = AF_UNSPEC;
        in_port_t port = static_cast<in_port_t>(tunnel_addr->getPortNumber());
        const auto &ipv6_addr = tunnel_addr->getIpv6Addr();
        if (ipv6_addr) {
            hostname = *ipv6_addr.value();
            family = AF_INET6;
        } else {
            const auto &ipv4_addr = tunnel_addr->getIpv4Addr();
            if (ipv4_addr) {
                hostname = ipv4_addr.value();
                family = AF_INET;
            }
        }

        ret = make_shared_sockaddr(family, hostname, port);
    }

    return ret;
}

static SsmPort make_ssm(const MbStfIngestAddr::AfSsmType::value_type &af_ssm)
{
    if (!af_ssm) return SsmPort();
    const auto &af_ssm_addr = af_ssm->getSsm();
    in_port_t af_ssm_port = static_cast<in_port_t>(af_ssm->getPortNumber());
    std::string dest;
    const auto &dest_ip_addr = *af_ssm_addr->getDestIpAddr();
    if (dest_ip_addr.getIpv6Addr()) dest = *dest_ip_addr.getIpv6Addr().value();
    else if (dest_ip_addr.getIpv4Addr()) dest = dest_ip_addr.getIpv4Addr().value();
    std::string src;
    const auto &src_ip_addr = *af_ssm_addr->getSourceIpAddr();
    if (src_ip_addr.getIpv6Addr()) src = *src_ip_addr.getIpv6Addr().value();
    else if (src_ip_addr.getIpv4Addr()) src = src_ip_addr.getIpv4Addr().value();
    return SsmPort(af_ssm_port, dest, src);
}


MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
