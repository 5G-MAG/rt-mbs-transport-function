/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: SSM with Port class
 ******************************************************************************
 * Copyright: (C)2026 British Broadcasting Corporation
 * Author(s): David Waring <david.waring2@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */
#include <stdint.h>

#include <optional>
#include <string>
#include <utility>

#include "common.hh"
#include "openapi/model/IpAddr.h"
#include "openapi/model/UpTrafficFlowInfo.h"

#include "SsmPort.hh"

using reftools::mbstf::IpAddr;
using reftools::mbstf::UpTrafficFlowInfo;

MBSTF_NAMESPACE_START

static std::string _conv_IpAddr_to_string(const std::shared_ptr<IpAddr> &ip_addr);

/*** SsmPort class ***/

SsmPort::SsmPort()
    :m_sourceAddr()
    ,m_destAddr()
    ,m_port(0)
{
}

SsmPort::SsmPort(const std::shared_ptr<UpTrafficFlowInfo> &up_traffic_flow_info)
    :m_sourceAddr()
    ,m_destAddr()
    ,m_port(0)
{
    if (up_traffic_flow_info) {
        m_port = static_cast<in_port_t>(up_traffic_flow_info->getPortNumber());
        auto &src_addr = up_traffic_flow_info->getSrcIpAddr();
        if (src_addr) {
            m_sourceAddr = _conv_IpAddr_to_string(src_addr.value());
        }
        m_destAddr = _conv_IpAddr_to_string(up_traffic_flow_info->getDestIpAddr());
    }
}

SsmPort::SsmPort(in_port_t port, const std::string &multicast_destination, const std::optional<std::string> &unicast_source)
    :m_sourceAddr(unicast_source)
    ,m_destAddr(multicast_destination)
    ,m_port(port)
{
}

SsmPort::SsmPort(const SsmPort &other)
    :m_sourceAddr(other.m_sourceAddr)
    ,m_destAddr(other.m_destAddr)
    ,m_port(other.m_port)
{
}

SsmPort::SsmPort(SsmPort &&other)
    :m_sourceAddr(std::move(other.m_sourceAddr))
    ,m_destAddr(std::move(other.m_destAddr))
    ,m_port(other.m_port)
{
}

SsmPort &SsmPort::operator=(const SsmPort &other)
{
    m_sourceAddr = other.m_sourceAddr;
    m_destAddr = other.m_destAddr;
    m_port = other.m_port;
    return *this;
}

SsmPort &SsmPort::operator=(SsmPort &&other)
{
    m_sourceAddr = std::move(other.m_sourceAddr);
    m_destAddr = std::move(other.m_destAddr);
    m_port = other.m_port;
    return *this;
}

bool SsmPort::operator==(const SsmPort &other) const
{
    return m_port == other.m_port && m_destAddr == other.m_destAddr && m_sourceAddr == other.m_sourceAddr;
}

/*** Local functions ***/

static std::string _conv_IpAddr_to_string(const std::shared_ptr<IpAddr> &ip_addr)
{
    if (!ip_addr) return std::string();
    const auto &ipv4_addr = ip_addr->getIpv4Addr();
    if (ipv4_addr) return ipv4_addr.value();
    const auto &ipv6_addr = ip_addr->getIpv6Addr();
    if (ipv6_addr && ipv6_addr.value()) {
        return *ipv6_addr.value();
    }
    const auto &ipv6_prefix = ip_addr->getIpv6Prefix();
    if (ipv6_prefix && ipv6_prefix.value()) {
        return *ipv6_prefix.value();
    }
    return std::string();
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
