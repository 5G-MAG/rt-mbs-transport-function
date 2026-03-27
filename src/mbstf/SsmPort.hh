#ifndef _MBS_TF_SSM_PORT_HH_
#define _MBS_TF_SSM_PORT_HH_
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
#include <netinet/in.h>

#include <optional>
#include <string>
#include <utility>

#include "common.hh"

namespace reftools::mbstf {
    class UpTrafficFlowInfo;
}

MBSTF_NAMESPACE_START

class SsmPort {
public:
    SsmPort();
    SsmPort(const std::shared_ptr<reftools::mbstf::UpTrafficFlowInfo> &up_traffic_flow_info);
    SsmPort(in_port_t port, const std::string &multicast_destination, const std::optional<std::string> &unicast_source);
    SsmPort(const SsmPort &other);
    SsmPort(SsmPort &&other);

    virtual ~SsmPort() {};

    SsmPort &operator=(const SsmPort &other);
    SsmPort &operator=(SsmPort &&other);

    bool operator==(const SsmPort &other) const;
    bool operator!=(const SsmPort &other) const { return !(*this == other); };

    operator bool() const { return m_port != 0 && !m_destAddr.empty(); };

    const std::optional<std::string> &sourceAddress() const { return m_sourceAddr; };
    bool hasSourceAddress() const { return m_sourceAddr.has_value(); };
    SsmPort &sourceAddress(const std::nullopt_t &val) { m_sourceAddr.reset(); return *this; };
    SsmPort &sourceAddress(const std::optional<std::string> &val) { m_sourceAddr = val; return *this; };
    SsmPort &sourceAddress(std::optional<std::string> &&val) { m_sourceAddr = std::move(val); return *this; };
    SsmPort &sourceAddress(const std::string &val) { m_sourceAddr = val; return *this; };
    SsmPort &sourceAddress(std::string &&val) { m_sourceAddr = std::move(val); return *this; };

    const std::string &destinationAddress() const { return m_destAddr; };
    SsmPort &destinationAddress(const std::string &val) { m_destAddr = val; return *this; };
    SsmPort &destinationAddress(std::string &&val) { m_destAddr = std::move(val); return *this; };

    in_port_t port() const { return m_port; };
    SsmPort &port(in_port_t val) { m_port = val; return *this; };

private:
    std::optional<std::string> m_sourceAddr;
    std::string m_destAddr;
    in_port_t m_port;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */

#endif /* _MBS_TF_SSM_PORT_HH_ */
