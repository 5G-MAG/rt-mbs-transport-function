#ifndef _MBS_TF_PACKET_INGESTER_HH_
#define _MBS_TF_PACKET_INGESTER_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Packet Ingest base class
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
#include "ThreadedWorker.hh"
#include "SsmPort.hh"

MBSTF_NAMESPACE_START

class PacketIngester : public PacketSource {
public:
    PacketIngester();
    PacketIngester(const std::shared_ptr<struct sockaddr> &listen_address, const std::shared_ptr<struct sockaddr> &remote_endpoint,
                   bool encapsulated_packets = false); // Unicast ingester
    PacketIngester(const SsmPort &multicast_source);   // Multicast ingester (not used with encapsulation)
    PacketIngester(const PacketIngester &other) = delete;
    PacketIngester(PacketIngester &&other);

    virtual ~PacketIngester();

    PacketIngester &operator=(const PacketIngester &) = delete;
    PacketIngester &operator=(PacketIngester &&);

    virtual bool processEvent(const std::shared_ptr<PacketEvent> &event);

    const struct sockaddr &localSockAddr() const;
    
    bool start();
    bool isStarted() const;
    bool stop();
    bool flush();
    bool reconfigure();

    operator bool() const { return m_socket >= 0; };

private:
    bool startWorker();
    bool stopWorker();
    void closeSocket();
    void sendICMPNeedSmallerMTU(uint16_t mtu, const Packet &pkt);

    SsmPort m_ssm;
    int m_socket;
    bool m_encapsulatedPackets;
    std::shared_ptr<struct sockaddr> m_localAddr;
    std::shared_ptr<struct sockaddr> m_remoteAddr;
    ThreadedWorker m_worker;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_PACKET_INGESTER_HH_ */
