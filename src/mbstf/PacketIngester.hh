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
#include <mutex>
#include <stdexcept>

#include "common.hh"
#include "PacketProcessing.hh"
#include "ThreadedWorker.hh"
#include "SsmPort.hh"

MBSTF_NAMESPACE_START

class PacketIngester : public PacketSource {
public:
    /** Thrown when the source address and port a unicast session names are already used by another session on
     *  the shared ingest port. */
    class AddressInUse : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    /** One source address and port on the shared ingest port, and the ingester using it.
     *
     * It is made by reserveShared() when the session is defined, and the session keeps it for its lifetime, so the pair
     * stays taken until the session has gone (the registry holds it weakly). The ingester attaches to it later.
     *
     * The receiver runs on its own thread, so it cannot know that the ingester has gone: it holds the lock while it
     * hands a packet to the ingester, and leaving takes the same lock and clears `ingester`, so the ingester is never
     * freed under a delivery (the same arrangement as PushObjectIngester::SharedLink). */
    struct SharedLink {
        std::recursive_mutex mtx;
        PacketIngester *ingester;
        bool running;
        explicit SharedLink(PacketIngester *i) :mtx(), ingester(i), running(true) {};
    };

    /** Whether mbstf.packetIngest names a fixed port, so unicast packet ingest sessions share one socket and are told
     *  apart by the source address and port of the Application Provider's tunnel. */
    static bool sharedPortConfigured();

    PacketIngester();
    PacketIngester(const std::shared_ptr<struct sockaddr> &listen_address, const std::shared_ptr<struct sockaddr> &remote_endpoint,
                   bool encapsulated_packets = false); // Unicast ingester
    /** Take the source address and port `remote_endpoint` on the shared ingest port. Throws AddressInUse if another
     *  session holds it, and std::out_of_range if it does not name one source address and port. Opens the shared socket
     *  on the first call. */
    static std::shared_ptr<SharedLink> reserveShared(const std::shared_ptr<struct sockaddr> &remote_endpoint);

    /** Unicast ingester on the shared ingest port, using a pair taken with reserveShared(). */
    PacketIngester(const std::shared_ptr<SharedLink> &reserved, const std::shared_ptr<struct sockaddr> &remote_endpoint,
                   bool encapsulated_packets);
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

    operator bool() const { return m_socket >= 0 || m_sharedLink; };

private:
    static void sharedReceiver();
    void deliverShared(struct msghdr &msg, size_t bytes);
    void leaveShared();
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
    std::shared_ptr<SharedLink> m_sharedLink; //!< set when this session uses the shared ingest port
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_PACKET_INGESTER_HH_ */
