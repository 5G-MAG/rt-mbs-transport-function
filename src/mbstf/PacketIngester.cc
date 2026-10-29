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

#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>

#include "ogs-core.h"
#include "ogs-sbi.h"

#include "common.hh"
#include "App.hh"
#include "Context.hh"
#include "Packet.hh"
#include "PacketProcessing.hh"
#include "ThreadedWorker.hh"

#include "PacketIngester.hh"

using namespace std::literals::chrono_literals;

MBSTF_NAMESPACE_START

static bool fill_sockaddr_by_hostname(void /*struct sockaddr*/ *addr, const std::string &hostname, int family);
static bool match_sockaddrs(const struct sockaddr *a, const struct sockaddr *b);
static const char *inet_sockaddr_to_str(const struct sockaddr *sa, char *buf, socklen_t buf_len);
static int get_interface_for_sockaddr(const struct sockaddr *sa);
static std::string shared_source_key(const struct sockaddr *sa);
static bool shared_source_is_specific(const struct sockaddr *sa);
static void shared_fill_advertised(const struct sockaddr_storage &bound, const std::optional<std::string> &advertise,
                                   struct sockaddr_storage &out);

/* Shared ingest port. With mbstf.packetIngest naming a fixed port, one UDP socket on it serves every unicast packet
   ingest session, so the port can be published (a container cannot publish a port it does not know when it starts).
   The sessions are told apart by the source address and port of the Application Provider's tunnel: TS 29.581 V18.6.0
   table 6.1.6.2.14-1, afEgressTunAddr: "The MBSTF shall use this information to validate the source IP address and port
   of incoming packets pertaining to the MBS User Data Ingest Session from the MBS Application Provider." */
static std::mutex s_sharedMtx;                       // guards everything below
static int s_sharedSocket = -1;
static std::thread s_sharedThread;
static std::atomic<bool> s_sharedStop{false};
static std::map<std::string, std::weak_ptr<PacketIngester::SharedLink> > s_sharedLinks; // source key -> session (held by the session)
static struct sockaddr_storage s_sharedAdvertised;   // what the Application Provider is told to send to
/* Backstop: stops and joins the receiver at exit, so that a joinable std::thread is not destroyed. The daemon does it
   earlier, from shutdownShared(). */
static struct SharedReceiverStopper {
    ~SharedReceiverStopper() { PacketIngester::shutdownShared(); }
} s_sharedReceiverStopper;

// public:

PacketIngester::PacketIngester()
    :PacketSource()
    ,m_ssm()
    ,m_socket(-1)
    ,m_encapsulatedPackets(false)
    ,m_localAddr()
    ,m_remoteAddr()
    ,m_worker()
{
    //ogs_debug("Construct empty ingester");
}

PacketIngester::PacketIngester(const std::shared_ptr<struct sockaddr> &listen_address,
                               const std::shared_ptr<struct sockaddr> &remote_endpoint,
                               bool encapsulated_packets) // Unicast ingester
    :PacketSource()
    ,m_ssm()
    ,m_socket(-1)
    ,m_encapsulatedPackets(encapsulated_packets)
    ,m_localAddr(listen_address)
    ,m_remoteAddr(remote_endpoint)
    ,m_worker()
{
    //ogs_debug("Construct unicast ingester");
    int family = AF_INET;
    if (m_localAddr) family = m_localAddr->sa_family;
    else if (m_remoteAddr) family = m_remoteAddr->sa_family;

    if (m_localAddr && m_remoteAddr && m_localAddr->sa_family != m_remoteAddr->sa_family) {
        throw std::out_of_range("Remote and local network address must be in the same family");
    }

    m_socket = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (m_socket < 0) throw std::generic_category().default_error_condition(errno);

    if (family == AF_INET) {
        int yes = 1;
        setsockopt(m_socket, IPPROTO_IP, IP_PKTINFO, &yes, sizeof(yes));
    } else if (family == AF_INET6) {
        int yes = 1;
        setsockopt(m_socket, IPPROTO_IPV6, IPV6_RECVPKTINFO, &yes, sizeof(yes));
    }

    if (m_localAddr) {
        socklen_t listen_length = 0;
        if (listen_address->sa_family == AF_INET) listen_length = sizeof(struct sockaddr_in);
        else if (listen_address->sa_family == AF_INET6) listen_length = sizeof(struct sockaddr_in6);
        if (listen_length> 0) {
            if (bind(m_socket, listen_address.get(), listen_length) == -1) {
                throw std::generic_category().default_error_condition(errno);
            }
        }
    }

    if (m_remoteAddr) {
        socklen_t remote_length = 0;
        if (m_remoteAddr->sa_family == AF_INET) remote_length = sizeof(struct sockaddr_in);
        else if (m_remoteAddr->sa_family == AF_INET6) remote_length = sizeof(struct sockaddr_in6);
        if (remote_length > 0) {
            if (connect(m_socket, m_remoteAddr.get(), remote_length) == -1) {
                throw std::generic_category().default_error_condition(errno);
            }
            std::shared_ptr<struct sockaddr_storage> ss{new struct sockaddr_storage};
            socklen_t ss_len = static_cast<socklen_t>(sizeof(*ss));
            auto sa = std::reinterpret_pointer_cast<struct sockaddr>(ss);
            if (!getsockname(m_socket, sa.get(), &ss_len)) {
                m_localAddr = sa;
            }
        }
    }
    
    {
        static const char unknown[] = "Unknown";
        char src_buf[INET6_ADDRSTRLEN + 6];
        auto src_str = inet_sockaddr_to_str(m_remoteAddr.get(), src_buf, sizeof(src_buf));
        if (!src_str) src_str = unknown;
        char dest_buf[INET6_ADDRSTRLEN + 6];
        auto dest_str = inet_sockaddr_to_str(m_localAddr.get(), dest_buf, sizeof(dest_buf));
        if (!dest_str) dest_str = unknown;
        ogs_debug("Opened unicast packet socket %s => %s", src_str, dest_str);
    }

    startWorker();
}

std::shared_ptr<PacketIngester::SharedLink> PacketIngester::reserveShared(const std::shared_ptr<struct sockaddr> &remote_endpoint)
{
    /* Sessions can only be told apart by one source address and port; a wildcard would match another session's
       packets as well. */
    if (!remote_endpoint || !shared_source_is_specific(remote_endpoint.get())) {
        throw std::out_of_range("a source address and port are needed to tell sessions apart on the shared packet ingest port");
    }
    const auto &ctx = App::self().context();
    if (!ctx || !ctx->packetIngest.address.has_value()) throw std::out_of_range("no shared packet ingest port is configured");

    /* A listener of one family only receives sources of that family; an IPv4 source also reaches an IPv6 listener, as an
       IPv4-mapped address (see shared_source_key). */
    const struct sockaddr_storage &listener = ctx->packetIngest.address.value();
    if (listener.ss_family == AF_INET && remote_endpoint->sa_family == AF_INET6 &&
        !IN6_IS_ADDR_V4MAPPED(&reinterpret_cast<const struct sockaddr_in6*>(remote_endpoint.get())->sin6_addr)) {
        throw std::out_of_range("the source is an IPv6 address, but the shared packet ingest port listens on IPv4");
    }

    /* Declared before the lock: if the holder lets go meanwhile, the link's deleter takes s_sharedMtx, which this thread
       must not hold then. */
    std::shared_ptr<SharedLink> holder;
    std::lock_guard<std::mutex> lock(s_sharedMtx);

    const std::string key = shared_source_key(remote_endpoint.get());
    auto taken = s_sharedLinks.find(key);
    if (taken != s_sharedLinks.end()) {
        if ((holder = taken->second.lock())) {
            char buf[INET6_ADDRSTRLEN + 8];
            throw AddressInUse(std::string("the source ") + (inet_sockaddr_to_str(remote_endpoint.get(), buf, sizeof(buf)) ? buf : "address") +
                               " is already used by another packet Distribution Session on the shared ingest port");
        }
        s_sharedLinks.erase(taken); // its session has gone
    }

    if (s_sharedSocket < 0) {
        const struct sockaddr_storage &bound = ctx->packetIngest.address.value();
        int fd = socket(bound.ss_family, SOCK_DGRAM, IPPROTO_UDP);
        if (fd < 0) throw std::generic_category().default_error_condition(errno);
        int yes = 1;
        if (bound.ss_family == AF_INET) setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &yes, sizeof(yes));
        else if (bound.ss_family == AF_INET6) {
            setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &yes, sizeof(yes));
            int v6only = 0; // IPv4 sources are taken too, as IPv4-mapped addresses (see shared_source_key)
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
        }
        socklen_t len = bound.ss_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
        if (bind(fd, reinterpret_cast<const struct sockaddr*>(&bound), len) == -1) {
            int err = errno;
            close(fd);
            ogs_error("Could not bind the configured packet ingest address: %s", strerror(err));
            throw std::generic_category().default_error_condition(err);
        }
        shared_fill_advertised(bound, ctx->packetIngest.advertise, s_sharedAdvertised);
        s_sharedSocket = fd;
        s_sharedStop = false;
        /* Kept for the life of the process once opened: a published port stays bound, and the receiver does nothing
           while no session holds a source address. Stopped by SharedReceiverStopper at exit. */
        s_sharedThread = std::thread(&PacketIngester::sharedReceiver);
        ogs_info("Packet ingest listening on the configured address for all unicast sessions");
    }

    /* The registry entry goes with the link, so that nothing of a finished session outlives it (the registry is static
       and lives past the shutdown check for leaked allocations). A later reservation of the same pair may have replaced
       the entry by then, hence the check that it is still expired. */
    std::shared_ptr<SharedLink> link(new SharedLink(nullptr), [key](SharedLink *l) {
        {
            std::lock_guard<std::mutex> lock(s_sharedMtx);
            auto it = s_sharedLinks.find(key);
            if (it != s_sharedLinks.end() && it->second.expired()) s_sharedLinks.erase(it);
        }
        delete l;
    });
    s_sharedLinks[key] = link;
    return link;
}

PacketIngester::PacketIngester(const std::shared_ptr<SharedLink> &reserved, const std::shared_ptr<struct sockaddr> &remote_endpoint,
                               bool encapsulated_packets) // Unicast ingester, shared port
    :PacketSource()
    ,m_ssm()
    ,m_socket(-1)
    ,m_encapsulatedPackets(encapsulated_packets)
    ,m_localAddr()
    ,m_remoteAddr(remote_endpoint)
    ,m_worker()
    ,m_sharedLink(reserved)
{
    if (!m_sharedLink) throw std::out_of_range("a reserved source address is needed for the shared packet ingest port");
    {
        std::lock_guard<std::mutex> lock(s_sharedMtx);
        auto adv = std::make_shared<struct sockaddr_storage>(s_sharedAdvertised);
        m_localAddr = std::reinterpret_pointer_cast<struct sockaddr>(adv);
    }
    std::lock_guard<std::recursive_mutex> lock(m_sharedLink->mtx);
    m_sharedLink->ingester = this;
    m_sharedLink->running = true;
}

PacketIngester::PacketIngester(const SsmPort &multicast_source) // Multicast ingester
    :PacketSource()
    ,m_ssm(multicast_source)
    ,m_socket(-1)
    ,m_encapsulatedPackets(false)
    ,m_localAddr()
    ,m_remoteAddr()
    ,m_worker()
{
    //ogs_debug("Construct multicast ingester");
    if (multicast_source.hasSourceAddress()) {
        struct group_source_req mreq = {};
        fill_sockaddr_by_hostname(&mreq.gsr_group, multicast_source.destinationAddress(), AF_UNSPEC);
        fill_sockaddr_by_hostname(&mreq.gsr_source, multicast_source.sourceAddress().value(), mreq.gsr_group.ss_family);
        mreq.gsr_interface = get_interface_for_sockaddr(reinterpret_cast<struct sockaddr*>(&mreq.gsr_source));
        int yes = 1;
        m_socket = socket(mreq.gsr_source.ss_family, SOCK_DGRAM, IPPROTO_UDP);
        if (m_socket < 0) throw std::generic_category().default_error_condition(errno);
        if (mreq.gsr_source.ss_family == AF_INET) {
            struct sockaddr_in any = {.sin_family = AF_INET, .sin_port = htons(multicast_source.port())};
            bind(m_socket, reinterpret_cast<struct sockaddr*>(&any), sizeof(any));
            setsockopt(m_socket, SOL_IP, IP_PKTINFO, &yes, sizeof(yes));
            setsockopt(m_socket, SOL_IP, MCAST_JOIN_SOURCE_GROUP, &mreq, sizeof(mreq));
            m_remoteAddr = std::reinterpret_pointer_cast<struct sockaddr>(std::make_shared<struct sockaddr_in>(*reinterpret_cast<struct sockaddr_in*>(&mreq.gsr_source)));
        } else if (mreq.gsr_source.ss_family == AF_INET6) {
            struct sockaddr_in6 any = {.sin6_family = AF_INET6, .sin6_port = htons(multicast_source.port())};
            bind(m_socket, reinterpret_cast<struct sockaddr*>(&any), sizeof(any));
            setsockopt(m_socket, SOL_IPV6, IPV6_RECVPKTINFO, &yes, sizeof(yes));
            setsockopt(m_socket, SOL_IPV6, MCAST_JOIN_SOURCE_GROUP, &mreq, sizeof(mreq));
            m_remoteAddr = std::reinterpret_pointer_cast<struct sockaddr>(std::make_shared<struct sockaddr_in6>(*reinterpret_cast<struct sockaddr_in6*>(&mreq.gsr_source)));
        }
    } else {
        struct group_req mreq = {};
        fill_sockaddr_by_hostname(&mreq.gr_group, multicast_source.destinationAddress(), AF_UNSPEC);
        int yes = 1;
        m_socket = socket(mreq.gr_group.ss_family, SOCK_DGRAM, IPPROTO_UDP);
        if (m_socket < 0) throw std::generic_category().default_error_condition(errno);
        if (mreq.gr_group.ss_family == AF_INET) {
            struct sockaddr_in any = {.sin_family = AF_INET, .sin_port = htons(multicast_source.port())};
            bind(m_socket, reinterpret_cast<struct sockaddr*>(&any), sizeof(any));
            setsockopt(m_socket, SOL_IP, IP_PKTINFO, &yes, sizeof(yes));
            setsockopt(m_socket, SOL_IP, MCAST_JOIN_GROUP, &mreq, sizeof(mreq));
        } else if (mreq.gr_group.ss_family == AF_INET6) {
            struct sockaddr_in6 any = {.sin6_family = AF_INET6, .sin6_port = htons(multicast_source.port())};
            bind(m_socket, reinterpret_cast<struct sockaddr*>(&any), sizeof(any));
            setsockopt(m_socket, SOL_IPV6, IPV6_RECVPKTINFO, &yes, sizeof(yes));
            setsockopt(m_socket, SOL_IPV6, MCAST_JOIN_GROUP, &mreq, sizeof(mreq));
        }
    }

    {
        char src_buf[INET6_ADDRSTRLEN + 8] = "Unspecified";
        if (m_remoteAddr) inet_sockaddr_to_str(m_remoteAddr.get(), src_buf, sizeof(src_buf));
        ogs_debug("Opened multicast packet socket from %s for group %s:%i", src_buf, multicast_source.destinationAddress().c_str(), multicast_source.port());
    }

    startWorker();
}

/* The receiver thread delivers to the ingester a link names, so while an ingester on the shared port is moved from, its
   link is held: the receiver then never reads it half moved. The lock is held until the new ingester is attached. */
std::unique_lock<std::recursive_mutex> PacketIngester::lockSharedLink(PacketIngester &other)
{
    if (!other.m_sharedLink) return std::unique_lock<std::recursive_mutex>();
    return std::unique_lock<std::recursive_mutex>(other.m_sharedLink->mtx);
}

PacketIngester::PacketIngester(PacketIngester &&other)
    :PacketIngester(std::move(other), lockSharedLink(other))
{
}

PacketIngester::PacketIngester(PacketIngester &&other, std::unique_lock<std::recursive_mutex> &&link_lock)
    :PacketSource(std::move(other))
    ,m_ssm(std::move(other.m_ssm))
    ,m_socket(other.m_socket)
    ,m_encapsulatedPackets(other.m_encapsulatedPackets)
    ,m_localAddr(std::move(other.m_localAddr))
    ,m_remoteAddr(std::move(other.m_remoteAddr))
    ,m_worker()
    ,m_sharedLink(std::move(other.m_sharedLink))
{
    //ogs_debug("Move constructor");
    other.stopWorker();
    other.m_socket = -1;
    if (m_sharedLink) {
        std::lock_guard<std::recursive_mutex> lock(m_sharedLink->mtx);
        m_sharedLink->ingester = this;
    }
}

PacketIngester::~PacketIngester()
{
    //ogs_debug("Destroy ingester");
    leaveShared();
    closeSocket();
    stopWorker();
}

PacketIngester &PacketIngester::operator=(PacketIngester &&other)
{
    //ogs_debug("Move operator");
    std::unique_lock<std::recursive_mutex> other_link_lock = lockSharedLink(other);
    stopWorker();
    leaveShared();
    bool worker_cancel = other.m_worker.isCancelled();
    other.stopWorker();
    PacketSource::operator=(std::move(other));
    m_ssm = std::move(other.m_ssm);
    closeSocket();
    m_socket = other.m_socket;
    other.m_socket = -1;
    m_encapsulatedPackets = other.m_encapsulatedPackets;
    m_localAddr = std::move(other.m_localAddr);
    m_remoteAddr = std::move(other.m_remoteAddr);
    m_sharedLink = std::move(other.m_sharedLink);
    if (m_sharedLink) {
        std::lock_guard<std::recursive_mutex> lock(m_sharedLink->mtx);
        m_sharedLink->ingester = this;
    }
    if (!worker_cancel && !m_sharedLink) startWorker();
    return *this;
}

bool PacketIngester::processEvent(const std::shared_ptr<PacketEvent> &event)
{
    //ogs_debug("PacketIngester::processEvent: event type = %i", event->eventType());
    if (event->eventType() == PacketEvent::PACKET_TOO_LARGE) {
        auto too_large_event = std::dynamic_pointer_cast<PacketTooLargeEvent>(event);
        if (!too_large_event) return false;

        auto packet = too_large_event->packet();
        sendICMPNeedSmallerMTU(too_large_event->expectedMTU(), packet);
    }
    return false;
}

bool PacketIngester::start()
{
    //ogs_debug("Start ingester");
    if (m_sharedLink) {
        std::lock_guard<std::recursive_mutex> lock(m_sharedLink->mtx);
        m_sharedLink->running = true;
        return true;
    }
    startWorker();
    return true;
}

bool PacketIngester::isStarted() const
{
    if (m_sharedLink) {
        std::lock_guard<std::recursive_mutex> lock(m_sharedLink->mtx);
        return m_sharedLink->running;
    }
    return m_worker.isRunning();
}

bool PacketIngester::stop()
{
    //ogs_debug("Stop ingester");
    if (m_sharedLink) {
        /* The source address stays reserved for this session; only the delivery stops. */
        std::lock_guard<std::recursive_mutex> lock(m_sharedLink->mtx);
        m_sharedLink->running = false;
        return true;
    }
    stopWorker();
    return true;
}

bool PacketIngester::flush()
{
    return true;
}

bool PacketIngester::reconfigure()
{
    return true;
}

const struct sockaddr &PacketIngester::localSockAddr() const
{
    return *m_localAddr;
}

// private:

void PacketIngester::shutdownShared()
{
    s_sharedStop = true;
    if (s_sharedThread.joinable()) s_sharedThread.join(); // the receiver takes s_sharedMtx, so not held here
    std::lock_guard<std::mutex> lock(s_sharedMtx);
    if (s_sharedSocket >= 0) { close(s_sharedSocket); s_sharedSocket = -1; }
}

bool PacketIngester::sharedPortConfigured()
{
    const auto &ctx = App::self().context();
    if (!ctx || !ctx->packetIngest.address.has_value()) return false;
    const auto &ss = ctx->packetIngest.address.value();
    if (ss.ss_family == AF_INET) return reinterpret_cast<const struct sockaddr_in*>(&ss)->sin_port != 0;
    if (ss.ss_family == AF_INET6) return reinterpret_cast<const struct sockaddr_in6*>(&ss)->sin6_port != 0;
    return false;
}

void PacketIngester::deliverShared(struct msghdr &msg, size_t bytes)
{
    msg.msg_iov->iov_len = bytes;
    Packet pkt{&msg, m_localAddr, m_encapsulatedPackets};
    sendPacket(pkt);
}

void PacketIngester::leaveShared()
{
    if (!m_sharedLink) return;
    std::shared_ptr<SharedLink> link = std::move(m_sharedLink);
    m_sharedLink.reset();

    /* Wait for a delivery that is in progress and no longer; after it the receiver finds no ingester. The source
       address stays taken for as long as the session holds the link. */
    std::lock_guard<std::recursive_mutex> lock(link->mtx);
    link->ingester = nullptr;
}

void PacketIngester::sharedReceiver()
{
    int fd;
    {
        std::lock_guard<std::mutex> lock(s_sharedMtx);
        fd = s_sharedSocket;
    }
    std::array<uint8_t, 65536> buffer;
    std::array<uint8_t, 65536> control_buffer;
    while (!s_sharedStop) {
        struct pollfd read_poll = { .fd = fd, .events = POLLIN, .revents = 0 };
        int presult = poll(&read_poll, 1, 100);
        if (presult < 0) {
            if (errno == EINTR) continue;
            ogs_error("Error polling the shared packet ingest socket: %s", strerror(errno));
            break;
        }
        if (presult == 0) continue;

        struct sockaddr_storage from_addr;
        struct iovec iov = { .iov_base = buffer.data(), .iov_len = buffer.size() };
        struct msghdr msg = {
            .msg_name = &from_addr,
            .msg_namelen = sizeof(from_addr),
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = control_buffer.data(),
            .msg_controllen = control_buffer.size(),
            .msg_flags = 0
        };
        ssize_t bytes = recvmsg(fd, &msg, 0);
        if (bytes <= 0) continue;

        std::shared_ptr<SharedLink> link;
        {
            std::lock_guard<std::mutex> lock(s_sharedMtx);
            auto it = s_sharedLinks.find(shared_source_key(reinterpret_cast<const struct sockaddr*>(&from_addr)));
            if (it != s_sharedLinks.end()) link = it->second.lock();
        }
        if (!link) {
            char buf[INET6_ADDRSTRLEN + 8];
            ogs_warn("Packet from unexpected source dropped: %s",
                     inet_sockaddr_to_str(reinterpret_cast<const struct sockaddr*>(&from_addr), buf, sizeof(buf)) ? buf : "Unknown address");
            continue;
        }
        std::lock_guard<std::recursive_mutex> lock(link->mtx);
        if (link->ingester && link->running) link->ingester->deliverShared(msg, static_cast<size_t>(bytes));
    }
}

bool PacketIngester::startWorker()
{
    //ogs_debug("Start worker");
    m_worker.startWorker("PacketIngester receiver", [this](std::function<void()> check_cancelled) {
        // Wait for socket to open
        //ogs_debug("Ingester: wait for socket");
        while (m_socket < 0) {
            std::this_thread::sleep_for(10ms);
            check_cancelled();
        }
        //ogs_debug("Ingester: got socket");

        // Receive packets and push them
        while (m_socket >= 0) {
            //ogs_debug("Ingester: wait for data");
            struct pollfd read_poll = {
                .fd = m_socket,
                .events = POLLIN,
                .revents = 0
            };
            auto presult = poll(&read_poll, 1, 10);
            if (presult > 0) {
                //ogs_debug("Ingester: data pending");
                check_cancelled();
                struct sockaddr_storage from_addr;
                auto *from_sa = reinterpret_cast<struct sockaddr*>(&from_addr);
                std::array<uint8_t, 65536> buffer;
                struct iovec iov = {
                    .iov_base = buffer.data(),
                    .iov_len = buffer.size()
                };
                std::array<uint8_t, 65536> control_buffer;
                struct msghdr msg = {
                    .msg_name = from_sa,
                    .msg_namelen = sizeof(from_addr),
                    .msg_iov = &iov,
                    .msg_iovlen = 1,
                    .msg_control = control_buffer.data(),
                    .msg_controllen = control_buffer.size(),
                    .msg_flags = 0
                };
                auto bytes = recvmsg(m_socket, &msg, 0);
                check_cancelled();
                if (bytes>0) {
                    //ogs_debug("Received %zu bytes", bytes);
                    if (match_sockaddrs(from_sa, m_remoteAddr.get())) {
                        //ogs_debug("Packet matches expected source, sending onward");
                        msg.msg_iov->iov_len = bytes;
                        Packet pkt{&msg, m_localAddr, m_encapsulatedPackets};
                        sendPacket(pkt);
                    } else {
                        char buf[INET6_ADDRSTRLEN + 6];
                        if (inet_sockaddr_to_str(from_sa, buf, sizeof(buf))) {
                            ogs_warn("Packet from unexpected source dropped: %s", buf);
                        } else {
                            ogs_warn("Packet from unexpected source dropped: Unknown address");
                        }
                    }
                } else { // Error or EOF
                    ogs_error("Error in stream, closing receiving socket: %s", strerror(errno));
                    closeSocket();
                }
            } else if (presult < 0) {
                // error on poll
                closeSocket();
            }
            check_cancelled();
        }
    });
    return true;
};

bool PacketIngester::stopWorker()
{
    //ogs_debug("Stop worker");
    if (!m_worker.isRunning()) return true;
    m_worker.cancel();
    return m_worker.join();
}

void PacketIngester::closeSocket()
{
    if (m_socket >= 0) {
        if (m_ssm) {
            if (m_ssm.hasSourceAddress()) {
                struct group_source_req mreq = {};
                fill_sockaddr_by_hostname(&mreq.gsr_group, m_ssm.destinationAddress(), AF_UNSPEC);
                fill_sockaddr_by_hostname(&mreq.gsr_source, m_ssm.sourceAddress().value(), mreq.gsr_group.ss_family);
                mreq.gsr_interface = get_interface_for_sockaddr(reinterpret_cast<struct sockaddr*>(&mreq.gsr_source));
                setsockopt(m_socket, mreq.gsr_group.ss_family, MCAST_LEAVE_SOURCE_GROUP, &mreq, sizeof(mreq));
            } else {
                struct group_req mreq = {};
                fill_sockaddr_by_hostname(&mreq.gr_group, m_ssm.destinationAddress(), AF_UNSPEC);
                setsockopt(m_socket, mreq.gr_group.ss_family, MCAST_LEAVE_GROUP, &mreq, sizeof(mreq));
            }
        }
        close(m_socket);
        m_socket = -1;
    }
}

void PacketIngester::sendICMPNeedSmallerMTU(uint16_t mtu, const Packet &pkt)
{
    if (pkt.sendICMPNeedSmallerMTU(mtu) < 0) {
        ogs_warn("Sending ICMP failed: %s", strerror(errno));
    }
} 

/**** Local functions ****/

static bool fill_sockaddr_by_hostname(void /*struct sockaddr*/ *addr, const std::string &hostname, int af_family)
{
    struct addrinfo *ai = nullptr;
    bool result = false;
    getaddrinfo(hostname.c_str(), nullptr, nullptr, &ai);
    if (ai) {
        for (const auto *it = ai; it; it = it->ai_next) {
            if ((af_family == AF_UNSPEC && (it->ai_family == AF_INET || it->ai_family == AF_INET6)) ||
                (af_family != AF_UNSPEC && af_family == it->ai_family)) {
                memcpy(addr, it->ai_addr, it->ai_addrlen);
                result = true;
                break;
            }
        }
        freeaddrinfo(ai);
    }
    return result;
}

static bool match_sockaddrs(const struct sockaddr *a, const struct sockaddr *b)
{
    if (!a || !b) return true; // match if either is NULL
    if (a->sa_family == AF_UNSPEC || b->sa_family == AF_UNSPEC) return true; // match if either is AF_UNSPEC
    if (a->sa_family != b->sa_family) return false; // Address families don't match
    if (a->sa_family == AF_INET) {
        const auto *a_sin = reinterpret_cast<const struct sockaddr_in*>(a);
        const auto *b_sin = reinterpret_cast<const struct sockaddr_in*>(b);
        if (a_sin->sin_addr.s_addr == INADDR_ANY || b_sin->sin_addr.s_addr == INADDR_ANY ||
            a_sin->sin_addr.s_addr == b_sin->sin_addr.s_addr) {

            return (a_sin->sin_port == 0 || b_sin->sin_port == 0 || a_sin->sin_port == b_sin->sin_port);
        }
    } else if (a->sa_family == AF_INET6) {
        const auto *a_sin6 = reinterpret_cast<const struct sockaddr_in6*>(a);
        const auto *b_sin6 = reinterpret_cast<const struct sockaddr_in6*>(b);
        if (IN6_IS_ADDR_UNSPECIFIED(&a_sin6->sin6_addr.s6_addr) || IN6_IS_ADDR_UNSPECIFIED(&b_sin6->sin6_addr.s6_addr) ||
            IN6_ARE_ADDR_EQUAL(&a_sin6->sin6_addr.s6_addr32, &b_sin6->sin6_addr.s6_addr32)) {

            return (a_sin6->sin6_port == 0 || b_sin6->sin6_port == 0 || a_sin6->sin6_port == b_sin6->sin6_port);
        }
    }

    return false;
}

static const char *inet_sockaddr_to_str(const struct sockaddr *sa, char *buf, socklen_t buf_len)
{
    if (!sa) return nullptr;

    const void *sa_addr = nullptr;
    const in_port_t *sa_port = nullptr;

    if (sa->sa_family == AF_INET) {
        const auto *sin = reinterpret_cast<const struct sockaddr_in*>(sa);
        sa_addr = &sin->sin_addr;
        sa_port = &sin->sin_port;
    } else if (sa->sa_family == AF_INET6) {
        const auto *sin6 = reinterpret_cast<const struct sockaddr_in6*>(sa);
        sa_addr = &sin6->sin6_addr;
        sa_port = &sin6->sin6_port;
    }

    if (sa_addr) {
        const char *ret = inet_ntop(sa->sa_family, sa_addr, buf, buf_len);
        if (ret && *sa_port) {
            strcat(buf, std::format(":{}", ntohs(*sa_port)).c_str());
        }
        return ret;
    }

    return nullptr;
}

/* The source address and port as a map key. An IPv4 source seen through an IPv6 socket arrives as an IPv4-mapped
   address and keys the same as the IPv4 one. */
static std::string shared_source_key(const struct sockaddr *sa)
{
    if (!sa) return std::string();
    if (sa->sa_family == AF_INET) {
        const auto *sin = reinterpret_cast<const struct sockaddr_in*>(sa);
        std::string key("4:");
        key.append(reinterpret_cast<const char*>(&sin->sin_addr), sizeof(sin->sin_addr));
        key.append(reinterpret_cast<const char*>(&sin->sin_port), sizeof(sin->sin_port));
        return key;
    }
    if (sa->sa_family == AF_INET6) {
        const auto *sin6 = reinterpret_cast<const struct sockaddr_in6*>(sa);
        if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            std::string key("4:");
            key.append(reinterpret_cast<const char*>(&sin6->sin6_addr.s6_addr[12]), 4);
            key.append(reinterpret_cast<const char*>(&sin6->sin6_port), sizeof(sin6->sin6_port));
            return key;
        }
        std::string key("6:");
        key.append(reinterpret_cast<const char*>(&sin6->sin6_addr), sizeof(sin6->sin6_addr));
        key.append(reinterpret_cast<const char*>(&sin6->sin6_port), sizeof(sin6->sin6_port));
        return key;
    }
    return std::string();
}

static bool shared_source_is_specific(const struct sockaddr *sa)
{
    if (!sa) return false;
    if (sa->sa_family == AF_INET) {
        const auto *sin = reinterpret_cast<const struct sockaddr_in*>(sa);
        return sin->sin_addr.s_addr != INADDR_ANY && sin->sin_port != 0;
    }
    if (sa->sa_family == AF_INET6) {
        const auto *sin6 = reinterpret_cast<const struct sockaddr_in6*>(sa);
        return !IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr) && sin6->sin6_port != 0;
    }
    return false;
}

/* The address and port the Application Provider is told to send to: the configured advertise address when there is
   one (a published port is reached on the host, not on the container's own address), otherwise the bound address, or
   for a wildcard bind the local address of the default route, as the object push server does. */
static void shared_fill_advertised(const struct sockaddr_storage &bound, const std::optional<std::string> &advertise,
                                   struct sockaddr_storage &out)
{
    out = bound;
    const in_port_t port = bound.ss_family == AF_INET6 ? reinterpret_cast<const struct sockaddr_in6*>(&bound)->sin6_port
                                                       : reinterpret_cast<const struct sockaddr_in*>(&bound)->sin_port;
    if (advertise && !advertise->empty()) {
        struct sockaddr_storage resolved = {};
        if (fill_sockaddr_by_hostname(&resolved, *advertise, AF_UNSPEC)) {
            out = resolved;
            if (out.ss_family == AF_INET6) reinterpret_cast<struct sockaddr_in6*>(&out)->sin6_port = port;
            else reinterpret_cast<struct sockaddr_in*>(&out)->sin_port = port;
            return;
        }
        ogs_warn("Could not resolve mbstf.packetIngest advertise \"%s\"; using the bound address", advertise->c_str());
    }
    /* A wildcard bind: the local address of the default route. A UDP connect() sends nothing; it only selects the route.
       A wildcard IPv6 socket also takes IPv4 (see reserveShared), so with no IPv6 route the IPv4 one is given. */
    auto local_address_towards = [](int family, struct sockaddr_storage &local) {
        int sock = socket(family, SOCK_DGRAM|SOCK_CLOEXEC, 0);
        if (sock < 0) return false;
        struct sockaddr_storage target = {};
        socklen_t target_len;
        if (family == AF_INET6) {
            auto *t = reinterpret_cast<struct sockaddr_in6*>(&target);
            t->sin6_family = AF_INET6;
            t->sin6_port = htons(53);
            inet_pton(AF_INET6, "2001:4860:4860::8888", &t->sin6_addr);
            target_len = sizeof(*t);
        } else {
            auto *t = reinterpret_cast<struct sockaddr_in*>(&target);
            t->sin_family = AF_INET;
            t->sin_port = htons(53);
            t->sin_addr.s_addr = htonl(0x08080808);
            target_len = sizeof(*t);
        }
        socklen_t len = sizeof(local);
        bool ok = connect(sock, reinterpret_cast<struct sockaddr*>(&target), target_len) == 0 &&
                  getsockname(sock, reinterpret_cast<struct sockaddr*>(&local), &len) == 0;
        close(sock);
        return ok;
    };
    struct sockaddr_storage local = {};
    if (bound.ss_family == AF_INET) {
        auto *sin = reinterpret_cast<struct sockaddr_in*>(&out);
        if (sin->sin_addr.s_addr == INADDR_ANY && local_address_towards(AF_INET, local)) {
            sin->sin_addr = reinterpret_cast<struct sockaddr_in*>(&local)->sin_addr;
        }
    } else if (bound.ss_family == AF_INET6 && IN6_IS_ADDR_UNSPECIFIED(&reinterpret_cast<const struct sockaddr_in6*>(&bound)->sin6_addr)) {
        if (local_address_towards(AF_INET6, local)) {
            reinterpret_cast<struct sockaddr_in6*>(&out)->sin6_addr = reinterpret_cast<struct sockaddr_in6*>(&local)->sin6_addr;
        } else if (local_address_towards(AF_INET, local)) {
            struct sockaddr_in v4 = {};
            v4.sin_family = AF_INET;
            v4.sin_port = port;
            v4.sin_addr = reinterpret_cast<struct sockaddr_in*>(&local)->sin_addr;
            memset(&out, 0, sizeof(out));
            memcpy(&out, &v4, sizeof(v4));
        }
    }
}

static int get_interface_for_sockaddr(const struct sockaddr *sa)
{
    int s = socket(sa->sa_family, SOCK_DGRAM, 0);
    if (s < 0) return 0;

    // connect the socket to get the kernel to find the best interface
    if (sa->sa_family==AF_INET) {
        connect(s, sa, sizeof(struct sockaddr_in));
    } else if (sa->sa_family==AF_INET6) {
        connect(s, sa, sizeof(struct sockaddr_in6));
    }

    // ask socket for the local address for the interface
    struct sockaddr_storage local_addr;
    socklen_t local_len = sizeof(local_addr);
    getsockname(s, reinterpret_cast<struct sockaddr*>(&local_addr), &local_len);

    // Now search network interfaces for an interface matching the local address
    struct ifaddrs *ifa = nullptr;
    struct ifreq ifr = {};
    if (!getifaddrs(&ifa)) {
        for (auto *it = ifa; it; it = it->ifa_next) {
            if (!it->ifa_addr) continue;
            if (it->ifa_addr->sa_family == local_addr.ss_family) {
                if (local_addr.ss_family == AF_INET) {
                    struct sockaddr_in *a = reinterpret_cast<struct sockaddr_in*>(it->ifa_addr);
                    struct sockaddr_in *b = reinterpret_cast<struct sockaddr_in*>(&local_addr);
                    if (a->sin_addr.s_addr == b->sin_addr.s_addr) {
                        strcpy(ifr.ifr_name, it->ifa_name);
                        break;
                    }
                } else if (local_addr.ss_family == AF_INET6) {
                    struct sockaddr_in6 *a = reinterpret_cast<struct sockaddr_in6*>(it->ifa_addr);
                    struct sockaddr_in6 *b = reinterpret_cast<struct sockaddr_in6*>(&local_addr);
                    if (IN6_ARE_ADDR_EQUAL(&a->sin6_addr, &b->sin6_addr)) {
                        strcpy(ifr.ifr_name, it->ifa_name);
                        break;
                    }
                }
            }
        }
        freeifaddrs(ifa);
    }
    ioctl(s, SIOCGIFINDEX, &ifr);
    close(s);
    return ifr.ifr_ifindex;
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
