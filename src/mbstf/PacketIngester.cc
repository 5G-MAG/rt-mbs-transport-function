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

#include <chrono>
#include <cstring>
#include <memory>
#include <system_error>

#include "ogs-core.h"
#include "ogs-sbi.h"

#include "common.hh"
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

PacketIngester::PacketIngester(PacketIngester &&other)
    :PacketSource(std::move(other))
    ,m_ssm(std::move(other.m_ssm))
    ,m_socket(other.m_socket)
    ,m_encapsulatedPackets(other.m_encapsulatedPackets)
    ,m_localAddr(std::move(other.m_localAddr))
    ,m_remoteAddr(std::move(other.m_remoteAddr))
    ,m_worker()
{
    //ogs_debug("Move constructor");
    other.stopWorker();
    other.m_socket = -1;
}

PacketIngester::~PacketIngester()
{
    //ogs_debug("Destroy ingester");
    closeSocket();
    stopWorker();
}

PacketIngester &PacketIngester::operator=(PacketIngester &&other)
{
    //ogs_debug("Move operator");
    stopWorker();
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
    if (!worker_cancel) startWorker();
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
    startWorker();
    return true;
}

bool PacketIngester::isStarted() const
{
    return m_worker.isRunning();
}

bool PacketIngester::stop()
{
    //ogs_debug("Stop ingester");
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
