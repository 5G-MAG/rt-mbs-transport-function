/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Common utility functions
 ******************************************************************************
 * Copyright: (C)2025-2026 British Broadcasting Corporation
 * Author(s): David Waring <david.waring2@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * Licensed under the License terms and conditions for use, reproduction, and
 * distribution of 5G-MAG software (the “License”).  You may not use this file
 * except in compliance with the License.  You may obtain a copy of the License at
 * https://www.5g-mag.com/reference-tools.  Unless required by applicable law or
 * agreed to in writing, software distributed under the License is distributed on
 * an “AS IS” BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied.
 *
 * See the License for the specific language governing permissions and limitations
 * under the License.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "ogs-core.h"

#include <chrono>
#include <exception>
#include <format>
#include <locale>
#include <string>
#include <sstream>

#include "common.hh"
#include "SsmPort.hh"

#include "App.hh"
#include "Context.hh"
#include <ifaddrs.h>

#include "utilities.hh"

MBSTF_NAMESPACE_START

std::string trim_slashes(const std::string &path)
{
    size_t start = path.starts_with('/') ? 1 : 0;
    size_t end = path.ends_with('/') ? path.size() - 1 : path.size();

    return path.substr(start, end - start);
}

std::string time_point_to_http_datetime_str(const std::chrono::system_clock::time_point &datetime)
{
    return std::format("{0:%a}, {0:%d} {0:%b} {0:%Y} {0:%T} GMT", datetime);
}

std::string time_point_to_iso8601_utc_str(const std::chrono::system_clock::time_point &datetime)
{
    std::ostringstream oss;
    auto datetime_us = std::chrono::time_point_cast<std::chrono::microseconds>(datetime);
    oss.imbue(std::locale("C"));
    oss << std::format("{0:%F}T{0:%T}Z", datetime_us);
    return oss.str();
}

std::chrono::system_clock::time_point iso8601_utc_str_to_time_point(const std::string &iso8601_str)
{
    std::chrono::system_clock::time_point retval;
    std::istringstream iss{iso8601_str};
    iss.imbue(std::locale("C"));
    iss >> std::chrono::parse("%FT%TZ", retval);
    if (iss.fail()) throw std::out_of_range(std::format("Bad ISO8601 UTC time: {}", iso8601_str));
    return retval;
}

std::chrono::system_clock::time_point http_datetime_str_to_time_point(const std::string &rfc9110_str)
{
    std::chrono::system_clock::time_point retval;
    std::istringstream iss{rfc9110_str};
    iss.imbue(std::locale("C"));
    iss >> std::chrono::parse("%a, %d %b %Y %T", retval);
    if (iss.fail()) throw std::out_of_range(std::format("Bad RFC9110 HTTP-date: {}", rfc9110_str));
    if (iss.peek() == '.') {
        /* extra fractions of a second */
        double frac;
        iss >> frac;
        retval += std::chrono::microseconds(static_cast<int>(frac*1000000.0));
    }
    char tz[5];
    iss.get(tz, sizeof(tz));
    if (std::string(tz) != " GMT") {
        throw std::out_of_range(std::format("Bad RFC9110 HTTP-date: {}", rfc9110_str));
    }
    return retval;
}

/** Whether an address belongs to an interface on this host.
 *
 * Traffic to such an address does not reach a network: the kernel routes it over the loopback
 * interface, whatever the address looks like.
 */
static bool address_is_local(const ogs_sockaddr_t &sock_addr)
{
    struct ifaddrs *ifaddr = nullptr;
    if (getifaddrs(&ifaddr) != 0) return false;
    bool found = false;
    for (const struct ifaddrs *ifa = ifaddr; ifa != nullptr && !found; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != sock_addr.ogs_sa_family) continue;
        if (sock_addr.ogs_sa_family == AF_INET) {
            const auto *a = reinterpret_cast<const struct sockaddr_in*>(ifa->ifa_addr);
            found = (a->sin_addr.s_addr == sock_addr.sin.sin_addr.s_addr);
        } else if (sock_addr.ogs_sa_family == AF_INET6) {
            const auto *a = reinterpret_cast<const struct sockaddr_in6*>(ifa->ifa_addr);
            found = (memcmp(&a->sin6_addr, &sock_addr.sin6.sin6_addr, sizeof(struct in6_addr)) == 0);
        }
    }
    freeifaddrs(ifaddr);
    return found;
}

int get_path_mtu(const ogs_sockaddr_t &sock_addr, int minus_level_hdrs, bool *via_loopback)
{
    if (via_loopback) *via_loopback = false;
    ogs_sock_t *sock = ogs_sock_socket(sock_addr.ogs_sa_family, SOCK_DGRAM, 0);
    ogs_sock_connect(sock, const_cast<ogs_sockaddr_t*>(&sock_addr));
    int mtu = 1500;
    socklen_t mtu_size = sizeof(mtu);
    if (sock_addr.ogs_sa_family == AF_INET) {
        getsockopt(sock->fd, IPPROTO_IP, IP_MTU, &mtu, &mtu_size);
        if (minus_level_hdrs >= GET_MTU_IP_PAYLOAD) mtu -= sizeof(iphdr);
    } else if (sock_addr.ogs_sa_family == AF_INET6) {
        getsockopt(sock->fd, IPPROTO_IPV6, IPV6_MTU, &mtu, &mtu_size);
        if (minus_level_hdrs >= GET_MTU_IP_PAYLOAD) mtu -= sizeof(ip6_hdr);
    }
    /* Whether this destination is one of the host's own addresses decides whether the datagram
       leaves the host at all, and so whether the MTU just read describes a path to a receiver.
       Where it is, the kernel routes it over the loopback interface and answers with the loopback
       MTU however the destination address is written.
       Testing the destination against the host's own addresses rather than for the 127/8 prefix:
       a co-located MB-UPF is commonly reached on the address of a real interface (a veth, say),
       which loops back without ever looking like a loopback address. */
    if (via_loopback) *via_loopback = address_is_local(sock_addr);
    ogs_sock_destroy(sock);
    return mtu;
}

int flute_path_mtu(int discovered_mtu, bool discovered_via_loopback)
{
    /* A measurement of a route that leaves the host is a real bound and is used as it stands,
       including where an operator has raised it: a deployment running jumbo frames between the
       MB-UPF and the gNB is configured through the interface MTUs, and second-guessing that here
       would cap it for no reason.

       A loopback route is not a path. Where the MBSTF and the ingress point are co-located the
       kernel answers with the loopback MTU, 65536, and symbols sized for that leave as datagrams
       nothing downstream carries. There is nothing to measure in that case, so the configured
       path MTU is used, which mbstf.pathMtu sets and which is documented in mbstf.yaml. */
    if (!discovered_via_loopback && discovered_mtu > 0) return discovered_mtu;

    const int path_mtu = App::self().context()->pathMtu;
    if (discovered_via_loopback) {
        ogs_info("The route to this session's ingress is loopback, so its %d byte MTU is not the "
                 "path to a receiver; sizing FLUTE symbols for the configured %d byte path MTU "
                 "instead (mbstf.pathMtu)", discovered_mtu, path_mtu);
    }
    return path_mtu;
}

int get_tunnelled_path_mtu(const SsmPort &ssm_port, const std::optional<std::string> &tunnel_ip, in_port_t tunnel_port, int minus_level_hdrs, bool *via_loopback)
{
    int mtu = 1500; // default to 1500 if no MTU can be found.
    if (via_loopback) *via_loopback = false;

    if (tunnel_ip) { // Use MTU of tunnel if provided
        ogs_sockaddr_t *sa = nullptr;
        if (ogs_addaddrinfo(&sa, AF_UNSPEC, tunnel_ip.value().c_str(), tunnel_port, AI_NUMERICSERV) == OGS_OK) {
            mtu = get_path_mtu(*sa, minus_level_hdrs, via_loopback);
            ogs_freeaddrinfo(sa);
        } // else error already reported
    } else { // No tunnel provided so try MTU of direct destination
        if (ssm_port) {
            ogs_sockaddr_t *sa = nullptr;
            if (ogs_addaddrinfo(&sa, AF_UNSPEC, ssm_port.destinationAddress().c_str(), ssm_port.port(), AI_NUMERICSERV) == OGS_OK) {
                mtu = get_path_mtu(*sa, minus_level_hdrs, via_loopback);
                ogs_freeaddrinfo(sa);
            }
        }
    }
    return mtu;
}

std::shared_ptr<struct sockaddr> make_shared_sockaddr(int family_hint, const std::string &hostname, in_port_t port)
{
    std::shared_ptr<struct sockaddr> ret;
    if (!hostname.empty()) {
        struct addrinfo *ai = nullptr;
        getaddrinfo(hostname.c_str(), std::format("{}", port).c_str(), nullptr, &ai);
        if (ai) {
            for (const auto *it = ai; it; it = it->ai_next) {
                if ((family_hint == AF_UNSPEC && (it->ai_family == AF_INET || it->ai_family == AF_INET6)) ||
                    (family_hint == it->ai_family)) {
                    auto sa_data = std::make_shared<uint8_t[]>(static_cast<size_t>(it->ai_addrlen));
                    memcpy(sa_data.get(), it->ai_addr, it->ai_addrlen);
                    ret = std::reinterpret_pointer_cast<struct sockaddr>(sa_data);
                    break;
                }
            }
            freeaddrinfo(ai);
        }
    }
    return ret;
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
