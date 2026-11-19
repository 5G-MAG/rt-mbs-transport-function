/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: IPv6 extension header unit test
 ******************************************************************************
 * License: 5G-MAG Public License v1
 ******************************************************************************/

/* A Packet that carries an encapsulated IPv6 packet finds the UDP header after the IPv6 header and the extension
 * headers that follow it. RFC 8200 clause 4: "Each extension header is an integer multiple of 8 octets long", and the
 * Hdr Ext Len field of the Hop-by-Hop Options, Routing and Destination Options headers is their "Length ... in 8-octet
 * units, not including the first 8 octets". The Fragment header is 8 octets.
 *
 * The offset shows in fragmentData(): the fragment is cut to a multiple of 8 octets after the headers, and what is
 * removed from the packet is the part of the fragment after the headers, so the size that the packet has left depends
 * on where its UDP header was taken to be.
 */

#include "common.hh"
#include "Packet.hh"

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

using namespace com::fiveg_mag::ref_tools::mbstf;

static int g_pass = 0;
static int g_fail = 0;

static void check(bool ok, const std::string &what)
{
    if (ok) { g_pass++; } else { g_fail++; std::printf("FAIL: %s\n", what.c_str()); }
}

struct ExtensionHeader {
    uint8_t type;        // the Next Header value that names this header
    uint8_t hdr_ext_len; // Hdr Ext Len (the Fragment header has none: 8 octets)
};

/* An IPv6 packet carrying a UDP datagram of 100 octets of payload behind the given extension headers. The UDP source
 * port starts with 0x12, which is not the number of UDP (17). */
static std::vector<uint8_t> ipv6Udp(const std::vector<ExtensionHeader> &extensions, size_t &headers_length)
{
    std::vector<uint8_t> packet(sizeof(ip6_hdr), 0);
    packet[0] = 0x60;
    packet[6] = extensions.empty() ? IPPROTO_UDP : extensions.front().type;
    packet[7] = 64;
    packet[8 + 15] = 1;   // source ::1
    packet[24 + 15] = 2;  // destination ::2
    for (size_t i = 0; i < extensions.size(); i++) {
        const uint8_t next = (i + 1 < extensions.size()) ? extensions[i + 1].type : static_cast<uint8_t>(IPPROTO_UDP);
        const size_t length = (extensions[i].type == IPPROTO_FRAGMENT) ? 8 : (static_cast<size_t>(extensions[i].hdr_ext_len) + 1) * 8;
        std::vector<uint8_t> header(length, 0);
        header[0] = next;
        if (extensions[i].type != IPPROTO_FRAGMENT) header[1] = extensions[i].hdr_ext_len;
        packet.insert(packet.end(), header.begin(), header.end());
    }
    headers_length = packet.size();
    const uint8_t udp[sizeof(udphdr)] = {0x12, 0x34, 0x56, 0x78, 0x00, 0x6c, 0x00, 0x00};
    packet.insert(packet.end(), udp, udp + sizeof(udp));
    for (size_t i = 0; i < 100; i++) packet.push_back(static_cast<uint8_t>(i));
    const uint16_t payload_length = static_cast<uint16_t>(packet.size() - sizeof(ip6_hdr));
    packet[4] = payload_length >> 8;
    packet[5] = payload_length & 0xff;
    return packet;
}

/* Cuts a fragment of at most 96 octets from the packet and checks the fragment and what the packet has left. */
static void checkFragmentation(Packet &packet, size_t total, size_t headers_length, const std::string &what)
{
    const size_t maximum = 96;
    Packet fragment = packet.fragmentData(maximum);
    check(fragment.size() == maximum, what + ": the fragment is 96 octets");
    check(packet.size() == total - (maximum - headers_length),
          what + ": the packet keeps what the fragment did not take, after the same headers");
}

static void testFromBuffer(const std::vector<ExtensionHeader> &extensions, const std::string &what)
{
    size_t headers_length = 0;
    std::vector<uint8_t> bytes = ipv6Udp(extensions, headers_length);
    Packet packet(bytes.data(), bytes.size(), true);
    checkFragmentation(packet, bytes.size(), headers_length, "buffer, " + what);
}

static void testFromMessage(const std::vector<ExtensionHeader> &extensions, const std::string &what)
{
    size_t headers_length = 0;
    std::vector<uint8_t> bytes = ipv6Udp(extensions, headers_length);
    struct iovec iov = {bytes.data(), bytes.size()};
    struct msghdr msg;
    std::memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    std::shared_ptr<struct sockaddr> listen_address;
    Packet packet(&msg, listen_address, true);
    checkFragmentation(packet, bytes.size(), headers_length, "message, " + what);
}

int main()
{
    const std::vector<std::pair<std::string, std::vector<ExtensionHeader>>> cases = {
        {"no extension header", {}},
        {"one Hop-by-Hop header of 8 octets", {{IPPROTO_HOPOPTS, 0}}},
        {"a Hop-by-Hop header of 16 octets and a Destination Options header of 8", {{IPPROTO_HOPOPTS, 1}, {IPPROTO_DSTOPTS, 0}}},
        {"a Routing header of 24 octets and a Fragment header", {{IPPROTO_ROUTING, 2}, {IPPROTO_FRAGMENT, 0}}},
    };
    for (const auto &c : cases) {
        testFromBuffer(c.second, c.first);
        testFromMessage(c.second, c.first);
    }

    std::printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
