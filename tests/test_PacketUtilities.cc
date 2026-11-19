/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: packet checksum and proxy MTU unit test
 ******************************************************************************
 * License: 5G-MAG Public License v1
 ******************************************************************************/

/* Packet::checksum() is the Internet checksum of RFC 1071 clause 4.1: the one's complement of the one's complement sum
 * of the 16-bit words of the data, where an odd final octet is padded with a zero octet for the sum. The final partial
 * word of a buffer whose length is not a multiple of four is built here from the octets that remain, and the others
 * of its four octets must be zero.
 *
 * PacketProxyPacketisation sizes the packets it carries to the outer MTU less the IP and UDP headers of the outer
 * packet, 20 + 8 octets for an IPv4 source and 40 + 8 for an IPv6 one.
 */

#include "common.hh"
#include "Packet.hh"
#include "PacketProxyPacketisation.hh"
#include "SsmPort.hh"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

using namespace com::fiveg_mag::ref_tools::mbstf;

static int g_pass = 0;
static int g_fail = 0;

static void check(bool ok, const std::string &what)
{
    if (ok) { g_pass++; } else { g_fail++; std::printf("FAIL: %s\n", what.c_str()); }
}

/* Fills the stack below the caller with a pattern, so that a local array that is read before it is written holds it. */
__attribute__((noinline)) static void dirtyTheStack()
{
    volatile uint8_t scratch[4096];
    for (size_t i = 0; i < sizeof(scratch); i++) scratch[i] = 0xA5;
}

/* The same checksum from the definition: sum the 16-bit words in memory order, a missing final octet is zero. */
static uint16_t referenceChecksum(const std::vector<uint8_t> &data)
{
    uint64_t sum = 0;
    for (size_t i = 0; i < data.size(); i += 2) {
        uint8_t pair[2] = {data[i], static_cast<uint8_t>(i + 1 < data.size() ? data[i + 1] : 0)};
        uint16_t word;
        std::memcpy(&word, pair, sizeof(word));
        sum += word;
    }
    while (sum > 0xFFFF) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

static void testChecksumOfBuffersThatAreNotAMultipleOfFour()
{
    for (size_t length = 1; length <= 11; length++) {
        std::vector<uint8_t> data(length);
        for (size_t i = 0; i < length; i++) data[i] = static_cast<uint8_t>(0x11 * (i + 1));
        dirtyTheStack();
        const uint16_t got = Packet::checksum(data.data(), data.size());
        check(got == referenceChecksum(data), "checksum of " + std::to_string(length) + " octets is the definition's");
    }
}

static void testChecksumOfARfc1071Example()
{
    /* RFC 1071 clause 3: the words 0001 f203 f4f5 f6f7 sum to ddf2 in network order, so the checksum is 220d. */
    const std::vector<uint8_t> data = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
    uint16_t got = Packet::checksum(data.data(), data.size());
    uint8_t in_memory[2];
    std::memcpy(in_memory, &got, sizeof(got));
    check(in_memory[0] == 0x22 && in_memory[1] == 0x0d, "the RFC 1071 example gives 220d in network order");
}

static void testProxyMtuLeavesRoomForTheOuterHeaders()
{
    SsmPort ipv4(5000, "232.0.0.1", std::optional<std::string>("127.0.0.7"));
    PacketProxyPacketisation proxy4(1500, ipv4);
    check(proxy4.mtu() == 1500 - 20 - 8, "IPv4 outer packet: 1472 left of a 1500 octet MTU");

    SsmPort ipv6(5000, "ff3e::1234", std::optional<std::string>("2001:db8::7"));
    PacketProxyPacketisation proxy6(1500, ipv6);
    check(proxy6.mtu() == 1500 - 40 - 8, "IPv6 outer packet: 1452 left of a 1500 octet MTU");
}

int main()
{
    testChecksumOfBuffersThatAreNotAMultipleOfFour();
    testChecksumOfARfc1071Example();
    testProxyMtuLeavesRoomForTheOuterHeaders();

    std::printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
