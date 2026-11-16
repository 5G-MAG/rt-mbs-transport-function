/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: packet-mode MTU unit test
 ******************************************************************************
 * Copyright: (C)2026 British Broadcasting Corporation
 * License: 5G-MAG Public License v1
 ******************************************************************************/

/* Covers inner_packet_mtu() and tunnel_address_is_ipv6(), which size the packets of a packet-mode session. The
 * packet goes to the MB-UPF in a UDP datagram, and the MB-UPF puts it in a GTP-U packet to the gNB, so what fits is
 * the path MTU less the outer IP header, the UDP header and the GTP-U header (GTP_HEADER_SIZE, 20 octets as the MB-UPF
 * writes it): 1452 for IPv4 on a 1500 octet path, 1432 for IPv6.
 */

#include "common.hh"
#include "PacketMtu.hh"

#include <cstdio>
#include <optional>
#include <string>

using namespace com::fiveg_mag::ref_tools::mbstf;

static int g_pass = 0;
static int g_fail = 0;

static void check(bool ok, const char *what)
{
    if (ok) { g_pass++; } else { g_fail++; std::printf("FAIL: %s\n", what); }
}

int main()
{
    check(GTP_HEADER_SIZE == 20, "the GTP-U allowance is the 20 octets the MB-UPF writes");

    check(inner_packet_mtu(1500, false) == 1452, "IPv4 tunnel on a 1500 octet path: 1452");
    check(inner_packet_mtu(1500, true) == 1432, "IPv6 tunnel on a 1500 octet path: 1432");
    check(inner_packet_mtu(9000, false) == 8952, "IPv4 tunnel on a jumbo frame path: 8952");
    check(inner_packet_mtu(1400, false) == 1352, "a smaller path gives a smaller packet");
    check(inner_packet_mtu(1500, true) < inner_packet_mtu(1500, false), "IPv6 leaves less than IPv4");

    /* The packet the MB-UPF sends on, with its own IP, UDP and GTP-U headers, is within the path MTU. */
    check(inner_packet_mtu(1500, false) + 20 + 8 + GTP_HEADER_SIZE <= 1500, "IPv4: the outer packet fits the path");
    check(inner_packet_mtu(1500, true) + 40 + 8 + GTP_HEADER_SIZE <= 1500, "IPv6: the outer packet fits the path");

    check(!tunnel_address_is_ipv6(std::nullopt), "no address is taken as IPv4");
    check(!tunnel_address_is_ipv6(std::string("10.99.0.1")), "a dotted address is IPv4");
    check(!tunnel_address_is_ipv6(std::string("127.0.0.1")), "a loopback IPv4 address is IPv4");
    check(tunnel_address_is_ipv6(std::string("::1")), "::1 is IPv6");
    check(tunnel_address_is_ipv6(std::string("2001:db8:cafe::1")), "a global IPv6 address is IPv6");
    check(tunnel_address_is_ipv6(std::string("fe80::1")), "a link-local IPv6 address is IPv6");

    std::printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
