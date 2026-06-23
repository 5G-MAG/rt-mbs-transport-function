#!/usr/bin/python3
############################################################################################################
# Copyright: 2026 British Broadcasting Corporation
# Author(s): David Waring <david.waring2@bbc.co.uk>
# License: 5G-MAG Public License v1.0
#
# Licensed under the License terms and conditions for use, reproduction, and distribution of 5G-MAG
# software (the “License”).
#
# You may not use this file except in compliance with the License. You may obtain a copy of the License
# at https://www.5g-mag.com/reference-tools.
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is
# distributed on an “AS IS” BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the License for the specific language governing permissions and limitations under the License.
############################################################################################################

import argparse
import asyncio
import functools
import ipaddress
import os.path
import socket
import struct
import sys

g_this_script = os.path.basename(__file__)

socket_consts = [
    ('IP_MTU_DISCOVER', 10),

    ('IPV6_MTU_DISCOVER', 23),

    ('IP_PMTUDISC_DONT', 0),
    ('IP_PMTUDISC_PROBE', 3),

    ('IPV6_PMTUDISC_DONT', 0),
    ('IPV6_PMTUDISC_PROBE', 3),
]
for (attr, value) in socket_consts:
    if not hasattr(socket, attr):
        setattr(socket, attr, value)

class StreamClientProtocol:
    def __init__(self, loop, encap_dest, encap_src, packet_size, packet_rate_ms, ttl, do_not_fragment):
        self.__loop = loop
        self.__conn_end_future = self.__loop.create_future()
        if encap_dest is None:
            self.__encap_dest = None
            self.__encap_src = None
            self.__encap_family = None
        else:
            for (family, _, _, _, sockaddr) in socket.getaddrinfo(*encap_dest):
                if family in [socket.AF_INET, socket.AF_INET6]:
                    self.__encap_dest = (socket.inet_pton(family, sockaddr[0]), sockaddr[1])
                    self.__encap_family = family
                    break
            for (_, _, _, _, sockaddr) in socket.getaddrinfo(*encap_src, family=self.__encap_family):
                self.__encap_src = (socket.inet_pton(self.__encap_family, sockaddr[0]), sockaddr[1])
        self.__packet_size = packet_size
        self.__packet_rate_ms = packet_rate_ms
        self.__ttl = ttl
        self.__do_not_fragment = do_not_fragment
        self.__pkt_counter = 1
        self.__transport = None

    async def checksum_raw(self, buffer):
        if len(buffer) % 2 == 1:
            cksum = functools.reduce(lambda x,y: x + y[0], struct.iter_unpack('H', buffer[0:-1]), 0) + (struct.unpack_from('B', buffer, len(buffer)-1) << 16)
        else:
            cksum = functools.reduce(lambda x,y: x + y[0], struct.iter_unpack('H', buffer), 0)
        while cksum > 0xffff:
            cksum = (cksum & 0xffff) + (cksum >> 16)
        return cksum

    async def checksum(self, buffer):
        cksum = await self.checksum_raw(buffer)
        return ~cksum & 0xffff

    async def ip_header(self, payload_len, ttl=64, do_not_fragment=False):
        iph = b'\x45\x00'
        iph += struct.pack("!H", payload_len + 20)
        iph += b'\x00\x00'
        if (do_not_fragment):
            iph += b'\x40\x00'
        else:
            iph += b'\x00\x00'
        iph += struct.pack("!B", ttl)
        iph += struct.pack("!B", socket.IPPROTO_UDP)
        cksum_offset = len(iph)
        iph += b'\x00\x00'
        #print(f"IP SRC {self.__encap_src[0]!r}")
        iph += self.__encap_src[0]
        #print(f"IP DEST {self.__encap_dest[0]!r}")
        iph += self.__encap_dest[0]
        iph = iph[0:cksum_offset] + struct.pack("H", await self.checksum(iph)) + iph[cksum_offset+2:]
        return iph

    async def ip6_header(self, payload_len, ttl=64):
        iph = b'\x60\x00\x00\x00'
        iph += struct.pack("!H", payload_len)
        iph += struct.pack("!B", socket.IPPROTO_UDP)
        iph += struct.pack("!B", ttl)
        #print(f"IP6 SRC {self.__encap_src[0]!r}")
        iph += self.__encap_src[0]
        #print(f"IP6 DEST {self.__encap_dest[0]!r}")
        iph += self.__encap_dest[0]
        return iph

    async def udp_header_and_payload(self, payload):
        udp = struct.pack("!H", self.__encap_src[1])
        udp += struct.pack("!H", self.__encap_dest[1])
        udp += struct.pack("!H", len(payload) + 8)
        cksum_offset = len(udp)
        udp += b'\x00\x00'
        udp += payload

        pseudo_ip = self.__encap_src[0]
        pseudo_ip += self.__encap_dest[0]
        pseudo_ip += b'\x00'
        pseudo_ip += struct.pack("!B", socket.IPPROTO_UDP)
        pseudo_ip += struct.pack("!H", len(payload) + 8)

        cksum = await self.checksum_raw(pseudo_ip) + await self.checksum_raw(udp)
        while cksum > 0xffff:
            cksum = (cksum & 0xffff) + (cksum >> 16)
        cksum = ~cksum & 0xffff

        udp = udp[0:cksum_offset] + struct.pack("H", cksum) + udp[cksum_offset+2:]

        return udp

    async def udp_packet(self, payload, ttl=64, do_not_fragment=False):
        if self.__encap_family is not None:
            if self.__encap_family == socket.AF_INET:
                packet = await self.ip_header(len(payload) + 8, ttl, do_not_fragment)
            elif self.__encap_family == socket.AF_INET6:
                packet = await self.ip6_header(len(payload) + 8, ttl)
            else:
                packet = b''
            packet += await self.udp_header_and_payload(payload)
        else:
            packet = payload
        return packet

    async def make_packet(self):
        packet_body = bytes([self.__pkt_counter & 0xff] * self.__packet_size)
        self.__pkt_counter += 1
        return await self.udp_packet(packet_body, self.__ttl, self.__do_not_fragment)

    async def send_loop(self):
        while True:
            self.__transport.sendto(await self.make_packet())
            await asyncio.sleep(self.__packet_rate_ms/1000.0)

    async def on_con_lost(self):
        return await self.__conn_end_future

    def connection_made(self, transport):
        self.__transport = transport
        self.__send_task = asyncio.create_task(self.send_loop(), eager_start=True)
        
    def datagram_received(self, data, addr):
        print(f"Unexpected packet of {len(data)} bytes from: {addr}")
        #self.__transport.close()

    def error_received(self, exc):
        #print('Error received: ', exc)
        pass

    def connection_lost(self, exc):
        print("\nConnection closed")
        if not self.__conn_end_future.cancelled():
            self.__conn_end_future.set_result(True)

def to_addr_port(ap_str):
    if ap_str is None:
        return None
    (addr, _, port) = ap_str.rpartition(':')
    if addr[0] == '[' and addr[-1] == ']':
        addr = addr[1:-1]
    return (addr, int(port))

async def main():
    parser = argparse.ArgumentParser(description='Test script to stream UDP packets to the MBSTF.')
    parser.add_argument('-s', '--size', metavar='BYTES', help='Size of packets to send. (default: %(default)s)', type=int, default=1428)
    parser.add_argument('-t', '--ttl', help='TTL to use on packets. (default: %(default)s)', type=int, default=64)
    parser.add_argument('-r', '--packet-rate', metavar='PACKET-RATE', help='The number of packets per second to send. (default: %(default)s)', type=int, default=100)
    parser.add_argument('-d', '--do-not-fragment', help='Flag packets as "Do not fragment" (only applies to IPv4). (default: fragmentation allowed)', action='store_true')
    parser.add_argument('tunnel_source', metavar='local-address:port', type=to_addr_port, help='Local address and port that packets will be sent from.')
    parser.add_argument('tunnel_dest', metavar='destination-address:port', type=to_addr_port, help='Remote address and port that packets will be sent to.')
    parser.add_argument('encap_dest', nargs='?', metavar='encap-dest-address:port', type=to_addr_port, help='Encapsulated destination address and port that packet payloads will contain. If omitted then there\'s no encapsulation.', default=None)
    parser.add_argument('encap_source', nargs='?', metavar='encap-src-address:port', type=to_addr_port, help='Encapsulated source address and port that packet payloads will contain. If omitted then the <local-address:port> is used if appropriate.', default=None)

    opts = parser.parse_args()

    local_addr_port = opts.tunnel_source
    remote_addr_port = opts.tunnel_dest
    encap_dest_addr_port = opts.encap_dest
    encap_src_addr_port = opts.encap_source
    packet_size = opts.size
    packet_rate = opts.packet_rate
    do_not_fragment = opts.do_not_fragment
    ttl = opts.ttl
    if encap_src_addr_port is None:
        encap_src_addr_port = local_addr_port

    loop = asyncio.get_running_loop()

    transport, protocol = await loop.create_datagram_endpoint(
      lambda: StreamClientProtocol(loop, encap_dest_addr_port, encap_src_addr_port, packet_size, packet_rate, ttl, do_not_fragment),
      local_addr=local_addr_port, remote_addr=remote_addr_port)

    sock = transport.get_extra_info('socket')
    if sock.family == socket.AF_INET:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        if do_not_fragment:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MTU_DISCOVER, socket.IP_PMTUDISC_PROBE)
        else:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MTU_DISCOVER, socket.IP_PMTUDISC_DONT)
        (host, port) = sock.getsockname()
        if ipaddress.ip_address(host).is_multicast:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    elif sock.family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)
        if do_not_fragment:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MTU_DISCOVER, socket.IPV6_PMTUDISC_PROBE)
        else:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MTU_DISCOVER, socket.IPV6_PMTUDISC_DONT)
        (host, port, flowinfo, scope_id) = sock.getsockname()
        if ipaddress.ip_address(host).is_multicast:
            sock.setsockopt(socket.IPPROTO_IPv6, socket.IPV6_MULTICAST_HOPS, ttl)
            sock.setsockopt(socket.IPPROTO_IPv6, socket.IPV6_MULTICAST_LOOP, 1)

    try:
        await protocol.on_con_lost()
    except asyncio.exceptions.CancelledError:
        pass
    finally:
        transport.close()

    return 0

sys.exit(asyncio.run(main()))
