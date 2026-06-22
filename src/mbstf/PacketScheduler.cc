/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Packet Scheduler base class
 ******************************************************************************
 * Copyright: (C)2026 British Broadcasting Corporation
 * Author(s): David Waring <david.waring2@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include <sys/socket.h>

#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <thread>

#include "common.hh"
#include "Packet.hh"
#include "PacketProcessing.hh"

#include "PacketScheduler.hh"

using namespace std::literals::chrono_literals;

MBSTF_NAMESPACE_START

PacketScheduler::PacketScheduler()
    :PacketSink()
    ,m_abr(0)
    ,m_burstBits(0)
    ,m_bitBucketMutex(new decltype(m_bitBucketMutex)::element_type)
    ,m_bitBucketCondVar()
    ,m_bitBucket(0)
    ,m_bucketFillerThread()
    ,m_maxBufferSize(0)
    ,m_queueMutex(new decltype(m_queueMutex)::element_type)
    ,m_queueCondVar()
    ,m_queuedPackets()
    ,m_queuedBytes(0)
    ,m_sendThread()
    ,m_sendSocket(-1)
    ,m_sendAddress()
{
}


PacketScheduler::PacketScheduler(uint64_t burst_bits, uint64_t abr, size_t max_buffer, const struct sockaddr *tunnel_endpoint, PacketSource *source)
    :PacketSink(source)
    ,m_abr(abr)
    ,m_burstBits(burst_bits)
    ,m_bitBucketMutex(new decltype(m_bitBucketMutex)::element_type)
    ,m_bitBucketCondVar()
    ,m_bitBucket(burst_bits)
    ,m_bucketFillerThread()
    ,m_maxBufferSize(max_buffer)
    ,m_queueMutex(new decltype(m_queueMutex)::element_type)
    ,m_queueCondVar()
    ,m_queuedPackets()
    ,m_queuedBytes(0)
    ,m_sendThread()
    ,m_sendSocket(-1)
    ,m_sendAddress()
{
    if (tunnel_endpoint) {
        socklen_t addr_len = 0;
        switch (tunnel_endpoint->sa_family) {
        case AF_INET:
            addr_len = sizeof(sockaddr_in);
            break;
        case AF_INET6:
            addr_len = sizeof(sockaddr_in6);
            break;
        default:
            break;
        }
        if (addr_len) {
            memcpy(&m_sendAddress, tunnel_endpoint, addr_len);
            m_sendSocket = socket(tunnel_endpoint->sa_family, SOCK_DGRAM, IPPROTO_UDP);
            if (m_sendSocket >= 0) {
                connect(m_sendSocket, tunnel_endpoint, addr_len);
            }
        }
    }
}

PacketScheduler::PacketScheduler(PacketScheduler &&other)
    :PacketSink(std::move(other))
    ,m_abr(other.m_abr)
    ,m_burstBits(other.m_burstBits)
    ,m_bitBucketMutex(new decltype(m_bitBucketMutex)::element_type)
    ,m_bitBucketCondVar()
    ,m_bitBucket(0)
    ,m_bucketFillerThread()
    ,m_maxBufferSize(other.m_maxBufferSize)
    ,m_queueMutex(new decltype(m_queueMutex)::element_type)
    ,m_queueCondVar()
    ,m_queuedPackets()
    ,m_queuedBytes(0)
    ,m_sendThread()
    ,m_sendSocket(other.m_sendSocket)
    ,m_sendAddress(other.m_sendAddress)
{
    other.haltThreads();
    other.m_sendSocket = -1;

    m_bitBucket = other.m_bitBucket.load();

    {
        std::lock_guard<decltype(m_queueMutex)::element_type> bucket_lock(*other.m_queueMutex);
        m_queuedPackets = std::move(other.m_queuedPackets);
        m_queuedBytes = other.m_queuedBytes.exchange(0);
    }

    startThreads();
}

PacketScheduler::~PacketScheduler()
{
    //stop();
    haltThreads();
}

PacketScheduler &PacketScheduler::operator=(PacketScheduler &&other)
{
    PacketSink::operator=(std::move(other));

    if (m_sendSocket >= 0) close(m_sendSocket);
    m_sendSocket = other.m_sendSocket;
    other.m_sendSocket = -1;

    m_sendAddress = other.m_sendAddress;

    m_abr = other.m_abr;
    m_burstBits = other.m_burstBits;
    m_maxBufferSize = other.m_maxBufferSize;

    m_bitBucket = other.m_bitBucket.load();

    {
        std::lock_guard<decltype(m_queueMutex)::element_type> other_queue_lock(*other.m_queueMutex);
        std::lock_guard<decltype(m_queueMutex)::element_type> queue_lock(*m_queueMutex);
        m_queuedPackets = std::move(other.m_queuedPackets);
        m_queuedBytes = other.m_queuedBytes.exchange(0);
    }

    m_bucketFillerThread = std::move(other.m_bucketFillerThread);
    m_sendThread = std::move(other.m_sendThread);

    return *this;
}

bool PacketScheduler::processPacket(Packet &packet)
{
    ogs_debug("Scheduling packet of %zu bytes", packet.size());
    std::lock_guard<decltype(m_queueMutex)::element_type> queue_lock(*m_queueMutex);
    if (m_queuedBytes + packet.size() > m_maxBufferSize) {
        ogs_debug("Scheduling: Buffer overflow, discarding packet");
        sendEvent(PacketEvent::bufferOverflowEvent(packet));
        return false;
    }

    m_queuedBytes += packet.size();
    m_queuedPackets.push_back(std::move(packet));
    m_queueCondVar.notify_all();
    return true;
}

bool PacketScheduler::start()
{
    startThreads();
    return true;
}

bool PacketScheduler::stop()
{
    haltThreads();
    return true;
}

bool PacketScheduler::flush()
{
    std::lock_guard<decltype(m_queueMutex)::element_type> queue_lock(*m_queueMutex);

    // Wait for the queue to empty or the sending thread to stop
    while (m_sendThread.isRunning() && m_queuedPackets.size() > 0) {
        m_queueCondVar.wait_for(*m_queueMutex, 10ms);
    }

    // Tidy up queue if thread cancelled
    if (m_queuedPackets.size() > 0) {
        m_queuedPackets.clear();
        m_queuedBytes = 0;
    }

    return true;
}

bool PacketScheduler::reconfigure()
{
    return true;
}

// private:

void PacketScheduler::startThreads()
{
    if (m_abr > 0 && m_burstBits > 0) {
        m_bucketFillerThread.startWorker("bucket-bit-filler", [this](auto check_cancelled) -> void {
            bucketFillerWorker(check_cancelled);
        });
    }

    if (m_sendSocket >= 0) {
        std::lock_guard<decltype(m_queueMutex)::element_type> bucket_lock(*m_queueMutex);

        m_sendThread.startWorker("packet-send", [this](auto check_cancelled) -> void {
            sendWorker(check_cancelled);
        });
    }
}

void PacketScheduler::haltThreads()
{
    haltBucketFillerThread();
    haltSendThread();
}

void PacketScheduler::haltBucketFillerThread()
{
    m_bucketFillerThread.cancel();
    m_bucketFillerThread.join();
}

void PacketScheduler::haltSendThread()
{
    m_sendThread.cancel();
    m_sendThread.join();
}

void PacketScheduler::bucketFillerWorker(std::function<void()> check_cancelled)
{
    double counter = 0;
    double increment = m_abr / 100; // increment needed each 10ms
    auto next_fill = std::chrono::system_clock::now() + 10ms;
    while (true) {
        counter += increment;
        uint64_t bits = floor(counter);
        counter -= bits;

        {
            std::lock_guard<decltype(m_bitBucketMutex)::element_type> bucket_lock(*m_bitBucketMutex);
            bits = std::min(bits, m_burstBits - m_bitBucket);
            m_bitBucket += bits;
            m_bitBucketCondVar.notify_all();
        }

        std::this_thread::sleep_until(next_fill);
        next_fill += 10ms;
        check_cancelled();
    }
}

void PacketScheduler::sendWorker(std::function<void()> check_cancelled)
{
    while (true) {
        const auto &packet = waitForNextPacket(check_cancelled);
        ogs_debug("Scheduler: got packet of %zu bytes", packet.size());
        waitForBitsAvailable(check_cancelled, packet.size() * 8);
        ogs_debug("Scheduler: bucket has enough bits");

        {
            std::lock_guard<decltype(m_bitBucketMutex)::element_type> bucket_lock(*m_bitBucketMutex);

            m_bitBucket -= packet.size() * 8;
            m_bitBucketCondVar.notify_all();
        }

        auto pl = packet.payload();
        ogs_debug("Scheduler: transmitting %zu bytes", pl.size());
        auto res = send(m_sendSocket, pl.data(), pl.size(), 0);
        if (res < 0) {
            ogs_warn("Scheduler: send failed: %s", strerror(errno));
        }

        {
            std::lock_guard<decltype(m_queueMutex)::element_type> queue_lock(*m_queueMutex);
            m_queuedBytes -= packet.size();
            m_queuedPackets.pop_front(); // Invalidates packet
            m_queueCondVar.notify_all();
        }

        check_cancelled();
    }
}

const Packet& PacketScheduler::waitForNextPacket(std::function<void()> check_cancelled)
{
    std::lock_guard<decltype(m_queueMutex)::element_type> queue_lock(*m_queueMutex);

    while (m_queuedPackets.size() == 0) {
        m_queueCondVar.wait_for(*m_queueMutex, 10ms);
        check_cancelled();
    }

    return m_queuedPackets.front();
}

void PacketScheduler::waitForBitsAvailable(std::function<void()> check_cancelled, size_t bits)
{
    std::lock_guard<decltype(m_bitBucketMutex)::element_type> bucket_lock(*m_bitBucketMutex);

    while(m_bitBucket < bits) {
        m_bitBucketCondVar.wait_for(*m_bitBucketMutex,10ms);
        check_cancelled();
    }
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
