#ifndef _MBS_TF_PACKET_SCHEDULER_HH_
#define _MBS_TF_PACKET_SCHEDULER_HH_
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
#include <unistd.h>

#include <condition_variable>
#include <cstdint>
#include <list>
#include <mutex>
#include <thread>

#include "common.hh"
#include "Packet.hh"
#include "PacketProcessing.hh"
#include "ThreadedWorker.hh"

MBSTF_NAMESPACE_START

class PacketScheduler : public PacketSink {
public:
    PacketScheduler();
    PacketScheduler(uint64_t burst_bits, uint64_t abr, size_t max_buffer, const struct sockaddr *tunnnel_endpoint, PacketSource *source = nullptr);
    PacketScheduler(const PacketScheduler &) = delete;
    PacketScheduler(PacketScheduler &&other);

    virtual ~PacketScheduler();

    PacketScheduler &operator=(const PacketScheduler &) = delete;
    PacketScheduler &operator=(PacketScheduler &&other);

    operator bool() const {
        return m_abr != 0 && m_burstBits != 0 && m_maxBufferSize != 0 && m_sendAddress.ss_family != AF_UNSPEC;
    };

    virtual bool processPacket(Packet &packet);

    bool start();
    bool stop();
    bool flush();
    bool reconfigure();

private:
    void startThreads();
    void haltThreads();
    void haltBucketFillerThread();
    void haltSendThread();
    void bucketFillerWorker(std::function<void()>);
    void sendWorker(std::function<void()>);
    const Packet& waitForNextPacket(std::function<void()>);
    void waitForBitsAvailable(std::function<void()>, size_t bits);

    uint64_t m_abr;
    uint64_t m_burstBits;
    std::shared_ptr<std::recursive_mutex> m_bitBucketMutex;
    std::condition_variable_any m_bitBucketCondVar;
    std::atomic<uint64_t> m_bitBucket;
    ThreadedWorker m_bucketFillerThread;

    size_t m_maxBufferSize;
    std::shared_ptr<std::recursive_mutex> m_queueMutex;
    std::condition_variable_any m_queueCondVar;
    std::list<Packet> m_queuedPackets;
    std::atomic<size_t> m_queuedBytes;
    ThreadedWorker m_sendThread;

    int m_sendSocket;
    struct sockaddr_storage m_sendAddress;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_PACKET_SCHEDULER_HH_ */
