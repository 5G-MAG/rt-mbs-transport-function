#ifndef _MBS_TF_PACKET_PROCESSING_HH_
#define _MBS_TF_PACKET_PROCESSING_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Packet Processing base class
 ******************************************************************************
 * Copyright: (C)2026 British Broadcasting Corporation
 * Author(s): David Waring <david.waring2@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include <netinet/in.h>

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "common.hh"
#include "Packet.hh"

MBSTF_NAMESPACE_START

class PacketSink;

class PacketCommsEvent;
class PacketTooLargeEvent;

class PacketEvent {
public:
    enum EventType {
        PACKET_BUFFER_OVERFLOW,
        PACKET_TOO_LARGE,
        SINK_ATTACHED,
        SINK_DETACHED
    };

    PacketEvent() = delete;
    PacketEvent(EventType typ) :m_eventType(typ) {};
    PacketEvent(const PacketEvent &other) :m_eventType(other.m_eventType) {};
    PacketEvent(PacketEvent &&other) :m_eventType(other.m_eventType) {};

    virtual ~PacketEvent() {};

    PacketEvent &operator=(const PacketEvent &other) { m_eventType = other.m_eventType; return *this; };
    PacketEvent &operator=(PacketEvent &&other) { m_eventType = other.m_eventType; return *this; };

    bool operator==(const PacketEvent &other) const {
        return m_eventType == other.m_eventType;
    };

    EventType eventType() const { return m_eventType; };

    static std::shared_ptr<PacketEvent> bufferOverflowEvent(const Packet &packet) { return std::static_pointer_cast<PacketEvent>(std::make_shared<PacketCommsEvent>(PACKET_BUFFER_OVERFLOW, packet)); };
    static std::shared_ptr<PacketEvent> packetTooLargeEvent(uint16_t expected_mtu, const Packet &packet) { return std::static_pointer_cast<PacketEvent>(std::make_shared<PacketTooLargeEvent>(expected_mtu, packet)); };
    static std::shared_ptr<PacketEvent> sinkAttachedEvent() { return std::make_shared<PacketEvent>(SINK_ATTACHED); };
    static std::shared_ptr<PacketEvent> sinkDetachedEvent() { return std::make_shared<PacketEvent>(SINK_DETACHED); };

private:
    EventType m_eventType;
};

class PacketCommsEvent : public PacketEvent {
public:
    PacketCommsEvent() = delete;
    PacketCommsEvent(EventType typ, const Packet &packet) :PacketEvent(typ) ,m_packet(&packet) {};
    PacketCommsEvent(const PacketCommsEvent &other) :PacketEvent(other), m_packet(other.m_packet) {};
    PacketCommsEvent(PacketCommsEvent &&other) :PacketEvent(other), m_packet(other.m_packet) {};

    virtual ~PacketCommsEvent() {};

    PacketCommsEvent &operator=(const PacketCommsEvent &other) { PacketEvent::operator=(other); m_packet = other.m_packet; return *this; };
    PacketCommsEvent &operator=(PacketCommsEvent &&other) { PacketEvent::operator=(std::move(other)); m_packet = other.m_packet; return *this; };

    bool operator==(const PacketCommsEvent &other) const {
        return PacketEvent::operator==(other) && (m_packet == other.m_packet || *m_packet == *other.m_packet);
    };

    const Packet &packet() const { return *m_packet; };

private:
    const Packet *m_packet;
};

class PacketTooLargeEvent : public PacketCommsEvent {
public:
    PacketTooLargeEvent() = delete;
    PacketTooLargeEvent(uint16_t expected_mtu, const Packet &packet) :PacketCommsEvent(PacketEvent::PACKET_TOO_LARGE, packet), m_expectedMTU(expected_mtu) {};
    PacketTooLargeEvent(const PacketTooLargeEvent &other) :PacketCommsEvent(other), m_expectedMTU(other.m_expectedMTU) {};
    PacketTooLargeEvent(PacketTooLargeEvent &&other) :PacketCommsEvent(std::move(other)), m_expectedMTU(other.m_expectedMTU) {};

    virtual ~PacketTooLargeEvent() {};

    PacketTooLargeEvent &operator=(const PacketTooLargeEvent &other) {
        PacketCommsEvent::operator=(other);
        m_expectedMTU = other.m_expectedMTU;
        return *this;
    };
    PacketTooLargeEvent &operator=(PacketTooLargeEvent &&other) {
        PacketCommsEvent::operator=(std::move(other));
        m_expectedMTU = other.m_expectedMTU;
        return *this;
    };

    bool operator==(const PacketTooLargeEvent &other) const {
        return m_expectedMTU == other.m_expectedMTU && PacketCommsEvent::operator==(other);
    }

    uint16_t expectedMTU() const { return m_expectedMTU; };

private:
    uint16_t m_expectedMTU;
};

class PacketSource {
public:
    PacketSource(PacketSink *sink = nullptr);
    PacketSource(const PacketSource &other) = delete;
    PacketSource(PacketSource &&other);

    virtual ~PacketSource();

    PacketSource &operator=(const PacketSource &other) = delete;
    PacketSource &operator=(PacketSource &&other);

    bool attachSink(PacketSink *sink);
    virtual bool processEvent(const std::shared_ptr<PacketEvent> &event) = 0;

    PacketSink *sink() { return m_sink; };
    const PacketSink *sink() const { return m_sink; };

protected:
    bool sendPacket(Packet &buffer);
    virtual bool detach();

    PacketSink *m_sink;
};

class PacketSink {
public:
    PacketSink(PacketSource *source = nullptr);
    PacketSink(const PacketSink &other) = delete;
    PacketSink(PacketSink &&other);

    virtual ~PacketSink();

    PacketSink &operator=(const PacketSink &other) = delete;
    PacketSink &operator=(PacketSink &&other);

    bool attachSource(PacketSource *source);
    virtual bool processPacket(Packet &buffer) = 0;

    PacketSource *source() { return m_source; };
    const PacketSource *source() const { return m_source; };

protected:
    virtual bool detach();
    bool sendEvent(const std::shared_ptr<PacketEvent> &event);

    PacketSource *m_source;
};

class PacketProcessing : public PacketSource, public PacketSink {
public:
    PacketProcessing(PacketSource *source = nullptr, PacketSink *sink = nullptr) :PacketSource(sink), PacketSink(source) {};
    PacketProcessing(const PacketProcessing &other) = delete;
    PacketProcessing(PacketProcessing &&other) :PacketSource(std::move(other)), PacketSink(std::move(other)) {};

    virtual ~PacketProcessing() { detach(); };

    PacketProcessing &operator=(const PacketProcessing &other) = delete;
    PacketProcessing &operator=(PacketProcessing &&other) {
        PacketSource::operator=(std::move(other));
        PacketSink::operator=(std::move(other));
        return *this;
    };

    bool insertAfter(PacketSource *source);
    bool insertBefore(PacketSink *sink);

    virtual bool processEvent(const std::shared_ptr<PacketEvent> &event);

protected:
    virtual bool detach();
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_PACKET_PROCESSING_HH_ */
