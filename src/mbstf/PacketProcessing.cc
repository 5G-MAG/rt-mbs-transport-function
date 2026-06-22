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

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "ogs-core.h"
#include "ogs-sbi.h"

#include "common.hh"
#include "Packet.hh"

#include "PacketProcessing.hh"

MBSTF_NAMESPACE_START

/*** class PacketSource ***/

PacketSource::PacketSource(PacketSink *sink)
    :m_sink(sink)
{
    if (m_sink) m_sink->attachSource(this);
}

PacketSource::PacketSource(PacketSource &&other)
    :m_sink(other.m_sink)
{
    other.m_sink = nullptr;
    if (m_sink) m_sink->attachSource(this);
}

PacketSource::~PacketSource()
{
    attachSink(nullptr);
}

PacketSource &PacketSource::operator=(PacketSource &&other)
{
    attachSink(other.m_sink);
    other.m_sink = nullptr;
    return *this;
}

bool PacketSource::attachSink(PacketSink *sink)
{
    if (m_sink == sink) return true;
    if (m_sink) {
        auto tmp_sink = m_sink;
        m_sink = nullptr;
        tmp_sink->attachSource(nullptr);
        processEvent(PacketEvent::sinkDetachedEvent());
    }
    m_sink = sink;
    if (m_sink) {
        m_sink->attachSource(this);
        processEvent(PacketEvent::sinkAttachedEvent());
    }
    return true;
}

// class PacketSource protected

bool PacketSource::sendPacket(Packet &buffer)
{
    if (m_sink) {
        return m_sink->processPacket(buffer);
    } else {
        ogs_error("Attempt to send packet down the chain when not attached to a sink");
    }
    return false;
}

bool PacketSource::detach()
{
    if (m_sink) {
        m_sink->attachSource(nullptr);
        processEvent(PacketEvent::sinkDetachedEvent());
        m_sink = nullptr;
        return true;
    }
    return false;
}

/*** class PacketSink ***/

PacketSink::PacketSink(PacketSource *source)
    :m_source(source)
{
    if (m_source) m_source->attachSink(this);
}

PacketSink::PacketSink(PacketSink &&other)
    :m_source(other.m_source)
{
    other.m_source = nullptr;
    if (m_source) m_source->attachSink(this);
}

PacketSink::~PacketSink()
{
    attachSource(nullptr);
}

PacketSink &PacketSink::operator=(PacketSink &&other)
{
    attachSource(other.m_source);
    other.m_source = nullptr;
    return *this;
}

bool PacketSink::attachSource(PacketSource *source)
{
    if (source == m_source) return true;
    if (m_source) {
        auto tmp_src = m_source;
        m_source = nullptr;
        tmp_src->attachSink(nullptr);
    }
    m_source = source;
    if (m_source) {
        m_source->attachSink(this);
    }
    return true;
}

// class PacketSink protected

bool PacketSink::sendEvent(const std::shared_ptr<PacketEvent> &event)
{
    if (m_source) return m_source->processEvent(event);
    return false;
}

bool PacketSink::detach()
{
    if (m_source) {
        m_source->attachSink(nullptr);
        m_source = nullptr;
        return true;
    }
    return false;
}

/*** class PacketProcessing ***/

bool PacketProcessing::insertAfter(PacketSource *source)
{
    if (!source) return false;
    if (source == m_source) return true;

    detach();

    if (source->sink()) source->sink()->attachSource(this);
    source->attachSink(this);

    return true;    
}

bool PacketProcessing::insertBefore(PacketSink *sink)
{
    if (!sink) return false;
    if (sink == m_sink) return true;

    detach();

    if (sink->source()) sink->source()->attachSink(this);
    sink->attachSource(this);

    return true;
}

bool PacketProcessing::processEvent(const std::shared_ptr<PacketEvent> &event)
{
    // send event upstream
    return sendEvent(event);
}

// class PacketProcessing protected

bool PacketProcessing::detach()
{
    bool retval = false;
    if (m_source) {
        m_source->attachSink(m_sink);
        retval = true;
    } else if (m_sink) {
        m_sink->attachSource(nullptr);
        retval = true;
    }
    m_source = nullptr;
    m_sink = nullptr;
    return retval;
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
