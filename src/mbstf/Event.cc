/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Subscription Event base class
 ******************************************************************************
 * Copyright: (C)2025 British Broadcasting Corporation
 * Author(s): David Waring <david.waring2@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include <iostream>

#include "common.hh"

#include "Event.hh"

MBSTF_NAMESPACE_START

Event::Event(const char *event_name)
    :m_eventName(event_name)
    ,m_preventDefault(false)
    ,m_stopProcessing(false)
{
}

Event::Event(const std::string &event_name)
    :m_eventName(event_name)
    ,m_preventDefault(false)
    ,m_stopProcessing(false)
{
}

Event::Event(std::string &&event_name)
    :m_eventName(std::move(event_name))
    ,m_preventDefault(false)
    ,m_stopProcessing(false)
{
}

Event::Event(const Event &other)
    :m_eventName(other.m_eventName)
    ,m_preventDefault(other.m_preventDefault)
    ,m_stopProcessing(other.m_stopProcessing)
{
}

Event::Event(Event &&other)
    :m_eventName(std::move(other.m_eventName))
    ,m_preventDefault(other.m_preventDefault)
    ,m_stopProcessing(other.m_stopProcessing)
{
}

Event::~Event()
{
}

Event &Event::operator=(const Event &other)
{
    m_eventName = other.m_eventName;
    m_preventDefault = other.m_preventDefault;
    m_stopProcessing = other.m_stopProcessing;
    return *this;
}

Event &Event::operator=(Event &&other)
{
    m_eventName = std::move(other.m_eventName);
    m_preventDefault = other.m_preventDefault;
    m_stopProcessing = other.m_stopProcessing;
    return *this;
}

void Event::stopProcessing()
{
    m_stopProcessing = true;
    m_preventDefault = true;
}

void Event::preventDefault()
{
    m_preventDefault = true;
}

Event Event::clone() const
{
    return Event(*this);
}

Event *Event::newClone() const
{
    return new Event(*this);
}

MBSTF_NAMESPACE_STOP

std::ostream &operator<<(std::ostream &ostrm, const MBSTF_NAMESPACE_NAME(Event) &event)
{
    ostrm << event.reprString();
    return ostrm;
}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
