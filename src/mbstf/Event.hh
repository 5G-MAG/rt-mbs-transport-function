#ifndef _MBS_TF_EVENT_HH_
#define _MBS_TF_EVENT_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Subscription Event base class
 ******************************************************************************
 * Copyright: (C)2024 British Broadcasting Corporation
 * Author(s): David Waring <david.waring2@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include <string>

#include "common.hh"

MBSTF_NAMESPACE_START

class Event
{
public:
    Event() = delete;
    Event(const char *event_name);
    Event(const std::string &event_name);
    Event(std::string &&event_name);
    Event(const Event &);
    Event(Event &&);

    virtual ~Event();

    Event &operator=(const Event &);
    Event &operator=(Event &&);

    const std::string &eventName() const { return m_eventName; };
    void stopProcessing(); // Do not send to any other Subscribers and do not perform default action
    void preventDefault(); // Send to other subscribers but do not perform any default action (synchronous events only)

    bool stopProcessingFlag() const { return m_stopProcessing; };
    bool preventDefaultFlag() const { return m_preventDefault; };

    virtual Event clone() const;
    virtual Event *newClone() const;

    virtual std::string reprString() const { return std::string("Event(\"") + m_eventName + "\")"; };
private:
    std::string m_eventName;
    bool m_preventDefault;
    bool m_stopProcessing;
};

MBSTF_NAMESPACE_STOP

std::ostream &operator<<(std::ostream &ostrm, const MBSTF_NAMESPACE_NAME(Event) &event);

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_EVENT_HH_ */
