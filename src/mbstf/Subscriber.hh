#ifndef _MBS_TF_SUBSCRIBER_HH_
#define _MBS_TF_SUBSCRIBER_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Subscriber class
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
#include <map>
#include <set>
#include <string>

#include "common.hh"

MBSTF_NAMESPACE_START

class SubscriptionService;
class Event;

class Subscriber
{
public:
    Subscriber();
    Subscriber(const Subscriber &other);
    Subscriber(Subscriber &&other);

    virtual ~Subscriber();

    Subscriber &operator=(const Subscriber &);
    Subscriber &operator=(Subscriber &&);

    virtual void processEvent(Event &event, SubscriptionService &event_service) = 0;
    virtual void subscriberRemoved(SubscriptionService &service);

    virtual std::string reprString() const;
    bool subscribeToService(SubscriptionService &service) {
        return subscribeTo(service);
    }

protected:
    bool subscribeTo(SubscriptionService &service); // subscribe to all events
    bool subscribeTo(std::initializer_list<const char*> events_list, SubscriptionService &service); // subscribe to specific events
    bool isSubscribedTo(SubscriptionService &service) const; // Check if we are subscribed in any way to service
    bool isSubscribedTo(std::initializer_list<const char*> events_list, SubscriptionService &service); // Check if we are subscribed to the given events on service

private:
    std::set<SubscriptionService*> m_subscriptions;
};

MBSTF_NAMESPACE_STOP

std::ostream &operator<<(std::ostream&, const MBSTF_NAMESPACE_NAME(Subscriber)&);

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_MBSTF_SUBSCRIBER_HH_ */
