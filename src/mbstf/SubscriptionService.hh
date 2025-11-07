#ifndef _MBS_TF_SUBSCRIPTION_SERVICE_HH_
#define _MBS_TF_SUBSCRIPTION_SERVICE_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Subscription Service class
 ******************************************************************************
 * Copyright: (C)2025 British Broadcasting Corporation
 * Author(s): David Waring <david.waring2@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include <atomic>
#include <condition_variable>
#include <deque>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>

#include "common.hh"
#include "LocalEvents.hh"

MBSTF_NAMESPACE_START

class Subscriber;
class Event;

class SubscriptionService : public std::enable_shared_from_this<SubscriptionService>
{
public:
    SubscriptionService();
    SubscriptionService(const SubscriptionService &);
    SubscriptionService(SubscriptionService &&);

    virtual ~SubscriptionService();

    SubscriptionService &operator=(const SubscriptionService &);
    SubscriptionService &operator=(SubscriptionService &&);

    bool subscribe(Subscriber &subscriber); // subscribe to all events
    bool subscribe(std::initializer_list<const char*> events_list, Subscriber &subscriber); // subscribe to named events
    template <class Iterable>
    bool subscribe(const Iterable &iterable, Subscriber &subscriber); // subscribe to named events
    bool unsubscribe(Subscriber &subscriber); // unsubscribe to any events (named or all)
    bool unsubscribe(std::initializer_list<const char*> events_list, Subscriber &subscriber); // unsubscribe from named events
    std::list<const char*> subscribedEvents(Subscriber &subscriber); // get the list of named events a Subscriber is subscribed to. nullptr in return means subscribed to all events. empty list means Subscriber is not subscribed.
    std::string reprString() const;

protected:
    bool sendEventSynchronous(Event &event);

    void sendEventAsynchronous(Event &&event);
    void sendEventAsynchronous(Event *event);
    void sendEventAsynchronous(const std::shared_ptr<Event> &event);

private:
    void startAsyncLoop();
    void stopAsyncLoop();
    static void asyncEventsLoopRunner(SubscriptionService *svc);
    void asyncEventsLoop();

    std::set<Subscriber*> m_allEventSubscriptions;
    std::map<std::string, std::set<Subscriber*> > m_namedEventSubscriptions;
    std::thread m_asyncThread;
    std::deque<std::shared_ptr<Event> > m_asyncEventQueue;
    std::unique_ptr<std::recursive_mutex> m_asyncMutex;
    std::condition_variable_any m_asyncCondVar;
    std::atomic_bool m_asyncCancel;
};

template <class Iterable>
bool SubscriptionService::subscribe(const Iterable &iterable, Subscriber &subscriber)
{
    bool ret = false;
    if (m_allEventSubscriptions.find(&subscriber) != m_allEventSubscriptions.end()) return ret;
    for (auto event_name : iterable) {
        std::string evt_name(event_name);
        auto &subsc_set = m_namedEventSubscriptions[evt_name];
        ret = subsc_set.insert(&subscriber).second || ret;
    }
    return ret;
}

MBSTF_NAMESPACE_STOP

std::ostream &operator<<(std::ostream &ostrm, const MBSTF_NAMESPACE_NAME(SubscriptionService)&);

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_SUBSCRIPTION_SERVICE_HH_ */
