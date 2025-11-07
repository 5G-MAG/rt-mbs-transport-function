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

#include <chrono>
#include <deque>
#include <list>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <thread>

#include "common.hh"
#include "App.hh"
#include "Subscriber.hh"
#include "Event.hh"

#include "SubscriptionService.hh"

MBSTF_NAMESPACE_START

SubscriptionService::SubscriptionService()
    :std::enable_shared_from_this<SubscriptionService>()
    ,m_allEventSubscriptions()
    ,m_namedEventSubscriptions()
    ,m_asyncThread()
    ,m_asyncEventQueue()
    ,m_asyncMutex(new std::recursive_mutex)
    ,m_asyncCondVar()
    ,m_asyncCancel(false)
{
}

SubscriptionService::SubscriptionService(const SubscriptionService &other)
    :std::enable_shared_from_this<SubscriptionService>(other)
    ,m_allEventSubscriptions(std::move(other.m_allEventSubscriptions))
    ,m_namedEventSubscriptions(std::move(other.m_namedEventSubscriptions))
    ,m_asyncThread()
    ,m_asyncEventQueue()
    ,m_asyncMutex(new std::recursive_mutex)
    ,m_asyncCondVar()
    ,m_asyncCancel(false)
{
    if (other.m_asyncThread.get_id() != std::thread::id() &&
        !other.m_asyncCancel) {
        std::lock_guard other_guard(*other.m_asyncMutex);
        m_asyncEventQueue = other.m_asyncEventQueue;
        startAsyncLoop();
    }
}

SubscriptionService::SubscriptionService(SubscriptionService &&other)
    :std::enable_shared_from_this<SubscriptionService>(std::move(other))
    ,m_allEventSubscriptions(std::move(other.m_allEventSubscriptions))
    ,m_namedEventSubscriptions(std::move(other.m_namedEventSubscriptions))
    ,m_asyncThread()
    ,m_asyncEventQueue()
    ,m_asyncMutex(new std::recursive_mutex)
    ,m_asyncCondVar()
    ,m_asyncCancel(false)
{
    if (other.m_asyncThread.get_id() != std::thread::id() &&
        !other.m_asyncCancel) {
        other.stopAsyncLoop();
        std::lock_guard other_guard(*other.m_asyncMutex);
        m_asyncEventQueue = std::move(other.m_asyncEventQueue);
        startAsyncLoop();
    }
}

SubscriptionService::~SubscriptionService()
{
    stopAsyncLoop();
    std::lock_guard guard(*m_asyncMutex);
    std::set<Subscriber*> subscribers;
    for (auto &subsc : m_allEventSubscriptions) {
        subscribers.insert(subsc);
    }
    for (auto& [name, subsc_set]: m_namedEventSubscriptions) {
        for (auto subsc : subsc_set) {
            subscribers.insert(subsc);
        }
    }
    for (auto subsc : subscribers) {
        subsc->subscriberRemoved(*this);
    }
}

SubscriptionService &SubscriptionService::operator=(const SubscriptionService &other)
{
    std::lock_guard guard(*m_asyncMutex);
    std::lock_guard other_guard(*other.m_asyncMutex);
    std::enable_shared_from_this<SubscriptionService>::operator=(other);
    m_allEventSubscriptions = other.m_allEventSubscriptions;
    m_namedEventSubscriptions = other.m_namedEventSubscriptions;
    if (other.m_asyncThread.get_id() != std::thread::id() &&
        !other.m_asyncCancel) {
        m_asyncEventQueue = other.m_asyncEventQueue;
        m_asyncCondVar.notify_all();
        startAsyncLoop();
    } else {
        stopAsyncLoop();
        m_asyncEventQueue.clear();
    }
    m_asyncCancel = !!other.m_asyncCancel;

    return *this;
}

SubscriptionService &SubscriptionService::operator=(SubscriptionService &&other)
{
    std::lock_guard guard(*m_asyncMutex);
    std::lock_guard other_guard(*other.m_asyncMutex);
    std::enable_shared_from_this<SubscriptionService>::operator=(std::move(other));
    m_allEventSubscriptions = std::move(other.m_allEventSubscriptions);
    m_namedEventSubscriptions = std::move(other.m_namedEventSubscriptions);
    if (other.m_asyncThread.get_id() != std::thread::id() &&
        !other.m_asyncCancel) {
        other.stopAsyncLoop();
        m_asyncEventQueue = std::move(other.m_asyncEventQueue);
        m_asyncCondVar.notify_all();
        startAsyncLoop();
    } else {
        stopAsyncLoop();
        m_asyncEventQueue.clear();
        other.m_asyncEventQueue.clear();
    }
    m_asyncCancel = !!other.m_asyncCancel;

    return *this;
}

bool SubscriptionService::subscribe(Subscriber &subscriber)
{
    std::lock_guard guard(*m_asyncMutex);
    // Remove named subscriptions if subscriber is now subscribing to all
    for (auto it = m_namedEventSubscriptions.begin(); it != m_namedEventSubscriptions.end(); /* handle in loop */) {
        auto &[name, subsc_set] = *it;
        if (subsc_set.erase(&subscriber) > 0) {
            if (subsc_set.empty()) {
                it = m_namedEventSubscriptions.erase(it);
            } else {
                ++it;
            }
        } else {
            ++it;
        }
    }
    // Add subscriber to all events list
    return m_allEventSubscriptions.insert(&subscriber).second;
}

bool SubscriptionService::subscribe(std::initializer_list<const char*> events_list, Subscriber &subscriber)
{
    bool ret = false;
    if (m_allEventSubscriptions.find(&subscriber) != m_allEventSubscriptions.end()) {
        // already subscribed to all events, ignore this request
        return false;
    }
    std::lock_guard guard(*m_asyncMutex);
    for (auto event_name : events_list) {
        auto &subsc_list = m_namedEventSubscriptions[std::string(event_name)];
        ret = subsc_list.insert(&subscriber).second || ret;
    }
    return ret;
}

bool SubscriptionService::unsubscribe(Subscriber &subscriber)
{
    bool ret = false;
    std::lock_guard guard(*m_asyncMutex);
    ret = (m_allEventSubscriptions.erase(&subscriber) > 0);
    if (!ret) {
        // check for individual events
        for (auto it = m_namedEventSubscriptions.begin(); it != m_namedEventSubscriptions.end(); /* handle in loop */) {
            auto &[name, subsc_set] = *it;
            if (subsc_set.erase(&subscriber) > 0) {
                ret = true;
                if (subsc_set.empty()) {
                    it = m_namedEventSubscriptions.erase(it);
                } else {
                    ++it;
                }
            } else {
                ++it;
            }
        }
    }
    return ret;
}

bool SubscriptionService::unsubscribe(std::initializer_list<const char*> events_list, Subscriber &subscriber)
{
    bool ret = false;
    for (auto name : events_list) {
        std::string event_name(name);
        auto it = m_namedEventSubscriptions.find(event_name);
        if (it != m_namedEventSubscriptions.end()) {
            if (it->second.erase(&subscriber) > 0) {
                ret = true;
                if (it->second.empty()) {
                    it = m_namedEventSubscriptions.erase(it);
                }
            }
        }
    }
    return ret;
}

std::list<const char*> SubscriptionService::subscribedEvents(Subscriber &subscriber)
{
    std::list<const char*> ret;
    if (m_allEventSubscriptions.find(&subscriber) != m_allEventSubscriptions.end()) {
        ret.push_back(nullptr);
    } else {
        for (auto &[name, subsc_set] : m_namedEventSubscriptions) {
            if (subsc_set.find(&subscriber) != subsc_set.end()) {
                ret.push_back(name.c_str());
            }
        }
    }
    return ret;
}

std::string SubscriptionService::reprString() const
{
    std::ostringstream os;
    os << "SubscriptionService(/* subscriptions=[";
    const char *sep="";
    for (auto subsc : m_allEventSubscriptions) {
        os << sep << *subsc;
        sep = ", ";
    }
    for (auto &[name, subsc_set] : m_namedEventSubscriptions) {
        os << sep << "{\"" << name << "\": [";
        sep = ", ";
        const char *sep2 = "";
        for (auto subsc : subsc_set) {
            os << sep2 << *subsc;
            sep2 = ", ";
        }
        os << "]}";
    }
    os << "] */)[" << this << "]";
    return os.str();
}

bool SubscriptionService::sendEventSynchronous(Event &event)
{
    std::lock_guard guard(*m_asyncMutex);
    auto self = shared_from_this(); /* make sure we don't get deleted while sending events */
    auto it = m_namedEventSubscriptions.find(event.eventName());
    if (it != m_namedEventSubscriptions.end()) {
        for (auto &subsc : it->second) {
            m_asyncMutex->unlock();
            subsc->processEvent(event, *this);
            m_asyncMutex->lock();
            if (event.stopProcessingFlag()) break;
        }
    }
    if (event.stopProcessingFlag()) return false;
    for (auto &subsc : m_allEventSubscriptions) {
        m_asyncMutex->unlock();
	subsc->processEvent(event, *this);
        m_asyncMutex->lock();
	if (event.stopProcessingFlag()) break;
    }
    return !event.preventDefaultFlag();
}

void SubscriptionService::sendEventAsynchronous(Event &&event)
{
    std::lock_guard guard(*m_asyncMutex);
    m_asyncEventQueue.emplace_back(std::shared_ptr<Event>(event.newClone()));
    m_asyncCondVar.notify_all();
    startAsyncLoop();
}

void SubscriptionService::sendEventAsynchronous(Event *event)
{
    std::lock_guard guard(*m_asyncMutex);
    m_asyncEventQueue.emplace_back(std::shared_ptr<Event>(event));
    m_asyncCondVar.notify_all();
    startAsyncLoop();
}

void SubscriptionService::sendEventAsynchronous(const std::shared_ptr<Event> &event)
{
    std::lock_guard guard(*m_asyncMutex);
    m_asyncEventQueue.push_back(event);
    m_asyncCondVar.notify_all();
    startAsyncLoop();
}

void SubscriptionService::startAsyncLoop()
{
    if (m_asyncThread.get_id() != std::thread::id()) return;
    if (!!m_asyncCancel) return;
    m_asyncThread = std::thread(SubscriptionService::asyncEventsLoopRunner, this);
}

void SubscriptionService::stopAsyncLoop()
{
    {
        std::lock_guard guard(*m_asyncMutex);
        m_asyncCancel = true;
        m_asyncCondVar.notify_all();
    }
    if (m_asyncThread.get_id() != std::this_thread::get_id() && m_asyncThread.joinable()) m_asyncThread.join();
}

void SubscriptionService::asyncEventsLoopRunner(SubscriptionService *svc)
{
    svc->asyncEventsLoop();
}

void SubscriptionService::asyncEventsLoop()
{
    using namespace std::literals;
    auto self = shared_from_this(); /* make sure we don't get deleted while sending events, but exit if we are the last holder */
    while (!m_asyncCancel && self.use_count() > 1) {
        std::lock_guard guard(*m_asyncMutex);
        while (!m_asyncCancel && m_asyncEventQueue.empty()) {
            m_asyncCondVar.wait_for(*m_asyncMutex, 500ms);
        }
        while (!m_asyncCancel && !m_asyncEventQueue.empty()) {
            auto event = m_asyncEventQueue.front();
            m_asyncEventQueue.pop_front();
            m_asyncMutex->unlock();
            try {
                sendEventSynchronous(*event);
            } catch (std::exception &ex) {
                //m_asyncCancel = true;
            }
            m_asyncMutex->lock();
        }
    }
    if (self.use_count() == 1) {
        std::shared_ptr<Open5GSEvent> evt(new Open5GSEvent(new ogs_event_t));
        evt->ogsEvent()->id = LocalEvents::RELEASE_SUBSCRIPTION_SVC;
        evt->setSbiData(new std::shared_ptr<SubscriptionService>(self));
        App::self().queuePush(evt);
    }
}

MBSTF_NAMESPACE_STOP

std::ostream &operator<<(std::ostream &ostrm, const MBSTF_NAMESPACE_NAME(SubscriptionService) &svc)
{
    ostrm << svc.reprString();
    return ostrm;
}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
