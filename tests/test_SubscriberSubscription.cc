/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Unit test: Subscriber/Subscription
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
#include <condition_variable>
#include <exception>
#include <format>
#include <iostream>
#include <optional>
#include <mutex>

#include "common.hh"
#include "SubscriptionService.hh"
#include "Subscriber.hh"
#include "Event.hh"

using namespace std::chrono_literals;

MBSTF_NAMESPACE_USING;

class EventType1 : public Event
{
public:
    EventType1(int data) :Event("Type1"),m_data(data) {};
    EventType1(const EventType1 &other) :Event(other), m_data(other.m_data) {};

    virtual ~EventType1() {};

    virtual Event clone() const {return EventType1(*this);};
    virtual Event *newClone() const {return new EventType1(*this);};
    virtual std::string reprString() const { return std::format("EventType1({})", m_data); };

    int data() const { return m_data; };

private:
    int m_data;
};

class EventType2 : public Event
{
public:
    EventType2(int data) :Event("Type2"),m_data(data) {};
    EventType2(const EventType2 &other) :Event(other), m_data(other.m_data) {};

    virtual ~EventType2() {};

    virtual Event clone() const {return EventType2(*this);};
    virtual Event *newClone() const {return new EventType2(*this);};
    virtual std::string reprString() const { return std::format("EventType2({})", m_data); };

    int data() const { return m_data; };

private:
    int m_data;
};


class TestSubscriptionService : public SubscriptionService
{
public:
    TestSubscriptionService() :SubscriptionService() {};

    bool sendSynchronous(Event &event) {return sendEventSynchronous(event);};
    void sendAsynchronous(const std::shared_ptr<Event> &event) {sendEventAsynchronous(event);};
};

class TestSubscriber : public Subscriber
{
public:
    TestSubscriber() :Subscriber(), m_result() {};

    void addSubscribeToAll(SubscriptionService &svc) {
        if (!subscribeTo(svc)) {
            //std::cout << "TestSubscriber[" << this << "]: ERROR: Failed subscription all" << std::endl;
            throw std::runtime_error("Failed subscription");
        }
    }

    void addSubscribeToT1(SubscriptionService &svc) {
        if (!subscribeTo({"Type1"}, svc)) {
            //std::cout << "TestSubscriber[" << this << "]: ERROR: Failed subscription T1" << std::endl;
            throw std::runtime_error("Failed subscription");
        }
    }
    
    void addSubscribeToT2(SubscriptionService &svc) {
        if (!subscribeTo({"Type2"}, svc)) {
            //std::cout << "TestSubscriber[" << this << "]: ERROR: Failed subscription T2" << std::endl;
            throw std::runtime_error("Failed subscription");
        }
    }

    virtual ~TestSubscriber() { /*std::cout << "TestSubscriber[" << this << "]: going away" << std::endl; */ };

    virtual void processEvent(Event &event, SubscriptionService &event_service) {
        //std::cout << "TestSubscriber[" << this << "]: " << event_service << " sent: " << event << std::endl;
        if (event.eventName() == "Type1") {
            EventType1 &et1 = dynamic_cast<EventType1&>(event);
            m_result = et1.data();
        } else if (event.eventName() == "Type2") {
            EventType2 &et2 = dynamic_cast<EventType2&>(event);
            m_result = et2.data();
        }
        event.preventDefault();
    };
    virtual void subscriberRemoved(SubscriptionService &service) {
        //std::cout << "TestSubscriber[" << this << "]: Subscription service " << service << " has gone away" << std::endl;
        Subscriber::subscriberRemoved(service);
    };

    bool subscribedTo(SubscriptionService &svc) const {
        return isSubscribedTo(svc);
    };

    const std::optional<int> &result() const { return m_result; };
    void resetResult() { m_result.reset(); };

private:
    std::optional<int> m_result;
};

class TestAsyncSubscriber : public Subscriber
{
public:
    TestAsyncSubscriber() :Subscriber(),m_eventResult(std::nullopt),m_condMutex(),m_condVar() {};

    virtual ~TestAsyncSubscriber() {};

    virtual void processEvent(Event &event, SubscriptionService &event_service) {
        //std::cout << "TestAsyncSubscriber[" << this << "]: " << event_service << " sent: " << event << std::endl;
        if (event.eventName() == "Type1") {
            EventType1 &ev1 = dynamic_cast<EventType1&>(event);
            std::lock_guard guard(m_condMutex);
            m_eventResult = ev1.data();
            m_condVar.notify_all();
        }   
        event.preventDefault();
    };

    virtual void subscriberRemoved(SubscriptionService &service) {
        //std::cout << "TestAsyncSubscriber[" << this << "]: Subscription service " << service << " has gone away" << std::endl;
        Subscriber::subscriberRemoved(service);
    };

    void waitForEvent() {
        std::lock_guard guard(m_condMutex);
        if (!m_eventResult) {
            m_condVar.wait(m_condMutex);
        }
    }

    template <class Rep, class Period>
    bool waitForEvent(std::chrono::duration<Rep, Period> timeout) {
        std::lock_guard guard(m_condMutex);
        //std::cout << "TestAsyncSubscriber[" << this << "]: Wait for event" << std::endl;
        if (!m_eventResult) {
            if (m_condVar.wait_for(m_condMutex, timeout) == std::cv_status::timeout) {
                return false;
            }
        }
        //std::cout << "TestAsyncSubscriber[" << this << "]: got " << m_eventResult.value() << std::endl;
        return true;
    };

    void addSubscribeToAll(SubscriptionService &svc) {
        if (!subscribeTo(svc)) {
            //std::cout << "TestAsyncSubscriber[" << this << "]: ERROR: Failed subscription all" << std::endl;
            throw std::runtime_error("Failed subscription");
        }
    };

    void addSubscribeToT1(SubscriptionService &svc) {
        if (!subscribeTo({"Type1"}, svc)) {
            //std::cout << "TestAsyncSubscriber[" << this << "]: ERROR: Failed subscription T1" << std::endl;
            throw std::runtime_error("Failed subscription");
        }
    };

private:
    std::optional<int> m_eventResult;
    std::recursive_mutex m_condMutex;
    std::condition_variable_any m_condVar;
};

enum Result {
    RESULT_OK = 0,
    RESULT_ERROR,
    RESULT_SKIP,
    RESULT_MAX
};

struct TestContext {
    TestSubscriptionService *services[3];
    TestSubscriber *subscribers[3];
    TestAsyncSubscriber *async_subscribers[1];
};

void test_setup(TestContext &context)
{
    context.services[0] = new TestSubscriptionService;
    context.services[1] = new TestSubscriptionService;
}

Result test_synchronous_filtered(TestContext &ctx)
{
    // Setup subscribers
    ctx.subscribers[0] = new TestSubscriber();
    ctx.subscribers[0]->addSubscribeToT1(*ctx.services[0]);
    ctx.subscribers[0]->addSubscribeToT2(*ctx.services[1]);

    ctx.subscribers[1] = new TestSubscriber();
    ctx.subscribers[1]->addSubscribeToT2(*ctx.services[0]);
    ctx.subscribers[1]->addSubscribeToT1(*ctx.services[1]);

    // Check subscriptions
    {
        auto events = ctx.services[0]->subscribedEvents(*ctx.subscribers[0]);
        if (events.size() != 1 || std::string(events.front()) != "Type1") {
            std::cerr << "Mismatched in subscribed events from subscriber 1 and service 1" << std::endl;
            return RESULT_ERROR;
        }

        events = ctx.services[0]->subscribedEvents(*ctx.subscribers[1]);
        if (events.size() != 1 || std::string(events.front()) != "Type2") {
            std::cerr << "Mismatched in subscribed events from subscriber 2 and service 1" << std::endl;
            return RESULT_ERROR;
        }

        events = ctx.services[1]->subscribedEvents(*ctx.subscribers[0]);
        if (events.size() != 1 || std::string(events.front()) != "Type2") {
            std::cerr << "Mismatched in subscribed events from subscriber 1 and service 2" << std::endl;
            return RESULT_ERROR;
        }

        events = ctx.services[1]->subscribedEvents(*ctx.subscribers[1]);
        if (events.size() != 1 || std::string(events.front()) != "Type1") {
            std::cerr << "Mismatched in subscribed events from subscriber 2 and service 2" << std::endl;
            return RESULT_ERROR;
        }
    }

    // Send Type1 event from first service, should only be seen by first subscriber

    EventType1 t1(42);

    if (ctx.services[0]->sendSynchronous(t1)) {
        std::cerr << "Unexpected default event action on synchronous Type1 event" << std::endl;
        return RESULT_ERROR;
    }

    {
        const std::optional<int> &event_result1 = ctx.subscribers[0]->result();
        const std::optional<int> &event_result2 = ctx.subscribers[1]->result();

        if (!event_result1 || event_result2) {
            std::cerr << "Type1 event not sent to correct subscribers" << std::endl;
            return RESULT_ERROR;
        }

        if (event_result1.value() != 42) {
            std::cerr << "Wrong data propagated in Type1 event" << std::endl;
            return RESULT_ERROR;
        }

        ctx.subscribers[0]->resetResult();
    }

    // Send Type2 event from first service, should only be seen by second subscriber

    EventType2 t2(128);

    if (ctx.services[0]->sendSynchronous(t2)) {
        std::cerr << "Unexpected default event action on synchronous Type2 event" << std::endl;
        return RESULT_ERROR;
    }

    {
        const std::optional<int> &event_result1 = ctx.subscribers[0]->result();
        const std::optional<int> &event_result2 = ctx.subscribers[1]->result();

        if (event_result1 || !event_result2) {
            std::cerr << "Type2 event not sent to correct subscribers" << std::endl;
            return RESULT_ERROR;
        }

        if (event_result2.value() != 128) {
            std::cerr << "Wrong data propagated in Type2 event" << std::endl;
            return RESULT_ERROR;
        }

        ctx.subscribers[1]->resetResult();
    }

    auto tmp_svc = ctx.services[0];
    delete ctx.services[0];
    ctx.services[0] = nullptr;

    if (ctx.subscribers[0]->subscribedTo(*tmp_svc) || ctx.subscribers[1]->subscribedTo(*tmp_svc)) {
        std::cerr << "Unsubscribe upon service deletion failed to propagate" << std::endl;
        return RESULT_ERROR;
    }

    if (!ctx.subscribers[0]->subscribedTo(*ctx.services[1]) || !ctx.subscribers[1]->subscribedTo(*ctx.services[1])) {
        std::cerr << "Unsubscribe upon service deletion progagated to wrong service" << std::endl;
        return RESULT_ERROR;
    }

    // check subscriptions

    {
        auto events = ctx.services[1]->subscribedEvents(*ctx.subscribers[0]);
        if (events.size() != 1 || std::string(events.front()) != "Type2") {
            std::cerr << "Mismatched in subscribed events, after deletion of service 1, from subscriber 1 and service 2" << std::endl;
            return RESULT_ERROR;
        }

        events = ctx.services[1]->subscribedEvents(*ctx.subscribers[1]);
        if (events.size() != 1 || std::string(events.front()) != "Type1") {
            std::cerr << "Mismatched in subscribed events, after deletion of service 1, from subscriber 2 and service 2" << std::endl;
            return RESULT_ERROR;
        }
    }

    // delete first subscriber, should only leave one subscription on second service

    delete ctx.subscribers[0];
    ctx.subscribers[0] = nullptr;

    if (!ctx.subscribers[1]->subscribedTo(*ctx.services[1])) {
        std::cerr << "Unsubscribe of subscriber 1 from service 2 progagated to subscriber 2" << std::endl;
        return RESULT_ERROR;
    }

    // Restore subscribers and services

    ctx.services[0] = new TestSubscriptionService;
    ctx.subscribers[0] = new TestSubscriber;

    ctx.subscribers[0]->addSubscribeToT1(*ctx.services[0]);
    ctx.subscribers[0]->addSubscribeToT2(*ctx.services[1]);
    ctx.subscribers[1]->addSubscribeToT2(*ctx.services[0]);
    
    // Check subscriptions
    {
        auto events = ctx.services[0]->subscribedEvents(*ctx.subscribers[0]);
        if (events.size() != 1 || std::string(events.front()) != "Type1") {
            std::cerr << "Mismatched in subscribed events from subscriber 1 and service 1 [restore]" << std::endl;
            return RESULT_ERROR;
        }

        events = ctx.services[0]->subscribedEvents(*ctx.subscribers[1]);
        if (events.size() != 1 || std::string(events.front()) != "Type2") {
            std::cerr << "Mismatched in subscribed events from subscriber 2 and service 1 [restore]" << std::endl;
            return RESULT_ERROR;
        }

        events = ctx.services[1]->subscribedEvents(*ctx.subscribers[0]);
        if (events.size() != 1 || std::string(events.front()) != "Type2") {
            std::cerr << "Mismatched in subscribed events from subscriber 1 and service 2 [restore]" << std::endl;
            return RESULT_ERROR;
        }

        events = ctx.services[1]->subscribedEvents(*ctx.subscribers[1]);
        if (events.size() != 1 || std::string(events.front()) != "Type1") {
            std::cerr << "Mismatched in subscribed events from subscriber 2 and service 2 [restore]" << std::endl;
            return RESULT_ERROR;
        }
    }

    return RESULT_OK;
}

Result test_synchronous_unfiltered(TestContext &ctx)
{
    ctx.subscribers[0]->addSubscribeToAll(*ctx.services[0]);
    ctx.subscribers[1]->addSubscribeToAll(*ctx.services[1]);

    {
        auto events = ctx.services[0]->subscribedEvents(*ctx.subscribers[0]);
        if (events.size() != 1 || events.front() != nullptr) {
            std::cerr << "Mismatched in subscribed events from subscriber 1 and service 1 [unfiltered-prelude]" << std::endl;
            return RESULT_ERROR;
        }

        events = ctx.services[0]->subscribedEvents(*ctx.subscribers[1]);
        if (events.size() != 1 || std::string(events.front()) != "Type2") {
            std::cerr << "Mismatched in subscribed events from subscriber 2 and service 1 [unfiltered-prelude]" << std::endl;
            return RESULT_ERROR;
        }

        events = ctx.services[1]->subscribedEvents(*ctx.subscribers[0]);
        if (events.size() != 1 || std::string(events.front()) != "Type2") {
            std::cerr << "Mismatched in subscribed events from subscriber 1 and service 2 [unfiltered-prelude]" << std::endl;
            return RESULT_ERROR;
        }

        events = ctx.services[1]->subscribedEvents(*ctx.subscribers[1]);
        if (events.size() != 1 || events.front() != nullptr) {
            std::cerr << "Mismatched in subscribed events from subscriber 2 and service 2 [unfiltered-prelude]" << std::endl;
            return RESULT_ERROR;
        }
    }

    // Send Type1 event from first service, should only be seen by first subscriber

    EventType1 t1(56);

    if (ctx.services[0]->sendSynchronous(t1)) {
        std::cerr << "Unexpected default event action on synchronous Type1 event" << std::endl;
        return RESULT_ERROR;
    }

    {
        const std::optional<int> &event_result1 = ctx.subscribers[0]->result();
        const std::optional<int> &event_result2 = ctx.subscribers[1]->result();

        if (!event_result1 || event_result2) {
            std::cerr << "Type1 event not sent to correct subscribers" << std::endl;
            return RESULT_ERROR;
        }

        if (event_result1.value() != 56) {
            std::cerr << "Wrong data propagated in Type1 event" << std::endl;
            return RESULT_ERROR;
        }

        ctx.subscribers[0]->resetResult();
    }

    // Send Type2 event from first service, should only be seen by both subscribers

    EventType2 t2(1234);

    if (ctx.services[0]->sendSynchronous(t2)) {
        std::cerr << "Unexpected default event action on synchronous Type2 event" << std::endl;
        return RESULT_ERROR;
    }

    {
        const std::optional<int> &event_result1 = ctx.subscribers[0]->result();
        const std::optional<int> &event_result2 = ctx.subscribers[1]->result();

        if (!event_result1 || !event_result2) {
            std::cerr << "Type2 event not sent to correct subscribers" << std::endl;
            return RESULT_ERROR;
        }

        if (event_result1.value() != 1234 || event_result2.value() != 1234) {
            std::cerr << "Wrong data propagated in Type2 event" << std::endl;
            return RESULT_ERROR;
        }

        ctx.subscribers[0]->resetResult();
        ctx.subscribers[1]->resetResult();
    }

    return RESULT_OK;
}

Result test_asynchronous_filtered(TestContext &ctx)
{
    // async test

    ctx.async_subscribers[0] = new TestAsyncSubscriber();
    ctx.services[2] = new TestSubscriptionService;
    std::shared_ptr<Event> t5(new EventType1(1));
    
    ctx.async_subscribers[0]->addSubscribeToT1(*ctx.services[2]);

    ctx.services[2]->sendAsynchronous(t5);
    t5.reset();

    if (!ctx.async_subscribers[0]->waitForEvent(15s)) {
        std::cerr << "Async Event took longer than 15 seconds to reach subscriber" << std::endl;
        return RESULT_ERROR;
    }

    return RESULT_OK;
}

Result test_asynchronous_unfiltered(TestContext &ctx)
{
    ctx.async_subscribers[0]->addSubscribeToAll(*ctx.services[2]);

    std::shared_ptr<Event> t5(new EventType1(2));
    ctx.services[2]->sendAsynchronous(t5);
    t5.reset();

    if (!ctx.async_subscribers[0]->waitForEvent(15s)) {
        std::cerr << "Async Event took longer than 15 seconds to reach subscriber" << std::endl;
        return RESULT_ERROR;
    }

    return RESULT_OK;
}

void test_cleanup(TestContext &ctx)
{
    for (auto *svc : ctx.services) {
        if (svc) {
            //std::cout << "delete TestSubscriptionService " << svc << std::endl;
            delete svc;
        }
    }
    for (auto *sub : ctx.subscribers) {
        if (sub) {
            //std::cout << "delete TestSubscriber " << sub << std::endl;
            delete sub;
        }
    }
    for (auto *sub : ctx.async_subscribers) {
        if (sub) {
            //std::cout << "delete TestAsyncSubscriber " << sub << std::endl;
            delete sub;
        }
    }
}

int main(int argc, char *argv[])
{
    TestContext ctx = {};
    test_setup(ctx);

    static const struct TestCase {
        const char *name;
        Result (*fn)(TestContext &ctx);
    } tests[] = {
        {"Synchronous events with event filters", test_synchronous_filtered},
        {"Synchronous events without event filters", test_synchronous_unfiltered},
        {"Asynchronous events with event filters", test_asynchronous_filtered},
        {"Asynchronous events without event filters", test_asynchronous_unfiltered}
    };

    size_t results[RESULT_MAX] = {};
    size_t total = 0;
    for (auto tc : tests) {
        std::cout << tc.name << "... ";
        Result result = tc.fn(ctx);
        total++;
        results[result]++;
        switch (result) {
        case RESULT_OK:
            std::cout << "ok" << std::endl;
            break;
        case RESULT_ERROR:
            std::cout << "ERROR!" << std::endl;
            break;
        case RESULT_SKIP:
            std::cout << "skipped" << std::endl;
            break;
        default:
            std::cout << "runtime error, aborting!" << std::endl;
            test_cleanup(ctx);
            return 1;
        }
    }

    test_cleanup(ctx);

    if (results[RESULT_OK] == 0 && results[RESULT_ERROR] == 0) return 77; /* tests skipped */

    if (results[RESULT_ERROR] != 0) return 1;

    return 0;
}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
