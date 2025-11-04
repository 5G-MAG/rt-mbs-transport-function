#ifndef _MBS_TF_OBJECT_INGESTER_HH_
#define _MBS_TF_OBJECT_INGESTER_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Object Ingester base class
 ******************************************************************************
 * Copyright: (C)2024 British Broadcasting Corporation
 * Author(s): Dev Audsin <dev.audsin@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */


#include <atomic>
#include <string>
#include <thread>

#include "common.hh"
#include "Event.hh"
#include "SubscriptionService.hh"

MBSTF_NAMESPACE_START

class ObjectStore;
class ObjectController;

class ObjectIngester : public SubscriptionService {
public:
    class IngestFailedEvent : public Event {
    public:
        static constexpr const char *event_name = "ObjectIngestFailed";
        typedef enum {
            TIMED_OUT = 1,
            GENERAL_ERROR,
            CLIENT_ERROR,
            SERVER_ERROR
        } FailureType;

        IngestFailedEvent(const std::string& url, FailureType fail_type)
            : Event(event_name), m_url(url), m_failureType(fail_type) {};
        IngestFailedEvent(const IngestFailedEvent &other)
            : Event(other), m_url(other.m_url), m_failureType(other.m_failureType) {};
        IngestFailedEvent(IngestFailedEvent &&other)
            : Event(std::move(other)), m_url(std::move(other.m_url)), m_failureType(std::move(other.m_failureType)) {};

        virtual ~IngestFailedEvent() {};

        IngestFailedEvent &operator=(const IngestFailedEvent &other) { Event::operator=(other); m_url = other.m_url; m_failureType = other.m_failureType; return *this; };
        IngestFailedEvent &operator=(IngestFailedEvent &&other) { Event::operator=(std::move(other)); m_url = std::move(other.m_url); m_failureType = std::move(other.m_failureType); return *this; };

        const std::string &url() const { return m_url; };
        FailureType failureType() const { return m_failureType; };

    private:
        std::string m_url;
        FailureType m_failureType;
    };

    ObjectIngester() = delete;
    ObjectIngester(ObjectStore &objectStore, ObjectController &controller)
        : SubscriptionService(), m_objectStore(objectStore), m_controller(controller), m_workerThread(), m_workerCancel(false) {}

    void abort() {
	m_workerCancel = true;
        if (m_workerThread.get_id() != std::this_thread::get_id() && m_workerThread.joinable()) {
	    m_workerThread.join();
        }
    }

    virtual ~ObjectIngester() {
	abort();
    }

    bool workerCancelled() const { return m_workerCancel; };

protected:
    ObjectStore &objectStore() { return m_objectStore; }
    const ObjectStore &objectStore() const { return m_objectStore; }
    ObjectController &controller() { return m_controller; }
    const ObjectController &controller() const { return m_controller; }
    void startWorker(){m_workerThread = std::thread(workerLoop, this);};

    virtual void doObjectIngest() = 0;

    /* subscription events */
    void emitObjectIngestFailedEvent(const std::string &url, IngestFailedEvent::FailureType fail_type);

private:
    static void workerLoop(ObjectIngester*);
    ObjectStore &m_objectStore;
    ObjectController &m_controller;
    std::thread m_workerThread;
    std::atomic_bool m_workerCancel;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_OBJECT_INGESTER_HH_ */
