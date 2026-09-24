#ifndef _MBS_TF_OBJECT_MANIFEST_CONTROLLER_HH_
#define _MBS_TF_OBJECT_MANIFEST_CONTROLLER_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Object Manifest Controller base class
 ******************************************************************************
 * Copyright: (C)2025-2026 British Broadcasting Corporation
 * Author(s): David Waring <david.waring2@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include <memory>
#include <list>

#include "common.hh"
#include "ObjectController.hh"
#include "ManifestHandler.hh"
#include "DASHManifestHandler.hh"
#include "Subscriber.hh"

MBSTF_NAMESPACE_START

class DistributionSession;
class ManifestHandler;
class Event;
class SubscriptionService;

class ObjectManifestController : public ObjectController {
public:
    ObjectManifestController() = delete;
    ObjectManifestController(DistributionSession &dist_session);
    ObjectManifestController(const ObjectManifestController&) = delete;
    ObjectManifestController(ObjectManifestController&&) = delete;

    void abort() {
        {
            /* The scheduled pull spends almost all of its time parked in
               m_manifestHandlerChange.wait_until(), whose deadline is the next manifest fetch.
               Setting the flag alone leaves it there until that deadline arrives, so the join
               below waited out a whole fetch interval, which is what made terminating the
               process take tens of seconds. The mutex is held while the flag is set so the
               waiter cannot miss the notification, and released before the join so the thread
               can reacquire it on the way out. */
            std::lock_guard<std::recursive_mutex> lock(m_manifestHandlerMutex);
            m_scheduledPullCancel = true;
            m_manifestHandlerChange.notify_all();
        }
        if (m_scheduledPullThread.get_id() != std::this_thread::get_id() && m_scheduledPullThread.joinable()) {
            m_scheduledPullThread.join();
        }

    }

    /** Stop the scheduled pull as well as the ingest workers.
     *
     * The scheduled pull is this controller's own thread and it writes into controller state, so
     * a teardown that stops only the ingest workers leaves it running against objects that are
     * being destroyed. abort() is idempotent once the thread has been joined.
     */
    virtual void abortIngest() override {
        abort();
        ObjectController::abortIngest();
    }

    virtual ~ObjectManifestController() {
        abort();
    };

    ObjectManifestController &operator=(const ObjectManifestController&) = delete;
    ObjectManifestController &operator=(ObjectManifestController&&) = delete;

    virtual void processEvent(Event &event, SubscriptionService &event_service);
    std::string &getManifestUrl();
    void manifestUrl();

    virtual void reconfigurePushObjectIngester();
    virtual void reconfigurePullObjectIngesters();

protected:
    void startWorker();
    virtual void initPullObjectIngesters();
    virtual void initPushObjectIngester();
    ObjectManifestController &manifestHandler(std::shared_ptr<ManifestHandler> &&manifest_handler);
    const std::shared_ptr<ManifestHandler> &manifestHandler() const;
    virtual std::string nextObjectId();
    virtual void objectAddOrUpdateEvent(const std::shared_ptr<ObjectStore::Object> &object) {};
    virtual bool includeManifest() { return false; };
    virtual bool checkObjectActiveInManifest(const std::shared_ptr<ObjectStore::Object> &object) { return true; };
    virtual void finishRequestInManifestHandler(const std::shared_ptr<ObjectStore::Object> &object) {};
    virtual void sendToPackager(const std::shared_ptr<ObjectStore::Object> &object) = 0;

private:
    static void workerLoop(ObjectManifestController *controller);
    std::list<PullObjectIngester::IngestItem> getPullAcquisitionIngestList();
    std::string generateUUID();

    std::string m_manifestUrl;
    std::shared_ptr<ManifestHandler> m_manifestHandler;
    std::condition_variable_any m_manifestHandlerChange;
    mutable std::recursive_mutex m_manifestHandlerMutex;
    std::thread m_scheduledPullThread;
    std::atomic_bool m_scheduledPullCancel;
    std::atomic_bool m_scheduledPullRunning;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_OBJECT_MANIFEST_CONTROLLER_HH_ */
