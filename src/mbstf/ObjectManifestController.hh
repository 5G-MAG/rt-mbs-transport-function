#ifndef _MBS_TF_OBJECT_MANIFEST_CONTROLLER_HH_
#define _MBS_TF_OBJECT_MANIFEST_CONTROLLER_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Object Manifest Controller base class
 ******************************************************************************
 * Copyright: (C)2025 British Broadcasting Corporation
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

    /*
    ObjectManifestController(DistributionSession &dist_session)
        :ObjectController(dist_session)
	,Subscriber()
        ,m_manifestHandler(nullptr)
	,m_scheduledPullCancel(false)
        {};
	*/
    ObjectManifestController(const ObjectManifestController&) = delete;
    ObjectManifestController(ObjectManifestController&&) = delete;

    void abort() {
        m_scheduledPullCancel = true;
        if (m_scheduledPullThread.joinable()) {
            m_scheduledPullThread.join();
        }

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

    ObjectManifestController &manifestHandler(std::unique_ptr<ManifestHandler> manifest_handler) {
        std::lock_guard guard(m_manifestHandlerMutex);
        m_manifestHandler = std::move(manifest_handler);
        m_manifestHandlerChange.notify_all();
        return *this;
    };
    ManifestHandler *manifestHandler() const {
        std::lock_guard guard(m_manifestHandlerMutex);
        return m_manifestHandler.get();
    };

    virtual std::string nextObjectId();


private:
    static void workerLoop(ObjectManifestController *controller);
    std::string generateUUID();

    std::string m_manifestUrl;
    std::unique_ptr<ManifestHandler> m_manifestHandler;
    std::condition_variable_any m_manifestHandlerChange;
    mutable std::recursive_mutex m_manifestHandlerMutex;
    std::thread m_scheduledPullThread;
    std::atomic_bool m_scheduledPullCancel;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_OBJECT_MANIFEST_CONTROLLER_HH_ */
