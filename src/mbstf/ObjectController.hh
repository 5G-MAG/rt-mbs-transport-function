#ifndef _MBS_TF_OBJECT_CONTROLLER_HH_
#define _MBS_TF_OBJECT_CONTROLLER_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Object Controller base class
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
#include <mutex>
#include <list>

#include "common.hh"
#include "Controller.hh"
#include "ObjectStore.hh"
#include "ObjectPackager.hh"
#include "Subscriber.hh"

MBSTF_NAMESPACE_START

class DistributionSession;
class PullObjectIngester;
class PushObjectIngester;
class Controller;
class ObjectStore;

class ObjectController : public Controller, public Subscriber {
public:
    ObjectController() = delete;
    ObjectController(DistributionSession &distributionSession)
        :Controller(distributionSession)
	,Subscriber()
        ,m_objectStore(*this)
        ,m_pullIngesters()
        ,m_pushIngester()
        ,m_packager()
        ,m_nextId(1)
        ,m_consecutiveIngestFailures(0)
    { subscribeTo({"ObjectAdded"}, m_objectStore); };
    ObjectController(const ObjectController &) = delete;
    ObjectController(ObjectController &&) = delete;

    virtual ~ObjectController() {};

    ObjectController &operator=(const ObjectController &) = delete;
    ObjectController &operator=(ObjectController &&) = delete;

    const ObjectStore &objectStore() const { return m_objectStore; };
    ObjectStore &objectStore() { return m_objectStore; };

    const std::list<std::shared_ptr<PullObjectIngester>> &getPullObjectIngesters() const {return m_pullIngesters;};

    virtual void processEvent(Event &event, SubscriptionService &event_service);

    virtual std::string nextObjectId();

    const std::optional<std::string> &getObjectDistributionBaseUrl() const;

    virtual void reconfigure() {
        this->reconfigureObjectStore();
        this->reconfigurePushObjectIngester();
        this->reconfigurePullObjectIngesters();
        this->reconfigureObjectPackager();
    };
    virtual void reconfigureObjectStore();
    virtual void reconfigurePushObjectIngester() = 0;
    virtual void reconfigurePullObjectIngesters() = 0;
    virtual void reconfigureObjectPackager() = 0;

    virtual void establishInactiveInputs(); /* Inactive state for DistSession */
    virtual void establishActiveInputs();   /* Established state for DistSession */
    virtual void activateOutput();          /* Active state for DistSession */
    virtual void deactivateOutput();        /* Deactivating state for DistSession */

protected:
    const std::shared_ptr<PullObjectIngester> &addPullObjectIngester(const std::shared_ptr<PullObjectIngester> &pull_obj_ingester);
    const std::shared_ptr<PullObjectIngester> &addPullObjectIngester(PullObjectIngester *pull_obj_ingester);
    bool removePullObjectIngester(std::shared_ptr<PullObjectIngester> &);
    bool removeAllPullObjectIngesters();
    const std::shared_ptr<PushObjectIngester> &pushObjectIngester() const { return m_pushIngester; };
    const std::shared_ptr<PushObjectIngester> &pushObjectIngester(PushObjectIngester* pushIngester);
    bool removePushObjectIngester();
    const std::shared_ptr<ObjectPackager> &packager() const { return m_packager; };
    const std::shared_ptr<ObjectPackager> &packager(ObjectPackager*);

    virtual void initPushObjectIngester() = 0;
    virtual void initPullObjectIngesters() = 0;
    virtual void setObjectPackager() = 0;
    virtual void unsetObjectPackager() = 0;

    std::recursive_mutex m_pullObjectIngestersMutex;

private:
    ObjectStore m_objectStore;
    std::list<std::shared_ptr<PullObjectIngester>> m_pullIngesters;
    std::shared_ptr<PushObjectIngester> m_pushIngester;
    std::shared_ptr<ObjectPackager> m_packager;
    std::atomic_int m_nextId;
    int m_consecutiveIngestFailures;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_OBJECT_CONTROLLER_HH_ */
