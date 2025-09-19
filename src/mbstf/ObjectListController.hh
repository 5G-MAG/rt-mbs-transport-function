#ifndef _MBS_TF_OBJECT_LIST_CONTROLLER_HH_
#define _MBS_TF_OBJECT_LIST_CONTROLLER_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Object List Controller class
 ******************************************************************************
 * Copyright: (C)2025 British Broadcasting Corporation
 * Author(s): Dev Audsin <dev.audsin@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include <memory>
#include <sstream>
#include <string>

#include "common.hh"
#include "openapi/model/ObjDistributionData.h"
#include "ObjectController.hh"
#include "Subscriber.hh"

MBSTF_NAMESPACE_START

class DistributionSession;
class Event;
class ObjectListPackager;
class PullObjectIngester;
class SubscriptionService;

class ObjectListController : public ObjectController {
public:
    ObjectListController() = delete;
    ObjectListController(DistributionSession &distributionSession);
    ObjectListController(const ObjectListController &) = delete;
    ObjectListController(ObjectListController &&) = delete;

    virtual ~ObjectListController();

    ObjectListController &operator=(const ObjectListController &) = delete;
    ObjectListController &operator=(ObjectListController &&) = delete;

    void fetchItems();
    std::shared_ptr<ObjectListPackager> getObjectListPackager() const;

    // Subscriber virtual methods
    virtual void processEvent(Event &event, SubscriptionService &event_service);
    // Optional: virtual void subscriberRemoved(SubscriptionService &event_service);
    std::string reprString() const {
                std::ostringstream os;
                os << "ObjectListController(controller =" << this << ")";
                return os.str();
    }
    virtual std::string nextObjectId();

    virtual void reconfigurePushObjectIngester();
    virtual void reconfigurePullObjectIngesters();
    virtual void reconfigureObjectPackager();

    static unsigned int factoryPriority() { return 100; };

protected:

    virtual void initPushObjectIngester();
    virtual void initPullObjectIngesters();
    virtual void setObjectPackager();
    virtual void unsetObjectPackager();

private:
    void sendToPackager(const std::string &objectId);

    std::string generateUUID();
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_OBJECT_LIST_CONTROLLER_HH_ */
