#ifndef _MBS_TF_OBJECT_STREAMING_CONTROLLER_HH_
#define _MBS_TF_OBJECT_STREAMING_CONTROLLER_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Object Streaming Controller class
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
#include "ObjectManifestController.hh"

MBSTF_NAMESPACE_START

class DistributionSession;
class Event;
class ObjectListPackager;
class PullObjectIngester;
class SubscriptionService;
class ObjectManifestController;

class ObjectStreamingController : public ObjectManifestController {
public:
    ObjectStreamingController() = delete;
    ObjectStreamingController(DistributionSession&);
    ObjectStreamingController(const ObjectStreamingController&) = delete;
    ObjectStreamingController(ObjectStreamingController&&) = delete;

    virtual ~ObjectStreamingController();

    ObjectStreamingController &operator=(const ObjectStreamingController&) = delete;
    ObjectStreamingController &operator=(ObjectStreamingController&&) = delete;

    std::shared_ptr<ObjectListPackager> getObjectListPackager() const;
    const std::optional<std::string> &getObjectDistributionBaseUrl() const;
    //virtual std::string nextObjectId();

    static unsigned int factoryPriority() { return 50; };

    // Subscriber virtual methods
    virtual void processEvent(Event &event, SubscriptionService &event_service);

    // Optional: virtual void subscriberRemoved(SubscriptionService &event_service);
    std::string reprString() const {
                std::ostringstream os;
                os << "ObjectStreamingController(controller =" << this << ")";
                return os.str();
    }

    void unsetObjectListPackager() {
        // Reset the shared pointer to release ownership.
        packager(nullptr);
    };

    virtual void reconfigureObjectPackager();

protected:
    virtual void setObjectPackager();
    virtual void unsetObjectPackager();

private:
    void sendToPackager(const std::string &object_id);
    //std::string generateUUID();
    //std::shared_ptr<ObjectListPackager> m_objectListPackager;
//    std::thread m_ingestSchedulingThread;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_OBJECT_STREAMING_CONTROLLER_HH_ */
