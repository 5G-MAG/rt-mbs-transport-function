#ifndef _MBS_TF_OBJECT_COLLECTION_CONTROLLER_HH_
#define _MBS_TF_OBJECT_COLLECTION_CONTROLLER_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Object Collection Controller class
 ******************************************************************************
 * Copyright: (C)2026 British Broadcasting Corporation
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
#include "ObjectStore.hh"

MBSTF_NAMESPACE_START

class DistributionSession;
class Event;
class ObjectListPackager;
class PullObjectIngester;
class SubscriptionService;
class ObjectManifestController;

// TS 26.517 V18.6.0 cl.6.2.3.3: "Object collection operating mode (OBJECT_COLLECTION) refers to
// the case in which multiple objects are distributed via the Object Distribution Method. The list
// of objects to be distributed is described by an object manifest document as specified in clause
// 6.1.2. The objects listed in the manifest are distributed only once." -- the manifest format and
// ingestion mechanics are the same as OBJECT_CAROUSEL (both use TS26517_MBSObjectManifest.yaml, and
// ObjectManifestController's shared machinery already only re-fetches items the manifest itself
// schedules; a manifest with no repetition/check-interval, as this mode's own manifest fields are
// documented to have "ignored" for it, is simply fetched once). What differs from Carousel is the
// packager: Carousel repeats delivery of each object indefinitely (ObjectCarouselPackager); this
// mode delivers each object once, matching ObjectListPackager's own model, which O5's own fix
// already described as covering "the single, collection and streaming modes".
class ObjectCollectionController : public ObjectManifestController {
public:
    ObjectCollectionController() = delete;
    ObjectCollectionController(DistributionSession&);
    ObjectCollectionController(const ObjectCollectionController&) = delete;
    ObjectCollectionController(ObjectCollectionController&&) = delete;

    virtual ~ObjectCollectionController();

    ObjectCollectionController &operator=(const ObjectCollectionController&) = delete;
    ObjectCollectionController &operator=(ObjectCollectionController&&) = delete;

    std::shared_ptr<ObjectListPackager> getObjectListPackager() const;
    const std::optional<std::string> &getObjectDistributionBaseUrl() const;

    static unsigned int factoryPriority() { return 50; };

    // Subscriber virtual methods
    virtual void processEvent(Event &event, SubscriptionService &event_service);

    std::string reprString() const {
                std::ostringstream os;
                os << "ObjectCollectionController(controller =" << this << ")";
                return os.str();
    }

    void unsetObjectListPackager() {
        packager(nullptr);
    };

    virtual void reconfigureObjectPackager();

protected:
    virtual void setObjectPackager();
    virtual void unsetObjectPackager();
    virtual void activateObjectPackager();
    virtual void deactivateObjectPackager();

private:
    void sendToPackager(const std::shared_ptr<ObjectStore::Object> &object);
    // Queues every object the manifest currently lists that has already been ingested. Unlike
    // Carousel's updateCarousel(), this never removes anything: the manifest is fetched once (per
    // the clause above), not periodically re-checked for changes, so there is nothing to diff
    // against on a later pass.
    void populateFromManifest();
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_OBJECT_COLLECTION_CONTROLLER_HH_ */
