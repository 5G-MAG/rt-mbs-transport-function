#ifndef _MBS_TF_OBJECT_CAROUSEL_CONTROLLER_HH_
#define _MBS_TF_OBJECT_CAROUSEL_CONTROLLER_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Object Carousel Controller class
 ******************************************************************************
 * Copyright: (C)2026 British Broadcasting Corporation
 * Author(s): David Waring <david.waring2@bbc.co.uk>
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
class ObjectCarouselPackager;
class PullObjectIngester;
class SubscriptionService;
class ObjectManifestController;

class ObjectCarouselController : public ObjectManifestController {
public:
    ObjectCarouselController() = delete;
    ObjectCarouselController(DistributionSession&);
    ObjectCarouselController(const ObjectCarouselController&) = delete;
    ObjectCarouselController(ObjectCarouselController&&) = delete;

    virtual ~ObjectCarouselController();

    ObjectCarouselController &operator=(const ObjectCarouselController&) = delete;
    ObjectCarouselController &operator=(ObjectCarouselController&&) = delete;

    std::shared_ptr<ObjectCarouselPackager> getObjectCarouselPackager() const;
    const std::optional<std::string> &getObjectDistributionBaseUrl() const;
    //virtual std::string nextObjectId();

    static unsigned int factoryPriority() { return 50; };

    // Subscriber virtual methods
    virtual void processEvent(Event &event, SubscriptionService &event_service);

    // Optional: virtual void subscriberRemoved(SubscriptionService &event_service);
    std::string reprString() const {
                std::ostringstream os;
                os << "ObjectCarouselController(controller =" << this << ")";
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
    virtual void activateObjectPackager();
    virtual void deactivateObjectPackager();

private:
    void sendToPackager(const std::string &object_id);
    void updateCarousel();
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_OBJECT_CAROUSEL_CONTROLLER_HH_ */
