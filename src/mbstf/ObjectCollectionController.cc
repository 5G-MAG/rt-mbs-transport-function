/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: ObjectCollectionController class
 ******************************************************************************
 * Copyright: (C)2026 British Broadcasting Corporation
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include <exception>
#include <iostream>
#include <list>
#include <memory>
#include <optional>
#include <string>

#include <netinet/in.h>

#include <uuid/uuid.h>

#include "ogs-app.h"
#include "ogs-sbi.h" // include before "common.hh" to ensure correct logging domain

#include "common.hh"
#include "ControllerFactory.hh"
#include "DistributionSession.hh"
#include "Event.hh"
#include "ManifestHandlerFactory.hh"
#include "ObjectController.hh"
#include "ObjectListPackager.hh"
#include "ObjectManifestHandler.hh"
#include "ObjectStore.hh"
#include "PullObjectIngester.hh"
#include "PushObjectIngester.hh"
#include "SsmPort.hh"
#include "SubscriptionService.hh"
#include "utilities.hh"
#include "openapi/model/DistSessionState.h"
#include "openapi/model/Object.h"
#include "openapi/model/ProblemCause.hh"

#include "ObjectCollectionController.hh"

using reftools::mbstf::DistSessionState;
using reftools::mbstf::Object;
using fiveg_mag_reftools::ModelException;
using fiveg_mag_reftools::ProblemCause;

MBSTF_NAMESPACE_START

static void validate_distribution_session(DistributionSession &distribution_session);

ObjectCollectionController::ObjectCollectionController(DistributionSession &distribution_session)
    :ObjectManifestController(distribution_session)
{
    ogs_debug("ObjectCollectionController validating DistributionSession");
    validate_distribution_session(distribution_session);
    ogs_debug("ObjectCollectionController subscribe to ObjectStore");
    subscribeToService(*objectStore());
    ogs_debug("ObjectCollectionController active");
}

ObjectCollectionController::~ObjectCollectionController()
{
    /* Dropped before anything else: this object is still subscribed to the object store, and an
       event delivered once the derived part is gone reaches ObjectManifestController::processEvent
       through a vtable that no longer has sendToPackager(), which ends the process with "pure
       virtual method called". ~Subscriber() unsubscribes too, but it runs after every derived
       destructor, which is exactly too late. */
    /* Stopped before anything else: the ingest workers this controller owns are held by its
       ObjectController base, so destruction alone stops them last, after every derived destructor
       has run. abort() below joins a scheduled pull that can take tens of seconds, and the workers
       keep ingesting throughout, using objects the teardown is already dismantling. */
    abortIngest();
    unsubscribeFromAll();
    abort();
}

void ObjectCollectionController::setObjectPackager()
{
    /* A new packager has been sent nothing yet. */
    m_queuedObjects.clear();
    auto ssm_port = distributionSession().getSsmPort();
    const std::optional<std::string> &tunnel_addr = distributionSession().getTunnelAddr();
    uint32_t rate_limit = distributionSession().getRateLimit();
    in_port_t tunnel_port = distributionSession().getTunnelPortNumber();
    bool mtu_via_loopback = false;
    /* Sequenced, not nested: the order arguments are evaluated in is unspecified, so reading
       mtu_via_loopback in the same call that fills it would read it before it is set. */
    const int discovered_mtu = get_tunnelled_path_mtu(ssm_port, tunnel_addr, tunnel_port,
                                                     GET_MTU_ETHERNET_PAYLOAD, &mtu_via_loopback);
    unsigned short mtu = flute_path_mtu(discovered_mtu, mtu_via_loopback) - GTP_HEADER_SIZE;
    auto fec_information = distributionSession().getFecInformation();
    packager(new ObjectListPackager(objectStore(), *this, ssm_port, rate_limit, mtu, tunnel_addr, tunnel_port, fec_information));
    auto pkgr = getObjectListPackager();
    subscribeToService(*pkgr);
    startWorker();
    // Catch up on anything the manifest already lists, in case it (and some of its objects) were
    // already ingested before the packager existed -- mirrors ObjectCarouselController's own
    // updateCarousel() call here, without the diff/removal half that mode needs and this one does
    // not (see populateFromManifest()'s own comment).
    populateFromManifest();
}

void ObjectCollectionController::unsetObjectPackager()
{
    packager(nullptr);
}

void ObjectCollectionController::activateObjectPackager() {
    packager()->activate();
    startWorker();
}

void ObjectCollectionController::deactivateObjectPackager() {
    if (packager()->deactivate()) {
        distributionSession().haveEmptyQueue();
    }
}

std::shared_ptr<ObjectListPackager> ObjectCollectionController::getObjectListPackager() const
{
    return std::dynamic_pointer_cast<ObjectListPackager>(packager());
}

void ObjectCollectionController::objectAddOrUpdateEvent(const std::shared_ptr<ObjectStore::Object> &object)
{
    object->second.keepAfterSend(true); /* keep all objects; nothing here ever removes one */
}

void ObjectCollectionController::manifestUpdated()
{
    populateFromManifest();
}

void ObjectCollectionController::manifestHandlerCreated()
{
    populateFromManifest();
}

bool ObjectCollectionController::checkObjectActiveInManifest(const std::shared_ptr<ObjectStore::Object> &object)
{
    const auto object_manifest_hndlr = std::dynamic_pointer_cast<const ObjectManifestHandler>(manifestHandler());
    if (!object_manifest_hndlr) {
        ogs_error("Manifest handler is not an ObjectManifestHandler (object %s); treating as not active",
                  object->second.objectId().c_str());
        return false;
    }
    return object_manifest_hndlr->isObjectURLActive(object->second.getOriginalUrl());
}

void ObjectCollectionController::finishRequestInManifestHandler(const std::shared_ptr<ObjectStore::Object> &object)
{
    auto object_manifest_hndlr = std::dynamic_pointer_cast<ObjectManifestHandler>(manifestHandler());
    if (!object_manifest_hndlr) {
        ogs_error("Manifest handler is not an ObjectManifestHandler (object %s); cannot finish request",
                  object->second.objectId().c_str());
        return;
    }
    object_manifest_hndlr->finishRequest(object->second.getOriginalUrl());
}

void ObjectCollectionController::sendToPackager(const std::shared_ptr<ObjectStore::Object> &object)
{
    auto packager = getObjectListPackager();
    if (packager) {
        ObjectListPackager::PackageItem item(object);
        if (packager->add(item)) m_queuedObjects.insert(object->second.objectId());
    }
}

const std::optional<std::string> &ObjectCollectionController::getObjectDistributionBaseUrl() const {
    return distributionSession().objectDistributionBaseUrl();
}

void ObjectCollectionController::reconfigureObjectPackager()
{
    if (distributionSession().getState() == DistSessionState::VAL_ACTIVE) {
        auto packager = getObjectListPackager();
        if (packager) {
            auto ssm_port = distributionSession().getSsmPort();
            const std::optional<std::string> &tunnel_addr = distributionSession().getTunnelAddr();
            uint32_t rate_limit = distributionSession().getRateLimit();
            in_port_t tunnel_port = distributionSession().getTunnelPortNumber();

            if (ssm_port) {
                packager->updateFluteInfo(ssm_port, rate_limit, tunnel_addr, tunnel_port);
            }
        } else {
            setObjectPackager();
        }
    }
}

void ObjectCollectionController::populateFromManifest()
{
    auto object_manifest_hndlr = std::dynamic_pointer_cast<const ObjectManifestHandler>(manifestHandler());
    if (!object_manifest_hndlr) return;
    const auto &manifest_objects = object_manifest_hndlr->getObjects();

    const auto &packager = getObjectListPackager();
    if (!packager) return;

    for (const auto &obj : manifest_objects) {
        if (obj && obj.value()) {
            const auto obj_metadata = objectStore()->findMetadataByURL(obj.value()->getLocator());
            if (obj_metadata) {
                if (m_queuedObjects.contains(obj_metadata->objectId())) continue;
                sendToPackager((*objectStore())[obj_metadata->objectId()]);
            }
            /* else not yet ingested -- the scheduled pull worker will fetch it, and its own
               ObjectAddedEvent will reach ObjectManifestController::processEvent() and queue it then */
        }
    }
}

namespace {
static const struct init {
    init() {
        ControllerFactory::registerController(new ControllerConstructor<ObjectCollectionController>);
    };
} g_init;
}

static void validate_distribution_session(DistributionSession &distribution_session)
{
    if (distribution_session.getObjectDistributionOperatingMode() != "COLLECTION") {
        throw std::logic_error("Expected objDistributionOperatingMode to be set to COLLECTION.");
    }
    ObjectController::validateDistributionSession(distribution_session);
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
