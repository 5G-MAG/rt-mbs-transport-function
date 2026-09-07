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
static bool check_if_object_added_is_manifest(const std::shared_ptr<ObjectStore::Object> &object, std::string &manifest_url);
static bool check_if_object_is_active_in_manifest(const std::shared_ptr<ObjectStore::Object> &object, const std::shared_ptr<ManifestHandler> &manifest_handler);
static void finish_request_in_manifest_handler(const std::shared_ptr<ObjectStore::Object> &object, const std::shared_ptr<ManifestHandler> &manifest_handler);

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
    abort();
}

void ObjectCollectionController::setObjectPackager()
{
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

void ObjectCollectionController::processEvent(Event &event, SubscriptionService &event_service)
{
    if (event.eventName() == ObjectStore::ObjectAddedEvent::event_name ||
        event.eventName() == ObjectStore::ObjectUpdatedEvent::event_name) {

        ObjectStore::ObjectChangedEvent &obj_added_event = dynamic_cast<ObjectStore::ObjectChangedEvent&>(event);
        std::string object_id = obj_added_event.objectId();
        ogs_debug("%s with ID: %s", event.eventName().c_str(), object_id.c_str());
        try {
            const std::shared_ptr<ObjectStore::Object> &object = (*objectStore())[object_id];
            ogs_debug("Object location: %s", object->second.getFetchedUrl().c_str());
            object->second.keepAfterSend(true); /* keep all objects; nothing here ever removes one */
            if (check_if_object_added_is_manifest(object, getManifestUrl())) {
                if (manifestHandler()) {
                    try {
                        if (!manifestHandler()->update(object)) {
                            ogs_error("Failed to update Manifest");
                            unsetObjectListPackager();
                            event.stopProcessing();
                            return;
                        }
                        startWorker();
                    } catch (std::exception &ex) {
                        ogs_error("Invalid Manifest update: %s", ex.what());
                        unsetObjectListPackager();
                        event.stopProcessing();
                        return;
                    }
                } else {
                    std::shared_ptr<ManifestHandler> manifest_handler(ManifestHandlerFactory::makeManifestHandler(object, this, distributionSession().getObjectAcquisitionMethod() == "PULL"));
                    if (!manifest_handler) {
                        // No registered handler recognises this object's media type as a
                        // manifest: the ingest source served an unexpected Content-Type, or the
                        // format is not one this build supports. The surrounding try catches only
                        // std::out_of_range, so a std::runtime_error raised here would leave the
                        // process and take down every other Distribution Session over one bad
                        // ingest response for this one session. Give up on this session's manifest
                        // the same way an update failure two branches above does.
                        ogs_error("Could not find suitable manifest handler for object %s", object_id.c_str());
                        unsetObjectListPackager();
                        event.stopProcessing();
                        return;
                    }
                    manifestHandler(std::move(manifest_handler));
                }
                populateFromManifest();
            } else if (check_if_object_is_active_in_manifest(object, manifestHandler())) {
                finish_request_in_manifest_handler(object, manifestHandler());
                sendToPackager(object);
            }
        } catch (std::out_of_range &ex) {
            ogs_error("Object %s is not in the ObjectStore", object_id.c_str());
        }
    }
    ObjectManifestController::processEvent(event, event_service);
}

void ObjectCollectionController::sendToPackager(const std::shared_ptr<ObjectStore::Object> &object)
{
    auto packager = getObjectListPackager();
    if (packager) {
        ObjectListPackager::PackageItem item(object);
        packager->add(item);
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
                sendToPackager((*objectStore())[obj_metadata->objectId()]);
            }
            /* else not yet ingested -- the scheduled pull worker will fetch it, and its own
               ObjectAddedEvent will reach processEvent() above and queue it then */
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

static bool check_if_object_added_is_manifest(const std::shared_ptr<ObjectStore::Object> &object, std::string &manifest_url)
{
    auto &metadata = object->second;
    return (metadata.getOriginalUrl() == manifest_url || metadata.getFetchedUrl() == manifest_url);
}

// dynamic_pointer_cast returns null when the manifest handler was constructed as a different
// ManifestHandler subclass (a DASH MPD giving a DASHManifestHandler, say), so the result is
// checked before use. ObjectCarouselController.cc holds an identical copy of these two functions
// and the same reasoning applies there.
static bool check_if_object_is_active_in_manifest(const std::shared_ptr<ObjectStore::Object> &object, const std::shared_ptr<ManifestHandler> &manifest_handler)
{
    const auto object_manifest_hndlr = std::dynamic_pointer_cast<const ObjectManifestHandler>(manifest_handler);
    if (!object_manifest_hndlr) {
        ogs_error("Manifest handler is not an ObjectManifestHandler (object %s); treating as not active",
                  object->second.objectId().c_str());
        return false;
    }
    return object_manifest_hndlr->isObjectURLActive(object->second.getOriginalUrl());
}

static void finish_request_in_manifest_handler(const std::shared_ptr<ObjectStore::Object> &object, const std::shared_ptr<ManifestHandler> &manifest_handler)
{
    auto object_manifest_hndlr = std::dynamic_pointer_cast<ObjectManifestHandler>(manifest_handler);
    if (!object_manifest_hndlr) {
        ogs_error("Manifest handler is not an ObjectManifestHandler (object %s); cannot finish request",
                  object->second.objectId().c_str());
        return;
    }
    object_manifest_hndlr->finishRequest(object->second.getOriginalUrl());
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
