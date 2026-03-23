/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: ObjectCarouselController class
 ******************************************************************************
 * Copyright: (C)2026 British Broadcasting Corporation
 * Author(s): David Waring <david.waring2@bbc.co.uk>
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
#include "ObjectCarouselPackager.hh"
#include "ObjectController.hh"
#include "ObjectManifestHandler.hh"
#include "ObjectStore.hh"
#include "PullObjectIngester.hh"
#include "PushObjectIngester.hh"
#include "SubscriptionService.hh"
#include "utilities.hh"
#include "openapi/model/DistSessionState.h"
#include "openapi/model/Object.h"

#include "ObjectCarouselController.hh"

using reftools::mbstf::DistSessionState;
using reftools::mbstf::Object;

MBSTF_NAMESPACE_START

static void validate_distribution_session(DistributionSession &distribution_session);
static bool check_if_object_added_is_manifest(const ObjectStore::Object &object, std::string &manifest_url);
static bool check_if_object_is_active_in_manifest(const ObjectStore::Object &object, const std::shared_ptr<ManifestHandler> &manifest_handler);
static void finish_request_in_manifest_handler(const ObjectStore::Object &object, const std::shared_ptr<ManifestHandler> &manifest_handler);

ObjectCarouselController::ObjectCarouselController(DistributionSession &distribution_session)
    :ObjectManifestController(distribution_session)
{
    ogs_debug("ObjectCarouselController validating DistributionSession");
    validate_distribution_session(distribution_session);
    ogs_debug("ObjectCarouselController subscribe to ObjectStore");
    subscribeToService(objectStore());
    ogs_debug("ObjectCarouselController active");
}

ObjectCarouselController::~ObjectCarouselController()
{
    abort();
}

void ObjectCarouselController::setObjectPackager()
{
    const std::optional<std::string> &dest_ip_addr = distributionSession().getDestIpAddr();
    const std::optional<std::string> &tunnel_addr = distributionSession().getTunnelAddr();
    uint32_t rate_limit = distributionSession().getRateLimit();
    in_port_t port = distributionSession().getPortNumber();
    in_port_t tunnel_port = distributionSession().getTunnelPortNumber();
    unsigned short mtu = get_tunnelled_path_mtu(dest_ip_addr, port, tunnel_addr, tunnel_port) - GTP_HEADER_SIZE;
    packager(new ObjectCarouselPackager(objectStore(), *this, dest_ip_addr, rate_limit, mtu, port, tunnel_addr, tunnel_port));
    auto pkgr = getObjectCarouselPackager();
    subscribeToService(*pkgr);
    startWorker();
    updateCarousel();
}

void ObjectCarouselController::unsetObjectPackager()
{
    packager(nullptr);
}

void ObjectCarouselController::activateObjectPackager() {
    packager()->activate();
    startWorker();
}

void ObjectCarouselController::deactivateObjectPackager() {
    if (packager()->deactivate()) {
        distributionSession().haveEmptyQueue();
    }
}

std::shared_ptr<ObjectCarouselPackager> ObjectCarouselController::getObjectCarouselPackager() const
{
    return std::dynamic_pointer_cast<ObjectCarouselPackager>(packager());
}

void ObjectCarouselController::processEvent(Event &event, SubscriptionService &event_service)
{
    if (event.eventName() == "ObjectAdded") {
        ObjectStore::ObjectAddedEvent &obj_added_event = dynamic_cast<ObjectStore::ObjectAddedEvent&>(event);
        std::string object_id = obj_added_event.objectId();
        ogs_info("Object added with ID: %s", object_id.c_str());
        ObjectStore::Object &object = objectStore()[object_id];
        ogs_info("Object arrived from: %s", object.second.getFetchedUrl().c_str());
        object.second.keepAfterSend(true); /* keep all objects, we'll manually remove if the carousel changes */
	if(check_if_object_added_is_manifest(object, getManifestUrl())) {
	    if(manifestHandler()) {
	        try {
	            if(!manifestHandler()->update(object)) {
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
                    throw std::runtime_error("Could not find suitable manifest handler");
                }
                manifestHandler(std::move(manifest_handler));
            }
	} else if (check_if_object_is_active_in_manifest(object, manifestHandler())) {
            finish_request_in_manifest_handler(object, manifestHandler());
            sendToPackager(object_id);
        }
    }
    ObjectManifestController::processEvent(event, event_service);
}

void ObjectCarouselController::sendToPackager(const std::string &object_id)
{
    auto packager = getObjectCarouselPackager();
    if (packager) {
        auto manifest_manager = std::dynamic_pointer_cast<ObjectManifestHandler>(manifestHandler());
        auto &object = objectStore()[object_id];
        ObjectCarouselPackager::PackageItem item(object, manifest_manager);
        packager->add(item);
    }
}

const std::optional<std::string> &ObjectCarouselController::getObjectDistributionBaseUrl() const {
    return distributionSession().objectDistributionBaseUrl();
}

void ObjectCarouselController::reconfigureObjectPackager()
{
    if (distributionSession().getState() == DistSessionState::VAL_ACTIVE) {
        auto packager = getObjectCarouselPackager();
        if (packager) {
            const std::optional<std::string> &dest_ip_addr = distributionSession().getDestIpAddr();
            const std::optional<std::string> &tunnel_addr = distributionSession().getTunnelAddr();
            uint32_t rate_limit = distributionSession().getRateLimit();
            in_port_t port = distributionSession().getPortNumber();
            in_port_t tunnel_port = distributionSession().getTunnelPortNumber();

            if (dest_ip_addr) {
                packager->updateFluteInfo(dest_ip_addr.value(), port, rate_limit, tunnel_addr, tunnel_port);
            }
        }
    }
}

void ObjectCarouselController::updateCarousel()
{
    /* get the list of current carousel objects from manifest handler */
    auto object_manifest_hndlr = std::dynamic_pointer_cast<const ObjectManifestHandler>(manifestHandler());
    if (!object_manifest_hndlr) return;
    const auto &manifest_objects = object_manifest_hndlr->getObjects();

    /* get a local copy of the list of objects currently in the packager */
    const auto &packager = getObjectCarouselPackager();
    auto packager_items = packager->getPackageItems();

    /* for each object from the manifest list */
    for (const auto &obj : manifest_objects) {
        if (obj && obj.value()) {
            /* if the object is already added to the packager */
            bool found = false;
            for (auto it = packager_items.begin(); it != packager_items.end(); it++) {
                const auto &pkg_item = *it;
                if (pkg_item == obj.value()) {
                    /* remove from local packager objects list */
                    packager_items.erase(it);
                    found = true;
                    break;
                }
            }
            if (!found) {
                /* else (if the object is not added to the packager */
                const auto &obj_metadata = objectStore().findMetadataByURL(obj.value()->getLocator());
                if (obj_metadata) {
                    /* if it is found in the ObjectStore, add it to the packager */
                    packager->add(ObjectCarouselPackager::PackageItem(objectStore()[obj_metadata->objectId()],
                                                                      object_manifest_hndlr));
                }
            }
        }
    }

    /* for each object left in the packager list */
    for (const auto &pkg_item : packager_items) {
        /* this object is no longer in the carousel, so remove it */
        packager->remove(pkg_item);
    }
}

namespace {
static const struct init {
    init() {
        ControllerFactory::registerController(new ControllerConstructor<ObjectCarouselController>);
    };
} g_init;
}

static void validate_distribution_session(DistributionSession &distribution_session)
{
    if (distribution_session.getObjectDistributionOperatingMode() != "CAROUSEL") {
        throw std::logic_error("Expected objDistributionOperatingMode to be set to CAROUSEL.");
    }
}

static bool check_if_object_added_is_manifest(const ObjectStore::Object &object, std::string &manifest_url)
{
    return (object.second.getOriginalUrl() == manifest_url || object.second.getFetchedUrl() == manifest_url);
}

static bool check_if_object_is_active_in_manifest(const ObjectStore::Object &object, const std::shared_ptr<ManifestHandler> &manifest_handler)
{
    const auto object_manifest_hndlr = std::dynamic_pointer_cast<const ObjectManifestHandler>(manifest_handler);
    return object_manifest_hndlr->isObjectURLActive(object.second.getOriginalUrl());
}

static void finish_request_in_manifest_handler(const ObjectStore::Object &object, const std::shared_ptr<ManifestHandler> &manifest_handler)
{
    auto object_manifest_hndlr = std::dynamic_pointer_cast<ObjectManifestHandler>(manifest_handler);
    object_manifest_hndlr->finishRequest(object.second.getOriginalUrl());
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
