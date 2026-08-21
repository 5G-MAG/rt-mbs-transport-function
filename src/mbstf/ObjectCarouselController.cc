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
#include "SsmPort.hh"
#include "SubscriptionService.hh"
#include "utilities.hh"
#include "openapi/model/DistSessionState.h"
#include "openapi/model/Object.h"
#include "openapi/model/ProblemCause.hh"

#include "ObjectCarouselController.hh"

using reftools::mbstf::DistSessionState;
using reftools::mbstf::Object;
using fiveg_mag_reftools::ModelException;
using fiveg_mag_reftools::ProblemCause;

MBSTF_NAMESPACE_START

static void validate_distribution_session(DistributionSession &distribution_session);

ObjectCarouselController::ObjectCarouselController(DistributionSession &distribution_session)
    :ObjectManifestController(distribution_session)
{
    ogs_debug("ObjectCarouselController validating DistributionSession");
    validate_distribution_session(distribution_session);
    ogs_debug("ObjectCarouselController subscribe to ObjectStore");
    subscribeToService(*objectStore());
    ogs_debug("ObjectCarouselController active");
}

ObjectCarouselController::~ObjectCarouselController()
{
    abort();
}

void ObjectCarouselController::setObjectPackager()
{
    auto ssm_port = distributionSession().getSsmPort();
    const std::optional<std::string> &tunnel_addr = distributionSession().getTunnelAddr();
    uint32_t rate_limit = distributionSession().getRateLimit();
    in_port_t tunnel_port = distributionSession().getTunnelPortNumber();
    unsigned short mtu = get_tunnelled_path_mtu(ssm_port, tunnel_addr, tunnel_port, GET_MTU_ETHERNET_PAYLOAD) - GTP_HEADER_SIZE;
    packager(new ObjectCarouselPackager(objectStore(), *this, ssm_port, rate_limit, mtu, tunnel_addr, tunnel_port));
    auto pkgr = getObjectCarouselPackager();
    subscribeToService(*pkgr);
    startWorker();
    updateCarousel();
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

void ObjectCarouselController::objectAddOrUpdateEvent(const std::shared_ptr<ObjectStore::Object> &object)
{
    object->second.keepAfterSend(true); /* keep all objects, we'll manually remove if the carousel changes */
}

void ObjectCarouselController::sendToPackager(const std::shared_ptr<ObjectStore::Object> &object)
{
    auto packager = getObjectCarouselPackager();
    if (packager) {
        auto manifest_manager = std::dynamic_pointer_cast<ObjectManifestHandler>(manifestHandler());
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
            auto ssm_port = distributionSession().getSsmPort();
            const std::optional<std::string> &tunnel_addr = distributionSession().getTunnelAddr();
            uint32_t rate_limit = distributionSession().getRateLimit();
            in_port_t tunnel_port = distributionSession().getTunnelPortNumber();

            if (ssm_port) {
                packager->updateFluteInfo(ssm_port, rate_limit, tunnel_addr, tunnel_port);
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
                /* else (if the object is not added to the packager) */
                auto object_store = objectStore();
                if (object_store) {
                    auto &obj_store = *object_store;
                    const auto &obj_metadata = obj_store.findMetadataByURL(obj.value()->getLocator());
                    if (obj_metadata) {
                        /* if it is found in the ObjectStore, add it to the packager */
                        packager->add(ObjectCarouselPackager::PackageItem(obj_store[obj_metadata->objectId()],
                                                                      object_manifest_hndlr));
                    }
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

bool ObjectCarouselController::checkObjectActiveInManifest(const std::shared_ptr<ObjectStore::Object> &object)
{
    const auto object_manifest_hndlr = std::dynamic_pointer_cast<const ObjectManifestHandler>(manifestHandler());
    if (object_manifest_hndlr) {
        return object_manifest_hndlr->isObjectURLActive(object->second.getOriginalUrl());
    }
    return false;
}

void ObjectCarouselController::finishRequestInManifestHandler(const std::shared_ptr<ObjectStore::Object> &object)
{
    auto object_manifest_hndlr = std::dynamic_pointer_cast<ObjectManifestHandler>(manifestHandler());
    if (object_manifest_hndlr) object_manifest_hndlr->finishRequest(object->second.getOriginalUrl());
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
    ObjectController::validateDistributionSession(distribution_session);
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
