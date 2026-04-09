/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: ObjectStreamingController class
 ******************************************************************************
 * Copyright: (C)2025 British Broadcasting Corporation
 * Author(s): Dev Audsin <dev.audsin@bbc.co.uk>
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
#include "ObjectStore.hh"
#include "PullObjectIngester.hh"
#include "PushObjectIngester.hh"
#include "SubscriptionService.hh"
#include "ObjectListPackager.hh"
#include "utilities.hh"
#include "openapi/model/DistSessionState.h"
#include "openapi/model/ProblemCause.hh"

#include "ObjectStreamingController.hh"

using reftools::mbstf::DistSessionState;
using fiveg_mag_reftools::ModelException;
using fiveg_mag_reftools::ProblemCause;

MBSTF_NAMESPACE_START

static void validate_distribution_session(DistributionSession &distributionSession);
static bool check_if_object_added_is_manifest(const std::string &object_id, ObjectStore &object_store,
                                              const std::string &manifest_url);

ObjectStreamingController::ObjectStreamingController(DistributionSession &distributionSession)
    :ObjectManifestController(distributionSession)
{
    validate_distribution_session(distributionSession);
    subscribeToService(objectStore());
    //setObjectListPackager();
    //startWorker();
}

ObjectStreamingController::~ObjectStreamingController()
{
    abort();
}

void ObjectStreamingController::setObjectPackager()
{
    const std::optional<std::string> &dest_ip_addr = distributionSession().getDestIpAddr();
    const std::optional<std::string> &tunnel_addr = distributionSession().getTunnelAddr();
    uint32_t rate_limit = distributionSession().getRateLimit();
    in_port_t port = distributionSession().getPortNumber();
    in_port_t tunnel_port = distributionSession().getTunnelPortNumber();
    unsigned short mtu = get_tunnelled_path_mtu(dest_ip_addr, port, tunnel_addr, tunnel_port) - GTP_HEADER_SIZE;
    packager(new ObjectListPackager(objectStore(), *this, dest_ip_addr, rate_limit, mtu, port, tunnel_addr, tunnel_port));
    auto pkgr = getObjectListPackager();
    subscribeToService(*pkgr);
    startWorker();
    const auto &obj_list = objectStore().getObjects();
    for (const auto &[obj_id, object] : obj_list) {
        sendToPackager(object);
    }
}

void ObjectStreamingController::unsetObjectPackager()
{
    packager(nullptr);
}

void ObjectStreamingController::activateObjectPackager() {
    packager()->activate();
    startWorker();
}

void ObjectStreamingController::deactivateObjectPackager() {
    if (packager()->deactivate()) {
        distributionSession().haveEmptyQueue();
    }
}

std::shared_ptr<ObjectListPackager> ObjectStreamingController::getObjectListPackager() const
{
    return std::dynamic_pointer_cast<ObjectListPackager>(packager());
}

void ObjectStreamingController::processEvent(Event &event, SubscriptionService &event_service)
{
    if (event.eventName() == ObjectStore::ObjectAddedEvent::event_name ||
        event.eventName() == ObjectStore::ObjectUpdatedEvent::event_name) {
        ObjectStore::ObjectChangedEvent &obj_changed_event = dynamic_cast<ObjectStore::ObjectChangedEvent&>(event);
        const std::string &object_id = obj_changed_event.objectId();
        ogs_info("%s with ID: %s", event.eventName().c_str(), object_id.c_str());
        const std::shared_ptr<ObjectStore::Object> &object = objectStore()[object_id];
        if(check_if_object_added_is_manifest(object_id, objectStore(), getManifestUrl())) {
            if(manifestHandler()) {
                try {
                    if(!manifestHandler()->update(object)) {
                        ogs_error("Failed to update Manifest");
                        unsetObjectListPackager();
                        event.stopProcessing();
                        return;
                    }
                    startWorker();
                    sendToPackager(object);
                } catch (std::exception &ex) {
                    ogs_error("Invalid Manifest update: %s", ex.what());
                    unsetObjectListPackager();
                    event.stopProcessing();
                    return;
                }

            } else {
                std::unique_ptr<ManifestHandler> manifest_handler(ManifestHandlerFactory::makeManifestHandler(object, this, distributionSession().getObjectAcquisitionMethod() == "PULL"));
                manifestHandler(std::move(manifest_handler));
                sendToPackager(object);
            }
        } else {
            sendToPackager(object);
        }
    }
    ObjectManifestController::processEvent(event, event_service);
}

void ObjectStreamingController::sendToPackager(const std::shared_ptr<ObjectStore::Object> &object)
{
    auto packager = getObjectListPackager();
    if (packager) {
        ObjectListPackager::PackageItem item(object);
        packager->add(item);
    }
}

const std::optional<std::string> &ObjectStreamingController::getObjectDistributionBaseUrl() const {
    return distributionSession().objectDistributionBaseUrl();
}

void ObjectStreamingController::reconfigureObjectPackager()
{
    if (distributionSession().getState() == DistSessionState::VAL_ACTIVE) {
        auto packager = getObjectListPackager();
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

namespace {
static const struct init {
    init() {
        ControllerFactory::registerController(new ControllerConstructor<ObjectStreamingController>);
    };
} g_init;
}

static void validate_distribution_session(DistributionSession &distribution_session)
{
    if (distribution_session.getObjectDistributionOperatingMode() != "STREAMING") {
        throw std::logic_error("Expected objDistributionOperatingMode to be set to STREAMING.");
    }
    ObjectController::validateDistributionSession(distribution_session);
}

static bool check_if_object_added_is_manifest(const std::string &object_id, ObjectStore &object_store,
                                              const std::string &manifest_url) {
    ObjectStore::Metadata &metadata = object_store.getMetadata(object_id);
    if(metadata.getOriginalUrl() == manifest_url || metadata.getFetchedUrl() == manifest_url) {
        metadata.keepAfterSend(true);
        return true;
    }
    return false;

}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
