/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: ObjectListController class
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

#include "common.hh"
#include "ControllerFactory.hh"
#include "DistributionSession.hh"
#include "Event.hh"
#include "ObjectController.hh"
#include "ObjectListPackager.hh"
#include "ObjectStore.hh"
#include "PullObjectIngester.hh"
#include "PushObjectIngester.hh"
#include "SubscriptionService.hh"
#include "utilities.hh"
#include "openapi/model/DistSessionState.h"

#include "ObjectListController.hh"

using reftools::mbstf::DistSessionState;

MBSTF_NAMESPACE_START

static int validate_distribution_session(DistributionSession &distributionSession);
static bool validate_push_url(DistributionSession &distributionSession, const std::string &url);

ObjectListController::ObjectListController(DistributionSession &distributionSession)
    :ObjectController(distributionSession)
{
    if (distributionSession.getObjectDistributionOperatingMode() != "SINGLE") {
        throw std::logic_error("Expected objDistributionOperatingMode to be set to SINGLE.");
    }

   if(!validate_distribution_session(distributionSession)) {
        throw std::runtime_error("Invalid Distribution Session");
    }

    subscribeToService(objectStore());
    subscribeTo({PullObjectIngester::ObjectPullQueueExhaustedEvent::event_name}, *this);
}

ObjectListController::~ObjectListController()
{
}

void ObjectListController::setObjectPackager() {
    std::optional<std::string> dest_ip_addr = distributionSession().getDestIpAddr();
    std::optional<std::string> tunnel_addr = distributionSession().getTunnelAddr();
    uint32_t rate_limit = distributionSession().getRateLimit();
    in_port_t port = distributionSession().getPortNumber();
    in_port_t tunnel_port = distributionSession().getTunnelPortNumber();
    //TODO: get the MTU for the dest_ip_addr or tunnel_addr
    unsigned short mtu = 1498; // 1500 - GTP overhead; to allow for downstream encapsulation to the gNodeB
    const auto &obj_list = objectStore().getObjects();
    packager(new ObjectListPackager(objectStore(), *this, dest_ip_addr, rate_limit, mtu, port, tunnel_addr, tunnel_port));
    // Send all objects that are in the ObjectStore
    for (const auto &[obj_id, object] : obj_list) {
        sendToPackager(obj_id);
    }
}

void ObjectListController::sendToPackager(const std::string &objectId)
{
    ObjectListPackager::PackageItem item(objectId);
    auto packager = getObjectListPackager();
    if (packager) {
        packager->add(item);
    }
}

void ObjectListController::unsetObjectPackager() {
    packager(nullptr);
}

std::shared_ptr<ObjectListPackager> ObjectListController::getObjectListPackager() const
{
    return std::dynamic_pointer_cast<ObjectListPackager>(packager());
}

void ObjectListController::processEvent(Event &event, SubscriptionService &event_service) {
    if (event.eventName() == "ObjectAdded") {
        ObjectStore::ObjectAddedEvent &objAddedEvent = dynamic_cast<ObjectStore::ObjectAddedEvent&>(event);
        std::string objectId = objAddedEvent.objectId();
        ogs_info("Object added with ID: %s", objectId.c_str());

        sendToPackager(objectId);
    } else if (event.eventName() == "ObjectPushStart") {
        PushObjectIngester::ObjectPushEvent &obj_push_event = dynamic_cast<PushObjectIngester::ObjectPushEvent&>(event);
        const PushObjectIngester::Request &request(obj_push_event.request());
        const std::optional<std::string> &content_type(request.contentType());
        const std::string &url(request.urlPath());
        ogs_debug("Check mime_type [%s] is ok?", content_type?content_type.value().c_str():"<none>");
        if(!validate_push_url(distributionSession(), url)) {
            const_cast<PushObjectIngester::Request&>(request).setError(400, "Bad Request");
            event.preventDefault();
        }
        // event.preventDefault() if checks fail
    } else if (event.eventName() == PullObjectIngester::ObjectPullQueueExhaustedEvent::event_name) {
        /* this is a PULL list and we've finished it, so go INACTIVE */
        try {
            dynamic_cast<ObjectListController&>(event_service);
            DistSessionState inactive_state;
            inactive_state = DistSessionState::VAL_INACTIVE;
            distributionSession().setState(inactive_state);
        } catch (std::bad_cast &ex) {
            /* event came from one of my PullObjectIngesters, so resend to ourselves to avoid deleting active PullObjectIngester */
            sendEventAsynchronous(event.newClone());
        }
        event.preventDefault();
    }
    ObjectController::processEvent(event, event_service);

    // TODO: Forward ingest and packager events for DistributionSessionSubscriptions notifications
    // else if (event.eventName() == "ObjectIngestFailed") { emitDataIngestFailedEvent(); }
    // else if (event.eventName() == "FluteSessionStarted") { emitSessionActivatedEvent(); }
    // else if (event.eventName() == "FluteSessionFailed") { emitServiceManagementFailureEvent(); }
    // else if (event.eventName() == "ObjectPushListening") { emitDataIngestSessionEstablished(); }
    // else if (event.eventName() == "ObjectPushClosed") { emitDataIngestSessionTerminated(); }
}

std::string ObjectListController::generateUUID() {
    uuid_t uuid;
    uuid_generate_random(uuid);
    char uuid_str[37];
    uuid_unparse(uuid, uuid_str);
    return std::string(uuid_str);
}

void ObjectListController::initPullObjectIngesters()
{
    std::optional<std::string> object_ingest_base_url = distributionSession().getObjectIngestBaseUrl();
    std::optional<std::string> object_distribution_base_url = distributionSession().objectDistributionBaseUrl();

    auto &pull_urls = distributionSession().getObjectAcquisitionPullUrls();
    if (pull_urls.has_value()) {
        std::list<PullObjectIngester::IngestItem> urls;

        for (auto &url : pull_urls.value()) {
            std::string obj_ingest_url;

            if (url.has_value()) {
                const std::string &url_str = url.value();
                if (object_ingest_base_url.has_value()) {
                    if (url_str.starts_with("https:") || url_str.starts_with("http:") || url_str.starts_with("//")) {
                        ogs_error("Invalid objectAcquisitionPullUrl when objectIngestBaseUrl is set: %s", url.value().c_str());
                        continue;
                    } else {
                        obj_ingest_url = object_ingest_base_url.value();
                        if (!obj_ingest_url.ends_with("/")) obj_ingest_url += "/";
                        obj_ingest_url += trim_slashes(url_str);
                    }

                }

                urls.emplace_back(std::move(PullObjectIngester::IngestItem(nextObjectId(), obj_ingest_url, url_str,
                                                                           object_ingest_base_url, object_distribution_base_url)));
            }
        }

        std::shared_ptr<PullObjectIngester> pull_obj_ingest(new PullObjectIngester(objectStore(), *this, urls));
        subscribeTo({PullObjectIngester::ObjectPullQueueExhaustedEvent::event_name}, *pull_obj_ingest);
        addPullObjectIngester(pull_obj_ingest);
    }
}


void ObjectListController::initPushObjectIngester()
{
    const std::string objIngestBaseUrl;

    PushObjectIngester *pushIngester = new PushObjectIngester(objectStore(), *this);

    distributionSession().setObjectIngestBaseUrl(pushIngester->getIngestServerPrefix());
    subscribeTo({"ObjectPushStart"}, *pushIngester);
    pushObjectIngester(pushIngester);
}

std::string ObjectListController::nextObjectId()
{
    return generateUUID();
}

void ObjectListController::reconfigurePushObjectIngester()
{
    auto &push_obj_ingester = pushObjectIngester();
    if (push_obj_ingester) {
        if (distributionSession().getObjectAcquisitionMethod() != "PUSH") {
            /* remove push_obj_ingester */
            pushObjectIngester(nullptr);
        } /* else the existing PushObjectIngester will just pick up the changes from the DistSession object */
    } else if (distributionSession().getObjectAcquisitionMethod() == "PUSH") {
        /* change from PULL to PUSH, so create PushObjectIngester */
        initPushObjectIngester();
    }
}

void ObjectListController::reconfigurePullObjectIngesters()
{
    removeAllPullObjectIngesters();
    /* create the ingesters if DistSession is not INACTIVE */
    if (distributionSession().getObjectAcquisitionMethod() == "PULL" &&
        distributionSession().getState() != DistSessionState::VAL_INACTIVE) {
        initPullObjectIngesters();
    }
}

void ObjectListController::reconfigureObjectPackager()
{
    /* only set the packager in the ACTIVE state */
    if (distributionSession().getState() == DistSessionState::VAL_ACTIVE) {
        setObjectPackager();
    }
}

namespace {
static const struct init { init() {ControllerFactory::registerController(new ControllerConstructor<ObjectListController>);};} g_init;
}

static bool validate_push_url(DistributionSession &distributionSession, const std::string &url)
{
    std::optional<std::string> object_acquisition_push_id = distributionSession.getObjectAcquisitionPushId();
    if (object_acquisition_push_id.has_value()) {
	std::string push_id = object_acquisition_push_id.value();
	std::string url_path(url);
	if ((push_id.front() == '/' && url_path.front() != '/')) {
	    url_path = '/' + url_path;
	} else if ((url_path.front() == '/' && push_id.front() != '/')) {
	    push_id = '/' + push_id;
	}
	if(push_id == url_path) {
	    return true;
	} else {
	    return false;
	}
    }

    return true;
}

static int validate_distribution_session(DistributionSession &distributionSession)
{
    if (distributionSession.getObjectAcquisitionMethod() == "PUSH" && distributionSession.getObjectDistributionOperatingMode() == "SINGLE") {
        std::optional<std::string> object_acquisition_push_id = distributionSession.getObjectAcquisitionPushId();
        if (object_acquisition_push_id.has_value()) {
            return 0;
        }
    }

    return 1;
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
