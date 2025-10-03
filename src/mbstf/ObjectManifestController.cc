/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: ObjectManifestController class
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
#include <uuid/uuid.h>
#include <netinet/in.h>

#include "ogs-app.h"

#include "common.hh"
#include "DistributionSession.hh"
#include "Event.hh"
#include "ObjectController.hh"
#include "ObjectStore.hh"
#include "PullObjectIngester.hh"
#include "PushObjectIngester.hh"
#include "SubscriptionService.hh"
#include "utilities.hh"
#include "openapi/model/DistSessionState.h"

#include "ObjectManifestController.hh"

using reftools::mbstf::DistSessionState;

MBSTF_NAMESPACE_START

static bool validate_push_url(DistributionSession &distributionSession, const std::string &url);
static void validate_pull_acquisition_method(DistributionSession &distributionSession);
static bool validate_push_acquisition_method(DistributionSession &distributionSession);

ObjectManifestController::ObjectManifestController(DistributionSession &dist_session)
        :ObjectController(dist_session)
        ,m_manifestHandler(nullptr)
	,m_scheduledPullCancel(false)

{
    validate_pull_acquisition_method(dist_session);
    validate_push_acquisition_method(dist_session);
};


void ObjectManifestController::initPullObjectIngesters()
{
    const std::optional<std::string> &object_ingest_base_url = distributionSession().getObjectIngestBaseUrl();
    const std::optional<std::string> &object_distribution_base_url = distributionSession().objectDistributionBaseUrl();

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

                urls.emplace_back(nextObjectId(), obj_ingest_url, url_str, object_ingest_base_url, object_distribution_base_url);
            }
        }

        addPullObjectIngester(new PullObjectIngester(objectStore(), *this, urls));
    }
}


void ObjectManifestController::initPushObjectIngester()
{
    const std::string objIngestBaseUrl;

    PushObjectIngester *push_ingester = new PushObjectIngester(objectStore(), *this);

    distributionSession().setObjectIngestBaseUrl(push_ingester->getIngestServerPrefix());
    subscribeTo({"ObjectPushStart"}, *push_ingester);
    pushObjectIngester(push_ingester);
}

std::string ObjectManifestController::nextObjectId()
{
    return generateUUID();
}

std::string ObjectManifestController::generateUUID()
{
    uuid_t uuid;
    uuid_generate_random(uuid);
    char uuid_str[37];
    uuid_unparse(uuid, uuid_str);
    return std::string(uuid_str);
}

void ObjectManifestController::workerLoop(ObjectManifestController *controller)
{

    while (true) {
        {
            std::lock_guard<std::recursive_mutex> lock(controller->m_manifestHandlerMutex);
            if ( controller->m_scheduledPullCancel || controller->m_manifestHandler != nullptr) {
                break;
            }
        }
        // Avoid a tight busy-loop: yield or sleep for a short time.
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    if (controller->m_scheduledPullCancel) return;

    while (!controller->m_scheduledPullCancel) {

        std::pair<ManifestHandler::time_type, ManifestHandler::ingest_list> next_ingest_items;
        ManifestHandler::durn_type default_deadline;
        // Get the next ingest items
	try {
            std::lock_guard<std::recursive_mutex> lock(controller->m_manifestHandlerMutex);
            next_ingest_items = controller->manifestHandler()->nextIngestItems();
            default_deadline = controller->manifestHandler()->getDefaultDeadline();
	} catch ( std::domain_error &err) {
	    ogs_error("Next Ingest Item: %s", err.what());
	}

	if (next_ingest_items.second.empty()) break;

	auto fetch_time = next_ingest_items.first; // Get fetch_time using .first

	std::list<PullObjectIngester::IngestItem> urls;

        {
            std::lock_guard<std::recursive_mutex> lock(controller->m_pullObjectIngestersMutex);
            auto &ingesters = controller->getPullObjectIngesters();
            while (ingesters.size() < next_ingest_items.second.size()) {
	        controller->addPullObjectIngester(new PullObjectIngester(controller->objectStore(), *controller, urls));
            }
	}

        // Wait until the fetch_time
	{
            std::ostringstream oss;
	    oss << fetch_time ;
	    ogs_debug("Sleeping until...%s", oss.str().c_str());
	}
	std::this_thread::sleep_until(fetch_time);

        {
            std::lock_guard<std::recursive_mutex> lock(controller->m_pullObjectIngestersMutex);
            // Add the URLs to the PullObjectIngester instances
            auto &ingesters = controller->getPullObjectIngesters();
            for (auto ingester_it = ingesters.begin(); ingester_it!= ingesters.end(); ++ingester_it) {
                if (next_ingest_items.second.empty()) break;
                auto ingest_item = next_ingest_items.second.front();
                next_ingest_items.second.pop_front();  // remove the item
	        //ingest_item.deadline(std::nullopt);
                ingest_item.deadline(std::chrono::system_clock::now() + default_deadline);
                if (!(*ingester_it)->fetch(ingest_item)) {
                    ogs_debug("Failed to fetch item: %s", ingest_item.url().c_str());
                }
            }
	}
    }
}

void ObjectManifestController::startWorker()
{
    if(m_scheduledPullThread.get_id() == std::thread::id()) {
        m_scheduledPullThread = std::thread(&ObjectManifestController::workerLoop, this);
    }
}

void ObjectManifestController::processEvent(Event &event, SubscriptionService &event_service)
{
    if (event.eventName() == "ObjectPushStart") {
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
    }
    ObjectController::processEvent(event, event_service);

}

std::string &ObjectManifestController::getManifestUrl()
{
    manifestUrl();
    return m_manifestUrl;
}


void ObjectManifestController::manifestUrl()
{
    std::optional<std::string> manifest_base_url = distributionSession().getObjectIngestBaseUrl();
    std::string manifest_url;

    auto &pull_urls = distributionSession().getObjectAcquisitionPullUrls();
    if (pull_urls.has_value()) {
        for (auto &url : pull_urls.value()) {

            if (url.has_value()) {
                const std::string &url_str = url.value();
                if (manifest_base_url.has_value()) {
                    if (url_str.starts_with("https:") || url_str.starts_with("http:") || url_str.starts_with("//")) {
                        ogs_error("Invalid objectAcquisitionPullUrl when objectIngestBaseUrl is set: %s", url.value().c_str());
                        continue;
                    } else {
                        manifest_url = manifest_base_url.value();
                        if (!manifest_url.ends_with("/")) manifest_url += "/";
                        manifest_url += trim_slashes(url_str);
                    }

                }

            }
        }
    }
    auto push_url = distributionSession().getObjectAcquisitionPushId();
    if (push_url) {
        const std::string &url_str = push_url.value();
        if (manifest_base_url) {
            if (url_str.starts_with("https:") || url_str.starts_with("http:") || url_str.starts_with("//")) {
                ogs_error("Invalid absolute objAcquisitionIdPush is set: %s", url_str.c_str());
            } else {
                manifest_url = manifest_base_url.value();
                if (!manifest_url.ends_with("/")) manifest_url += "/";
                manifest_url += trim_slashes(url_str);
            }
        }
    }
    m_manifestUrl = manifest_url;
}

void ObjectManifestController::reconfigurePushObjectIngester()
{
    auto &push_obj_ingester = pushObjectIngester();
    if (push_obj_ingester) {
        if (distributionSession().getObjectAcquisitionMethod() != "PUSH") {
            /* remove push_obj_ingester on change from PUSH to PULL mode */
            pushObjectIngester(nullptr);
        }
    } else if (distributionSession().getObjectAcquisitionMethod() == "PUSH") {
        /* Add a push ingester on change from PULL to PUSH mode */
        initPushObjectIngester();
    }
}

void ObjectManifestController::reconfigurePullObjectIngesters()
{
    std::lock_guard<std::recursive_mutex> lock(this->m_pullObjectIngestersMutex);
    removeAllPullObjectIngesters();
    if (distributionSession().getObjectAcquisitionMethod() == "PULL" &&
        distributionSession().getState() != DistSessionState::VAL_INACTIVE) {
        initPullObjectIngesters();
    }
}

static void validate_pull_acquisition_method(DistributionSession &distributionSession) {
    if (distributionSession.getObjectAcquisitionMethod() == "PULL") {
        auto &pull_urls = distributionSession.getObjectAcquisitionPullUrls();
        if (pull_urls.has_value() && pull_urls->size() != 1) {
            throw std::runtime_error("objAcquisitionIdsPull must contain exactly one item when objDistributionOperatingMode is set to " + distributionSession.getObjectDistributionOperatingMode());
        }
        std::optional<std::string> object_acquisition_push_id = distributionSession.getObjectAcquisitionPushId();
        if (object_acquisition_push_id.has_value()) {

            throw std::runtime_error("objAcquisitionIdPush must not be present when objAcquisitionMethod is set to " + distributionSession.getObjectAcquisitionMethod());
        }
    }
}

static bool validate_push_acquisition_method(DistributionSession &distributionSession) {
    if (distributionSession.getObjectAcquisitionMethod() == "PUSH") {
        auto &pull_urls = distributionSession.getObjectAcquisitionPullUrls();
        if (pull_urls.has_value()) {
            throw std::runtime_error("objAcquisitionIdsPull must not be present when objAcquisitionMethod is set to " + distributionSession.getObjectAcquisitionMethod());
        } else {
            std::optional<std::string> object_acquisition_push_id = distributionSession.getObjectAcquisitionPushId();
            if (!object_acquisition_push_id.has_value()) {
                std::optional<std::string> id = "manifest";
                distributionSession.setObjectAcquisitionIdPush(id);
            }
	    return true;
        }
    }
    return false;
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

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
