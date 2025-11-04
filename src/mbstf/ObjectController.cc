/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: ObjectController class
 ******************************************************************************
 * Copyright: (C)2025 British Broadcasting Corporation
 * Author(s): David Waring <david.waring2@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include <memory>
#include <list>

#include "common.hh"
#include "App.hh"
#include "Controller.hh"
#include "DistributionSession.hh"
#include "ObjectStore.hh"
#include "ObjectPackager.hh"
#include "PullObjectIngester.hh"
#include "PushObjectIngester.hh"
#include "openapi/model/DistSessionState.h"

#include "ObjectController.hh"

using reftools::mbstf::DistSessionState;

MBSTF_NAMESPACE_START

const std::shared_ptr<PullObjectIngester> &ObjectController::addPullObjectIngester(PullObjectIngester *ingester)
{
    std::lock_guard<std::recursive_mutex> lock(m_pullObjectIngestersMutex);
    // Transfer ownership from unique_ptr to shared_ptr
    auto &listed_ingester = m_pullIngesters.emplace_back(ingester);
    subscribeTo({ObjectIngester::IngestFailedEvent::event_name}, *listed_ingester);
    return listed_ingester;
}

bool ObjectController::removePullObjectIngester(std::shared_ptr<PullObjectIngester> &pullIngester)
{
    std::lock_guard<std::recursive_mutex> lock(m_pullObjectIngestersMutex);
    auto it = std::find(m_pullIngesters.begin(), m_pullIngesters.end(), pullIngester);
    if (it != m_pullIngesters.end()) {
        m_pullIngesters.erase(it);
        return true;
    }
    return false;
}

bool ObjectController::removeAllPullObjectIngesters()
{
    std::lock_guard<std::recursive_mutex> lock(m_pullObjectIngestersMutex);
    m_pullIngesters.clear();
    return true;
}

const std::shared_ptr<PushObjectIngester> &ObjectController::pushObjectIngester(PushObjectIngester *pushIngester)
{
    m_pushIngester.reset(pushIngester);
    subscribeTo({ObjectIngester::IngestFailedEvent::event_name}, *m_pushIngester);
    return m_pushIngester;
}

void ObjectController::processEvent(Event &event, SubscriptionService &event_service)
{
    if (event.eventName() == "ObjectSendCompleted") {
	ObjectPackager::ObjectSendCompleted &objSendEvent = dynamic_cast<ObjectPackager::ObjectSendCompleted&>(event);
        std::string object_id = objSendEvent.objectId();
        ogs_info("Object [%s] sent", object_id.c_str());

	const ObjectStore::Metadata &metadata = objectStore().getMetadata(object_id);

	if(!metadata.keepAfterSend()) {

	    objectStore().deleteObject(object_id);
	} else {
            ogs_debug("Keeping object [%s] in object store after sending...", object_id.c_str());
	}
    } else if (event.eventName() == ObjectIngester::IngestFailedEvent::event_name) {
        ObjectIngester::IngestFailedEvent &ingest_failed_event = dynamic_cast<ObjectIngester::IngestFailedEvent&>(event);
        ogs_debug("Object ingest failed for %s: reason = %i", ingest_failed_event.url().c_str(), ingest_failed_event.failureType());
        m_consecutiveIngestFailures++;
        sendEventSynchronous(event); /* repeat ingest failure event to subscribers of this ObjectController */
        auto max_failures = App::self().context()->consecutiveIngestFailuresBeforeAbort;
        if (max_failures != 0 && m_consecutiveIngestFailures >= max_failures) {
            DistSessionState inactive_state;
            inactive_state = DistSessionState::VAL_INACTIVE;
            distributionSession().setState(inactive_state);
        }
    }
}

std::string ObjectController::nextObjectId()
{
    std::ostringstream oss;
    oss << m_nextId;
    m_nextId++;
    return oss.str();
}

const std::shared_ptr<ObjectPackager> &ObjectController::packager(ObjectPackager *packager)
{
    m_packager.reset(packager);
    return m_packager;
}

const std::optional<std::string> &ObjectController::getObjectDistributionBaseUrl() const {
    return distributionSession().objectDistributionBaseUrl();
}

void ObjectController::reconfigureObjectStore()
{
    auto &dist_session = distributionSession();
    m_objectStore.reconfigureMetadatas(dist_session.getObjectIngestBaseUrl(), dist_session.objectDistributionBaseUrl());
}

void ObjectController::establishInactiveInputs()
{
    m_pullIngesters.clear();
    m_packager.reset();
    if (distributionSession().getObjectAcquisitionMethod() == "PUSH" && !m_pushIngester) initPushObjectIngester();
}

void ObjectController::establishActiveInputs()
{
    if (distributionSession().getObjectAcquisitionMethod() == "PULL") initPullObjectIngesters();
}

void ObjectController::activateOutput()
{
    if (!m_packager) setObjectPackager();
}

void ObjectController::deactivateOutput()
{
    if (m_packager) unsetObjectPackager();
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
