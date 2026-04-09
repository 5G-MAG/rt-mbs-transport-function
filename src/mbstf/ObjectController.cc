/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: ObjectController class
 ******************************************************************************
 * Copyright: (C)2025-2026 British Broadcasting Corporation
 * Author(s): David Waring <david.waring2@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include <memory>
#include <list>

#include "ogs-sbi.h" // include before "common.hh" to ensure correct logging domain

#include "common.hh"
#include "App.hh"
#include "Controller.hh"
#include "DistributionSession.hh"
#include "ObjectStore.hh"
#include "ObjectPackager.hh"
#include "PullObjectIngester.hh"
#include "PushObjectIngester.hh"
#include "openapi/model/CreateReqData.h"
#include "openapi/model/DistSessionState.h"

#include "ObjectController.hh"

using reftools::mbstf::DistSessionState;
using fiveg_mag_reftools::ModelException;
using fiveg_mag_reftools::ProblemCause;

MBSTF_NAMESPACE_START

const std::shared_ptr<PullObjectIngester> &ObjectController::addPullObjectIngester(
                                                                    const std::shared_ptr<PullObjectIngester> &pull_obj_ingester)
{
    std::lock_guard<std::recursive_mutex> lock(m_pullObjectIngestersMutex);
    auto &listed_ingester = m_pullIngesters.emplace_back(pull_obj_ingester);
    subscribeTo({ObjectIngester::IngestFailedEvent::event_name}, *listed_ingester);
    return listed_ingester;
}

const std::shared_ptr<PullObjectIngester> &ObjectController::addPullObjectIngester(PullObjectIngester *ingester)
{
    return addPullObjectIngester(std::shared_ptr<PullObjectIngester>(ingester));
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

        if (objSendEvent.queueEmpty()) {
            distributionSession().haveEmptyQueue();
        }
    } else if (event.eventName() == ObjectIngester::IngestFailedEvent::event_name) {
        ObjectIngester::IngestFailedEvent &ingest_failed_event = dynamic_cast<ObjectIngester::IngestFailedEvent&>(event);
        ogs_debug("Object ingest failed for %s: reason = %i", ingest_failed_event.url().c_str(), ingest_failed_event.failureType());
        m_consecutiveIngestFailures++;
        sendEventSynchronous(event); /* repeat ingest failure event to subscribers of this ObjectController */
        auto max_failures = App::self().context()->consecutiveIngestFailuresBeforeDeactivate;
        if (max_failures != 0 && m_consecutiveIngestFailures >= max_failures) {
            DistSessionState inactive_state;
            inactive_state = DistSessionState::VAL_INACTIVE;
            distributionSession().setState(inactive_state);
        }
    } else if (event.eventName() == ObjectPackager::PackagingFailedEvent::event_name) {
        ObjectPackager::PackagingFailedEvent &packaging_failed_event = dynamic_cast<ObjectPackager::PackagingFailedEvent&>(event);
        ogs_debug("Object packaging failed: reason = (%i) %s", packaging_failed_event.failureType(), packaging_failed_event.reason().c_str());
        sendEventSynchronous(event); /* repeat packaging failure event to subscribers of this ObjectController */
        DistSessionState inactive_state;
        inactive_state = DistSessionState::VAL_INACTIVE;
        distributionSession().setState(inactive_state);
    } else if (event.eventName() == ObjectStore::ObjectAddedEvent::event_name ||
               event.eventName() == ObjectStore::ObjectUpdatedEvent::event_name) {
        /* object successfully added/updated to the object store */
        m_consecutiveIngestFailures = 0;
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
    subscribeTo({ObjectPackager::ObjectSendCompleted::event_name, ObjectPackager::PackagingFailedEvent::event_name}, *m_packager.get());
    return m_packager;
}

const std::optional<std::string> &ObjectController::getObjectDistributionBaseUrl() const {
    return distributionSession().objectDistributionBaseUrl();
}

void ObjectController::reconfigureObjectStore()
{
    auto &dist_session = distributionSession();
    m_objectStore->reconfigureMetadatas(dist_session.getObjectIngestBaseUrl(), dist_session.objectDistributionBaseUrl());
}

void ObjectController::establishInactiveInputs()
{
    m_pullIngesters.clear();
    if (distributionSession().getObjectAcquisitionMethod() == "PUSH" && !m_pushIngester) initPushObjectIngester();
}

void ObjectController::establishActiveInputs()
{
    if (distributionSession().getObjectAcquisitionMethod() == "PULL") initPullObjectIngesters();
}

void ObjectController::activateOutput()
{
    if (!m_packager) {
        setObjectPackager();
    } else {
        activateObjectPackager();
    }
}

void ObjectController::deactivateOutput()
{
    if (m_packager) deactivateObjectPackager();
}

void ObjectController::flushPackagerQueue()
{
    if (m_packager) m_packager->flushQueue();
}

void ObjectController::validateDistributionSession(DistributionSession &distribution_session)
{
    const auto &create_req_data = distribution_session.distributionSessionReqData();
    if (!create_req_data) {
        throw ModelException("CreateReqData missing", "ObjectController", std::string(), ProblemCause::MANDATORY_IE_MISSING);
    }
    const auto &dist_session = create_req_data->getDistSession();
    if (!dist_session) {
        throw ModelException("distSession missing", "ObjectController", "distSession", ProblemCause::MANDATORY_IE_MISSING);
    }
    const auto &up_traffic_flow_info = dist_session->getUpTrafficFlowInfo();
    if (!up_traffic_flow_info || !up_traffic_flow_info.value()) {
        throw ModelException("Object distribution operating mode requires upTrafficFlowInfo", "ObjectController", "distSession.upTrafficFlowInfo", ProblemCause::MANDATORY_IE_MISSING);
    }
    const auto &obj_distr_data = dist_session->getObjDistributionData();
    if (!obj_distr_data || !obj_distr_data.value()) {
        throw ModelException("Object distribution operating mode requires objDistributionData", "ObjectController", "distSession.objDistributionData", ProblemCause::MANDATORY_IE_MISSING);
    }
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
