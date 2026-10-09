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

void ObjectController::abortIngest()
{
    if (m_pushIngester) m_pushIngester->abort();
    {
        std::lock_guard<decltype(m_pullObjectIngestersMutex)> lock(m_pullObjectIngestersMutex);
        for (auto &ingester : m_pullIngesters) {
            if (ingester) ingester->abort();
        }
    }
    /* The object store carries its own asynchronous event thread, for the same reason and with
       the same deadline as the ingesters' own. */
    if (m_objectStore) m_objectStore->stopAsyncEvents();
    Controller::abortIngest();
}

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
    /* pushObjectIngester(nullptr) removes the current one -- ObjectListController and
       ObjectManifestController's own reconfigurePushObjectIngester() both call it this way, on an
       acquisition method change away from PUSH. Same defect as packager(nullptr) above: subscribing
       only makes sense when there is now something to subscribe to. */
    if (m_pushIngester) {
        subscribeTo({ObjectIngester::IngestFailedEvent::event_name}, *m_pushIngester);
    }
    return m_pushIngester;
}

bool ObjectController::ingestFailedDuringSetUp() const
{
    return m_pushIngester && m_pushIngester->startFailed();
}

void ObjectController::refetchFailedPull(Event &event)
{
    /* A pushed object is the client's to send again; only a pull is retried here. */
    if (distributionSession().getObjectAcquisitionMethod() == "PUSH") return;
    // try fetch again
    try {
        PullObjectIngester::PullIngestFailedEvent &pull_ingest_failed_event = dynamic_cast<PullObjectIngester::PullIngestFailedEvent&>(event);
        std::lock_guard<std::recursive_mutex> lock(m_pullObjectIngestersMutex);
        auto &ingesters = getPullObjectIngesters();
        if (!ingesters.empty()) {
            auto &ingester = ingesters.front();
            auto &item = pull_ingest_failed_event.item();

            // The item's deadline is set by the manifest handler. For an object manifest (CAROUSEL and
            // COLLECTION) it is the manifest's latestFetchTime, and TS 26.517 V18.6.0 clause 6.1.2 governs it:
            // "The MBSTF shall fetch the object no later than this UTC timestamp." For STREAMING it is derived from
            // the streaming presentation manifest as the point after which a live segment is considered late, which
            // no 3GPP clause governs: the object could still be fetched, but a client would by then have asked the
            // MBS AS for it. For MPEG-DASH that point is the Segment availability end time, ISO/IEC 23009-1 sixth
            // edition (2026) clause 3.1.48, and clause 5.3.9.1 says each Segment is associated with
            // "a time window in wall-clock time at which the Segment can be accessed via the HTTP-URL".
            // In all cases a retry past the deadline is refused rather than issued and failed, however many
            // attempts have been made.
            const bool past_latest_fetch_time =
                item.hasDeadline() && std::chrono::system_clock::now() > item.getDeadline();

            // An object with no latestFetchTime may, by the same clause, be fetched "at a time
            // of its choosing", so no clause bounds its retries and the operator's own
            // consecutiveIngestFailuresBeforeDeactivate is applied per object instead. The
            // session-wide counter in ObjectController cannot serve here: any other object's
            // successful fetch resets it, so one permanently unfetchable object would be
            // retried without limit while the rest of the session proceeds normally.
            const int  max_failures  = App::self().context()->consecutiveIngestFailuresBeforeDeactivate;
            const unsigned failures  = item.recordFetchFailure();
            const bool out_of_tries  = max_failures != 0 && failures >= static_cast<unsigned>(max_failures);

            if (past_latest_fetch_time) {
                ogs_info("Not refetching %s: its latest fetch time has passed after %u attempt(s)",
                         item.objectId().c_str(), failures);
            } else if (out_of_tries) {
                ogs_warn("Not refetching %s: %u consecutive fetch failures reached the configured "
                         "consecutiveIngestFailuresBeforeDeactivate limit of %d",
                         item.objectId().c_str(), failures, max_failures);
            } else {
                item.forceRecache(true); // Force refetch on error
                ingester->fetch(item);
            }
        }
    } catch (std::bad_cast &ex) {
        // Should never happen, but just incase
        ogs_error("Unable to refetch failed non-PUSH ingest");
    }
}

void ObjectController::processEvent(Event &event, SubscriptionService &event_service)
{
    if (event.eventName() == "ObjectSendCompleted") {
        ObjectPackager::ObjectSendCompleted &objSendEvent = dynamic_cast<ObjectPackager::ObjectSendCompleted&>(event);
        std::string object_id = objSendEvent.objectId();
        ogs_info("Object [%s] sent", object_id.c_str());

        if (m_objectStore) {
            /* Decided and acted on under the store's own lock: reading keepAfterSend() through a
               reference and then deleting leaves room for another thread to replace or erase the
               entry in between. An object already gone is a normal outcome of that race rather than
               an error, so it is reported as "not deleted here" instead of throwing out of an event
               handler that has no handler for it. */
            if (m_objectStore->deleteUnlessKeptAfterSend(object_id)) {
                ogs_debug("Removed object [%s] after sending", object_id.c_str());
            } else {
                ogs_debug("Keeping object [%s] in object store after sending, or it is already gone",
                          object_id.c_str());
            }
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
            distributionSession().requestInactive();
        }
    } else if (event.eventName() == ObjectPackager::PackagingFailedEvent::event_name) {
        ObjectPackager::PackagingFailedEvent &packaging_failed_event = dynamic_cast<ObjectPackager::PackagingFailedEvent&>(event);
        ogs_debug("Object packaging failed: reason = (%i) %s", packaging_failed_event.failureType(), packaging_failed_event.reason().c_str());
        sendEventSynchronous(event); /* repeat packaging failure event to subscribers of this ObjectController */
        distributionSession().requestInactive();
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
    /* packager(nullptr) unsets the current packager -- ObjectCollectionController::
       unsetObjectListPackager() and unsetObjectPackager() both call it this way, on a manifest
       that has no packager to give up as much as one that does. Subscribing only makes sense
       when there is now something to subscribe to; dereferencing m_packager unconditionally here
       crashed every one of those calls. */
    if (m_packager) {
        subscribeTo({ObjectPackager::ObjectSendCompleted::event_name, ObjectPackager::PackagingFailedEvent::event_name}, *m_packager.get());
    }
    return m_packager;
}

const std::optional<std::string> &ObjectController::getObjectDistributionBaseUrl() const {
    return distributionSession().objectDistributionBaseUrl();
}

void ObjectController::reconfigureObjectStore()
{
    if (m_objectStore) {
        auto &dist_session = distributionSession();
        m_objectStore->reconfigureMetadatas(dist_session.getObjectIngestBaseUrl(), dist_session.objectDistributionBaseUrl());
    }
}

void ObjectController::establishInactiveInputs()
{
    std::lock_guard<decltype(m_pullObjectIngestersMutex)> guard(m_pullObjectIngestersMutex);
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
