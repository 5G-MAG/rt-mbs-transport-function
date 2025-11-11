/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Distribution Session Subscription class
 ******************************************************************************
 * Copyright: (C)2024-2025 British Broadcasting Corporation
 * Author(s): David Waring <david.waring2@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * Licensed under the License terms and conditions for use, reproduction, and
 * distribution of 5G-MAG software (the “License”).  You may not use this file
 * except in compliance with the License.  You may obtain a copy of the License at
 * https://www.5g-mag.com/reference-tools.  Unless required by applicable law or
 * agreed to in writing, software distributed under the License is distributed on
 * an “AS IS” BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied.
 *
 * See the License for the specific language governing permissions and limitations
 * under the License.
 */

#include <chrono>
#include <list>
#include <memory>
#include <string>

#include <uuid/uuid.h>

#include "common.hh"
#include "App.hh"
#include "DistributionSession.hh"
#include "DistributionSessionNotificationEvent.hh"
#include "openapi/model/DistSessionSubscription.h"
#include "openapi/model/DistSessionEventReport.h"
#include "openapi/model/DistSessionEventReportList.h"
#include "openapi/model/StatusNotifyReqData.h"
#include "utilities.hh"

#include "DistributionSessionSubscription.hh"

using reftools::mbstf::DistSessionEventReport;
using reftools::mbstf::DistSessionEventReportList;
using reftools::mbstf::DistSessionEventType;
using reftools::mbstf::DistSessionSubscription;
using reftools::mbstf::StatusNotifyReqData;
using fiveg_mag_reftools::CJson;
using fiveg_mag_reftools::ModelException;

MBSTF_NAMESPACE_START

static int __notify_client_cb(int status, ogs_sbi_response_t *response, void *data);

namespace {
    struct RequestData {
        ~RequestData() {};
        const DistributionSessionSubscription *subscription;
        std::shared_ptr<Open5GSSBIRequest> request;
    };
}

/* Constructors and Destructor */
DistributionSessionSubscription::DistributionSessionSubscription(const std::weak_ptr<DistributionSession> &dist_session,
                                                                 CJson &json, bool as_request)
    :m_distributionSession(dist_session)
    ,m_subscriptionId()
    ,m_eventTypes(0)
    ,m_distSessionSubscription(json, as_request)
    ,m_expiryTime()
    ,m_cache(new DistributionSessionSubscription::CacheType{})
{
    _setSubscriptionId();
    _setEventFlags();
    _setExpiryTime();
}

DistributionSessionSubscription::DistributionSessionSubscription(const std::weak_ptr<DistributionSession> &dist_session,
                                                                 const std::shared_ptr<DistSessionSubscription> &dist_session_subsc)
    :m_distributionSession(dist_session)
    ,m_subscriptionId()
    ,m_eventTypes(0)
    ,m_distSessionSubscription(*dist_session_subsc)
    ,m_expiryTime()
    ,m_cache(new DistributionSessionSubscription::CacheType{})
{
    _setSubscriptionId();
    _setEventFlags();
    _setExpiryTime();
}

DistributionSessionSubscription::DistributionSessionSubscription(DistributionSessionSubscription &&other)
    :m_distributionSession(std::move(other.m_distributionSession))
    ,m_subscriptionId(std::move(other.m_subscriptionId))
    ,m_eventTypes(std::move(other.m_eventTypes))
    ,m_distSessionSubscription(std::move(other.m_distSessionSubscription))
    ,m_expiryTime(std::move(other.m_expiryTime))
    ,m_cache(other.m_cache)
{
    other.m_cache = nullptr;
}

DistributionSessionSubscription::DistributionSessionSubscription(const DistributionSessionSubscription &other)
    :m_distributionSession(other.m_distributionSession)
    ,m_subscriptionId(other.m_subscriptionId)
    ,m_eventTypes(other.m_eventTypes)
    ,m_distSessionSubscription(other.m_distSessionSubscription)
    ,m_expiryTime(other.m_expiryTime)
    ,m_cache(new DistributionSessionSubscription::CacheType(*other.m_cache))
{
}

DistributionSessionSubscription::~DistributionSessionSubscription()
{
    if (m_cache) {
        delete m_cache;
        m_cache = nullptr;
    }
}

/* operators */
DistributionSessionSubscription &DistributionSessionSubscription::operator=(DistributionSessionSubscription &&other)
{
    m_distributionSession = std::move(other.m_distributionSession);
    m_subscriptionId = std::move(other.m_subscriptionId);
    m_eventTypes = std::move(other.m_eventTypes);
    m_distSessionSubscription = std::move(other.m_distSessionSubscription);
    m_expiryTime = std::move(other.m_expiryTime);
    if (m_cache) delete m_cache;
    m_cache = other.m_cache;
    other.m_cache = nullptr;
    return *this;
}

DistributionSessionSubscription &DistributionSessionSubscription::operator=(const DistributionSessionSubscription &other)
{
    m_distributionSession = other.m_distributionSession;
    m_subscriptionId = other.m_subscriptionId;
    m_eventTypes = other.m_eventTypes;
    m_distSessionSubscription = other.m_distSessionSubscription;
    m_expiryTime = other.m_expiryTime;
    *m_cache = *other.m_cache;
    return *this;
}

bool DistributionSessionSubscription::operator==(const DistributionSessionSubscription &other) const
{
    //if (m_distributionSession != other.m_distributionSession) return false;
    if (m_subscriptionId != other.m_subscriptionId) return false;
    if (m_eventTypes != other.m_eventTypes) return false;
    if (m_distSessionSubscription != other.m_distSessionSubscription) return false;
    return true;
}

const std::string &DistributionSessionSubscription::notifyUri() const
{
    auto notify_uri = m_distSessionSubscription.getNotifyUri();
    if (!notify_uri) {
        static const std::string empty{};
        return empty;
    }
    return notify_uri.value();
}

const std::optional<std::string> &DistributionSessionSubscription::correlationId() const
{
    return m_distSessionSubscription.getNotifyCorrelationId();
}

const std::optional<std::string> &DistributionSessionSubscription::nfcInstanceId() const
{
    return m_distSessionSubscription.getNfcInstanceId();
}

DistributionSessionSubscription &DistributionSessionSubscription::update(CJson &json, bool as_request)
{
    /* Update from json patch */
    if (json.isArray()) {
        for (auto json_patch_it = json.begin(); json_patch_it != json.end(); ++json_patch_it) {
            m_distSessionSubscription.applyJSONPatch(*json_patch_it);
        }
    } else if (json.isObject()) {
        m_distSessionSubscription.applyJSONPatch(json);
    } else {
        throw ModelException("Not a correctly formatted JSON patch list", "DistSessionSubscription");
    }
    _setEventFlags();
    _setExpiryTime();
    return *this;
}

/* OpenAPI type constructors */
std::shared_ptr<DistSessionEventReportList> DistributionSessionSubscription::makeReportList() const
{
    std::shared_ptr<DistSessionEventReportList> result(new DistSessionEventReportList);
    std::shared_ptr<DistributionSession> dist_session(m_distributionSession.lock());

    if (m_cache && dist_session) {
        /* get list of registered events from the DistributionSession */
        const auto &dist_sess_event_timestamps = dist_session->eventTimestamps();
        int bitmasks = m_eventTypes & dist_sess_event_timestamps.updatedSince(m_cache->lastReportedEventTimes);
        /* compare list to cached times for last reported event and add any that are newer to the result list */
#define ADD_LIST_EVENT(EVT,FIELD) \
    do { \
        if (bitmasks & DistributionSessionEvents::EVT) { \
            DistSessionEventReport::EventTypeType evt_type(new DistSessionEventReport::EventTypeType::element_type); \
            *evt_type = DistSessionEventType::VAL_ ## EVT; \
            std::shared_ptr<DistSessionEventReport> report(new DistSessionEventReport); \
            report->setEventType(std::move(evt_type)); \
            report->setTimeStamp(time_point_to_iso8601_utc_str(dist_sess_event_timestamps.FIELD.value())); \
            result->addEventReportList(report); \
            m_cache->lastReportedEventTimes.FIELD = dist_sess_event_timestamps.FIELD; \
        } \
    } while (0)

        ADD_LIST_EVENT(DATA_INGEST_FAILURE, dataIngestFailure);
        ADD_LIST_EVENT(SESSION_DEACTIVATED, sessionDeactivated);
        ADD_LIST_EVENT(SESSION_ACTIVATED, sessionActivated);
        ADD_LIST_EVENT(SERVICE_MANAGEMENT_FAILURE, serviceManagementFailure);
        ADD_LIST_EVENT(DATA_INGEST_SESSION_ESTABLISHED, dataIngestSessionEstablished);
        ADD_LIST_EVENT(DATA_INGEST_SESSION_TERMINATED, dataIngestSessionTerminated);

#undef ADD_LIST_EVENT

        /* add correlation Id if we have it */
        result->setNotifyCorrelationId(m_distSessionSubscription.getNotifyCorrelationId());
    }

    return result;
}

void DistributionSessionSubscription::pushNotificationsEvent() const
{
    std::shared_ptr<Open5GSEvent> event(new DistributionSessionNotificationEvent(*this));
    App::self().ogsApp()->pushEvent(event);
}

void DistributionSessionSubscription::sendNotifications() const
{
    if (!m_cache) return; /* being destroyed or this DistributionSessionSubscription has been moved to another */

    //ogs_debug("DistributionSessionSubscription[%p]: Sending notifications", this);
    const auto &notify_uri = m_distSessionSubscription.getNotifyUri();
    if (notify_uri) {
        //ogs_debug("DistributionSessionSubscription[%p]: notify URL = %s", this, notify_uri.value().c_str());
        auto report_list = makeReportList();
        const auto &reports = report_list->getEventReportList();
        if (!reports.empty()) {
            //ogs_debug("DistributionSessionSubscription[%p]: have events to send", this);
            if (!m_cache->client) {
                //ogs_debug("DistributionSessionSubscription[%p]: create new client", this);
                m_cache->client.reset(new Open5GSSBIClient(notify_uri.value()));
            }
            //ogs_debug("DistributionSessionSubscription[%p]: building notify request", this);
            std::shared_ptr<StatusNotifyReqData> status_notify_req_data(new StatusNotifyReqData);
            status_notify_req_data->setReportList(report_list);
            CJson json = status_notify_req_data->toJSON(true);
            std::string body(json.serialise());
            ogs_debug("DistributionSessionSubscription[%p]: sending: %s", this, body.c_str());
            static const std::string post_method(OGS_SBI_HTTP_METHOD_POST);
            static const std::string api_version(std::format("{}/{}", StatusNotifyReqData::apiName, StatusNotifyReqData::apiVersion));
            std::shared_ptr<Open5GSSBIRequest> request(new Open5GSSBIRequest(post_method, notify_uri.value(), api_version,
                                                body, OGS_SBI_CONTENT_JSON_TYPE));
            RequestData *data = new RequestData{this, request};
            m_cache->client->sendRequest(__notify_client_cb, request, data);
        }
    }
}

bool DistributionSessionSubscription::processClientResponse(const Open5GSEvent &event)
{
    switch (event.id()) {
    case OGS_EVENT_SBI_CLIENT:
    {
        RequestData *req_data = reinterpret_cast<RequestData*>(event.sbiData());
        if (req_data && req_data->subscription == this) {
            if (event.sbiState() == OGS_OK) {
                auto resp = event.sbiResponse(true);
                ogs_debug("Got %i response from notification(s) to %s", resp.status(), req_data->request->uri());
            } else {
                ogs_debug("Problem sending notification(s) to %s", req_data->request->uri());
            }
            req_data->request.reset();
            delete req_data;
            return true;
        }
        break;
    }
    default:
        break;
    }
    return false;
}

void DistributionSessionSubscription::_setEventFlags()
{
    m_eventTypes = 0;
    const auto &event_list = m_distSessionSubscription.getEventList();
    for (const auto &dist_session_event_type : event_list) {
        if (dist_session_event_type) {
            switch (dist_session_event_type.value()->getValue()) {
            case DistSessionEventType::VAL_DATA_INGEST_FAILURE:
                m_eventTypes |= DistributionSessionEvents::DATA_INGEST_FAILURE;
                break;
            case DistSessionEventType::VAL_SESSION_DEACTIVATED:
                m_eventTypes |= DistributionSessionEvents::SESSION_DEACTIVATED;
                break;
            case DistSessionEventType::VAL_SESSION_ACTIVATED:
                m_eventTypes |= DistributionSessionEvents::SESSION_ACTIVATED;
                break;
            case DistSessionEventType::VAL_SERVICE_MANAGEMENT_FAILURE:
                m_eventTypes |= DistributionSessionEvents::SERVICE_MANAGEMENT_FAILURE;
                break;
            case DistSessionEventType::VAL_DATA_INGEST_SESSION_ESTABLISHED:
                m_eventTypes |= DistributionSessionEvents::DATA_INGEST_SESSION_ESTABLISHED;
                break;
            case DistSessionEventType::VAL_DATA_INGEST_SESSION_TERMINATED:
                m_eventTypes |= DistributionSessionEvents::DATA_INGEST_SESSION_TERMINATED;
                break;
            default:
                ogs_warn("Ignoring unknown DistSessionEventType: %s", dist_session_event_type.value()->getString().c_str());
                break;
            }
        }
    }
}

void DistributionSessionSubscription::_setExpiryTime()
{
    auto opt_expiry_time = m_distSessionSubscription.getExpiryTime();
    if (!opt_expiry_time) {
        m_expiryTime.reset();
    } else {
        std::chrono::utc_clock::time_point utc_exp_time;
        std::istringstream is{opt_expiry_time.value()};
        is.imbue(std::locale("C"));
        is >> std::chrono::parse("%FT%TZ", utc_exp_time);
        m_expiryTime = std::chrono::utc_clock::to_sys(utc_exp_time);
    }
}

void DistributionSessionSubscription::_setSubscriptionId()
{
    uuid_t uuid;
    uuid_generate_random(uuid);
    char uuid_str[37];
    uuid_unparse(uuid, uuid_str);
    m_subscriptionId = uuid_str;
}

static int __notify_client_cb(int status, ogs_sbi_response_t *response, void *data)
{
    ogs_event_t *e = ogs_event_new(OGS_EVENT_SBI_CLIENT);
    int rv;
    RequestData *req_data = reinterpret_cast<RequestData*>(data);

    e = ogs_event_new(OGS_EVENT_SBI_CLIENT);
    ogs_assert(e);
    e->sbi.request = req_data->request->ogsSBIRequest();
    e->sbi.response = response;
    e->sbi.data = data;
    e->sbi.state = status;

    if (status != OGS_OK) {
        ogs_log_message(status == OGS_DONE ? OGS_LOG_DEBUG : OGS_LOG_WARN, 0,
                        "MBS Distribution Session Notification failed [%d]", status);
    } else {
        ogs_assert(response);
    }

    rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        ogs_error("ogs_queue_push() failed:%d", (int)rv);
        ogs_sbi_response_free(response);
        ogs_event_free(e);
        return OGS_ERROR;
    }

    return OGS_OK;
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
