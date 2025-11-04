/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Distribution Session class
 ******************************************************************************
 * Copyright: (C)2024 British Broadcasting Corporation
 * Author(s): Dev Audsin <dev.audsin@bbc.co.uk>
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

// Open5GS includes
#include "ogs-app.h"
#include "ogs-sbi.h"

// standard template library includes
#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>

// App header includes
#include "common.hh"
#include "App.hh"
#include "BitRate.hh"
#include "Context.hh"
#include "Controller.hh"
#include "ControllerFactory.hh"
#include "DistributionSessionEvents.hh"
#include "DistributionSessionNotificationEvent.hh"
#include "DistributionSessionSubscription.hh"
#include "hash.hh"
#include "LocalEvents.hh"
#include "MBSTFNetworkFunction.hh"
#include "ModelParamsException.hh"
#include "NfServer.hh"
#include "ObjectIngester.hh"
#include "Open5GSEvent.hh"
#include "Open5GSSBIMessage.hh"
#include "Open5GSSBIRequest.hh"
#include "Open5GSSBIResponse.hh"
#include "Open5GSSBIServer.hh"
#include "Open5GSSBIStream.hh"
#include "Open5GSTimer.hh"
#include "Open5GSYamlDocument.hh"
#include "Open5GSNetworkFunction.hh"
#include "openapi/model/CreateReqData.h"
#include "openapi/model/CreateRspData.h"
#include "openapi/model/DistSession.h"
#include "openapi/model/DistSessionEventReportList.h"
#include "openapi/model/DistSessionState.h"
#include "openapi/model/ObjDistributionData.h"
#include "openapi/model/ObjAcquisitionMethod.h"
#include "openapi/model/StatusSubscribeReqData.h"
#include "openapi/model/StatusSubscribeRspData.h"
#include "openapi/model/TunnelAddress.h"

#include "openapi/api/IndividualMBSDistributionSessionApi-info.h"
#include "TimerFunc.hh"

// Header include for this class
#include "DistributionSession.hh"

using fiveg_mag_reftools::CJson;
using fiveg_mag_reftools::ModelException;
using fiveg_mag_reftools::ProblemCause;
using reftools::mbstf::CreateReqData;
using reftools::mbstf::CreateRspData;
using reftools::mbstf::DistSession;
using reftools::mbstf::DistSessionState;
using reftools::mbstf::DistSessionEventReportList;
using reftools::mbstf::DistSessionSubscription;
using reftools::mbstf::IpAddr;
using reftools::mbstf::ObjDistributionData;
using reftools::mbstf::UpTrafficFlowInfo;
using reftools::mbstf::ObjAcquisitionMethod;
using reftools::mbstf::ObjDistributionOperatingMode;
using reftools::mbstf::StatusSubscribeReqData;
using reftools::mbstf::StatusSubscribeRspData;
using reftools::mbstf::TunnelAddress;

MBSTF_NAMESPACE_START

static const NfServer::InterfaceMetadata g_nmbstf_distributionsession_api_metadata(
    NMBSTF_DISTSESSION_API_NAME,
    NMBSTF_DISTSESSION_API_VERSION
);

static std::shared_ptr<ObjDistributionData> get_object_distribution_data(const DistributionSession &distributionSession);
static void send_model_error(const ModelException &err, Open5GSSBIStream &stream, int path_segments, Open5GSSBIMessage &message,
                             const NfServer::AppMetadata &app_meta, const std::optional<NfServer::InterfaceMetadata> &api,
                             const std::string &no_cause_reason, const std::string &log_prefix);
static void send_model_params_error(const ModelParamsException &err, Open5GSSBIStream &stream, int path_segments,
                                    Open5GSSBIMessage &message, const NfServer::AppMetadata &app_meta,
                                    const std::optional<NfServer::InterfaceMetadata> &api, const std::string &no_cause_reason,
                                    const std::string &log_prefix);

/**** public: ****/

DistributionSession::DistributionSession(CJson &json, bool as_request)
    :std::enable_shared_from_this<DistributionSession>()
    ,Subscriber()
    ,m_createReqData(new CreateReqData(json, as_request))
    //,m_generated
    //,m_lastUsed
    //,m_hash
    //,m_distributionSessionId
    ,m_controller()
    ,m_eventSubscriptions()
    ,m_currentStateFunction()
    ,m_eventTimestamps()
    ,m_subscriptionLocation()
{

    std::shared_ptr<DistSession> distSession = m_createReqData->getDistSession();

    _setLastUsed();
    m_generated = m_lastUsed;
    _setHash();
    m_distributionSessionId = distSession->getDistSessionId();
    _changeState(&DistributionSession::_constructedState);
}

DistributionSession::~DistributionSession()
{
    if (!m_eventTimestamps.sessionDeactivated) {
        _registerEvent(DistributionSessionEvents::SESSION_DEACTIVATED);
    }
}

CJson DistributionSession::json(bool as_request, bool include_subscription_location) const
{
    if (as_request) {
        /* Return original request object as JSON */
        return m_createReqData->toJSON(as_request);
    }
    /* Create new response object from DistSession */
    std::shared_ptr<DistSession> dist_session(new DistSession(*m_createReqData->getDistSession()));
    if (include_subscription_location) {
        /* We need to add the subscription location URI if an original subscription was present */
        auto &opt_subsc = dist_session->getDistSessionSubscription();
        if (opt_subsc) {
            std::shared_ptr<DistSessionSubscription> new_subsc(new DistSessionSubscription(*opt_subsc.value()));
            new_subsc->setDistSessionSubscUri(m_subscriptionLocation);
            dist_session->setDistSessionSubscription(new_subsc);
        }
    }
    CreateRspData response{};
    response.setDistSession(dist_session);
    return response.toJSON(as_request);
}

const std::shared_ptr<DistributionSession> &DistributionSession::find(const std::string &id)
{
    const std::map<std::string, std::shared_ptr<DistributionSession> > &distributionSessions = App::self().context()->distributionSessions;
    auto it = distributionSessions.find(id);
    if (it == distributionSessions.end()) {
        throw std::out_of_range("MBST Distribution session not found");
    }
    return it->second;
}

void DistributionSession::processEvent(Event &event, SubscriptionService &event_service)
{
    if (event.eventName() == ObjectIngester::IngestFailedEvent::event_name) {
        //ObjectIngester::IngestFailedEvent &ingest_failed_event = dynamic_cast<ObjectIngester::IngestFailedEvent&>(event);
        _registerEvent(DistributionSessionEvents::DATA_INGEST_FAILURE);
    }
}

bool DistributionSession::processEvent(Open5GSEvent &event)
{
    const NfServer::InterfaceMetadata &nmbstf_distributionsession_api = g_nmbstf_distributionsession_api_metadata;
    const NfServer::AppMetadata &app_meta = App::self().mbstfAppMetadata();

    switch (event.id()) {
    case OGS_EVENT_SBI_SERVER:
        {
            Open5GSSBIRequest request(event.sbiRequest());
            ogs_assert(request);
            Open5GSSBIMessage message;
            Open5GSSBIStream stream(reinterpret_cast<ogs_sbi_stream_t*>(event.sbiData()));
            ogs_assert(stream);
            Open5GSSBIServer server(stream.server());
            ogs_assert(server);
            std::optional<NfServer::InterfaceMetadata> api(std::nullopt);

            try {
                message.parseHeader(request);
            } catch (std::exception &ex) {
                ogs_error("Failed to parse request headers");
                ogs_assert(true == NfServer::sendError(stream, ProblemCause::INVALID_MSG_FORMAT, 0, message, app_meta,
                                                           api, "Failed to parse HTTP request headers"));
                return true;
            }

            std::string service_name(message.serviceName());
            const char *ptr_resource0 = message.resourceComponent(0);
            ogs_debug("OGS_EVENT_SBI_SERVER: service=%s, component[0]=%s", service_name.c_str(), ptr_resource0);
            if (service_name == "nmbstf-distsession") {
                api = nmbstf_distributionsession_api;
            } else {
                message.resetHeader();
                return false;
            }

            if (api.value() == nmbstf_distributionsession_api) {
                /******** nmbstf-distsession ********/
                std::string api_version(message.apiVersion());
                if (api_version != OGS_SBI_API_V1) {
                    ogs_error("Unsupported API version [%s]", api_version.c_str());
                    ogs_assert(true == NfServer::sendError(stream, ProblemCause::INVALID_API, 0, message, app_meta,
                                                           api, "Unsupported API version"));
                    return true;
                }

                if (ptr_resource0) {
                    std::string resource0(ptr_resource0);
                    if (resource0 == "dist-sessions") {
                        /* starts with .../dist-sessions... */
                        std::string method(message.method());
                        const char *ptr_resource1 = message.resourceComponent(1);
                        if (ptr_resource1) {
                            /* starts with .../dist-sessions/{distSessionId}... */
                            std::string dist_session_id(ptr_resource1);
                            std::shared_ptr<DistributionSession> dist_session;
                            try {
                                dist_session = DistributionSession::find(dist_session_id);
                            } catch (const std::out_of_range &e) {
                                std::ostringstream err;
                                err << "MBSTF Distribution Session [" << dist_session_id << "] does not exist.";
                                ogs_error("%s", err.str().c_str());

                                static const std::string param("{sessionId}");
                                std::ostringstream reason;
                                reason << "Invalid MBSTF Distribution Session identifier [" << dist_session_id << "]";
                                std::map<std::string, std::string> invalid_params(NfServer::makeInvalidParams(param, reason.str()));

                                ogs_assert(true == NfServer::sendError(stream, ProblemCause::SUBSCRIPTION_NOT_FOUND, 2, message,
                                                                    app_meta, api, "MBSTF Distribution Session not found",
                                                                    err.str(), std::nullopt, invalid_params));
                                return true;
                            }

                            const char *ptr_resource2 = message.resourceComponent(2);
                            if (ptr_resource2) {
                                std::string subresource(ptr_resource2);
                                if (subresource == "subscriptions") {
                                    /* starts with .../dist-sessions/{distSessionId}/subscriptions... */
                                    const char *ptr_resource3 = message.resourceComponent(3);
                                    if (ptr_resource3) {
                                        /* starts with .../dist-sessions/{distSessionId}/subscriptions/{subscriptionId}... */
                                        std::string subscription_id(ptr_resource3);
                                        const DistributionSessionSubscription *dist_sess_subsc = nullptr;
                                        try {
                                            dist_sess_subsc = &dist_session->getSubscription(subscription_id);
                                        } catch (std::out_of_range &ex) {
                                            std::ostringstream err;
                                            err << "Distribution Session Subscription [" << subscription_id << "] not found: "
                                                << ex.what();
                                            ogs_error("%s", err.str().c_str());
                                            std::map<std::string, std::string> invalid_params(
                                                                    NfServer::makeInvalidParams("{subscriptionId}", ex.what()));
                                            ogs_assert(true == NfServer::sendError(stream,
                                                                        ProblemCause::SUBSCRIPTION_NOT_FOUND, 4, message,
                                                                        app_meta, api,
                                                                        "MBSTF Distribution Session Subscription not found",
                                                                        err.str(), std::nullopt, invalid_params));
                                            return true;
                                        }
                                        const char *ptr_resource4 = message.resourceComponent(4);
                                        if (ptr_resource4) {
                                            /* starts .../dist-sessions/{distSessionRef}/subscriptions/{subscriptionId}/... */
                                            std::ostringstream err;
                                            err << "Distribution Session [" << dist_session_id << "] subscription ["
                                                << subscription_id << "] sub-resource [" << ptr_resource4
                                                << "] not understood";
                                            ogs_error("%s", err.str().c_str());
                                            ogs_assert(true == NfServer::sendError(stream,
                                                                        ProblemCause::RESOURCE_URI_STRUCTURE_NOT_FOUND,
                                                                        5, message, app_meta, api, std::nullopt, err.str()));
                                        } else {
                                            /* is .../dist-sessions/{distSessionRef}/subscriptions/{subscriptionId} */
                                            /* DELETE and PATCH methods allowed by TS 29.581 */
                                            /* We add OPTIONS for RESTful introspection */
                                            if (method == OGS_SBI_HTTP_METHOD_DELETE) {
                                                dist_session->_apiSubscriptionDelete(*dist_sess_subsc, stream, message, request, api, app_meta);
                                            } else if (method == OGS_SBI_HTTP_METHOD_PATCH) {
                                                dist_session->_apiSubscriptionPatch(*dist_sess_subsc, stream, message, request, api, app_meta);
                                            } else if (method == OGS_SBI_HTTP_METHOD_OPTIONS) {
                                                std::shared_ptr<Open5GSSBIResponse> response(NfServer::newResponse(std::nullopt, std::nullopt, std::nullopt, std::nullopt, 0, /*OGS_SBI_HTTP_METHOD_PATCH ", " OGS_SBI_HTTP_METHOD_DELETE ", " */ OGS_SBI_HTTP_METHOD_OPTIONS, api, app_meta));
                                                NfServer::populateResponse(response, "", OGS_SBI_HTTP_STATUS_NO_CONTENT);
                                                ogs_assert(true == Open5GSSBIServer::sendResponse(stream, *response));
                                            } else {
                                                std::ostringstream err;
                                                err << "Distribution Session [" << dist_session_id << "] subscription ["
                                                    << subscription_id << "] method [" << method
                                                    << "] not allowed for this resource";
                                                ogs_error("%s", err.str().c_str());
                                                ogs_assert(true == NfServer::sendError(stream,
                                                                        OGS_SBI_HTTP_STATUS_MEHTOD_NOT_ALLOWED,
                                                                        4, message, app_meta, api, std::nullopt, err.str()));
                                            }
                                        }
                                    } else {
                                        /* is .../dist-sessions/{distSessionRef}/subscriptions */
                                        /* POST method allowed by TS 29.581 */
                                        /* We add OPTIONS for RESTful introspection */
                                        if (method == OGS_SBI_HTTP_METHOD_POST) {
                                            dist_session->_apiSubscriptionCreate(stream, message, request, api, app_meta);

                                        } else if (method == OGS_SBI_HTTP_METHOD_OPTIONS) {
                                            std::shared_ptr<Open5GSSBIResponse> response(NfServer::newResponse(std::nullopt, std::nullopt, std::nullopt, std::nullopt, 0, OGS_SBI_HTTP_METHOD_POST ", " OGS_SBI_HTTP_METHOD_OPTIONS, api, app_meta));
                                            NfServer::populateResponse(response, "", OGS_SBI_HTTP_STATUS_NO_CONTENT);
                                            ogs_assert(true == Open5GSSBIServer::sendResponse(stream, *response));
                                        } else {
                                            std::ostringstream err;
                                            err << "Distribution Session [" << dist_session_id << "] subscriptions: method ["
                                                << method << "] not allowed for this resource";
                                            ogs_error("%s", err.str().c_str());
                                            ogs_assert(true == NfServer::sendError(stream,
                                                                        OGS_SBI_HTTP_STATUS_MEHTOD_NOT_ALLOWED,
                                                                        3, message, app_meta, api, std::nullopt, err.str()));
                                        }
                                    }
                                } else {
                                    /* is .../dist-sessions/{distSessionRef}/??? */
                                    std::string err = std::format("Distribution Session [{}] sub-resource [{}] is not understood",
                                                                  dist_session_id, subresource);
                                    ogs_error("%s", err.c_str());
                                    ogs_assert(true == NfServer::sendError(stream, ProblemCause::RESOURCE_URI_STRUCTURE_NOT_FOUND,
                                                                        3, message, app_meta, api, std::nullopt, err));
                                }
                            } else {
                                /* is .../dist-sessions/{distSessionRef} */
                                /* GET, PATCH and DELETE methods are allowed by TS 29.581 */
                                /* We add OPTIONS for RESTful introspection */
                                if (method == OGS_SBI_HTTP_METHOD_GET) {
                                    dist_session->_apiSessionGet(stream, message, request, api, app_meta);
                                } else if (method == OGS_SBI_HTTP_METHOD_PATCH) {
                                    dist_session->_apiSessionPatch(stream, message, request, api, app_meta);
                                } else if (method == OGS_SBI_HTTP_METHOD_DELETE) {
                                    dist_session->_apiSessionDelete(stream, message, request, api, app_meta);
                                } else if (method == OGS_SBI_HTTP_METHOD_OPTIONS) {
                                    std::shared_ptr<Open5GSSBIResponse> response(NfServer::newResponse(
                                                    std::nullopt, std::nullopt, std::nullopt, std::nullopt, 0,
                                                    OGS_SBI_HTTP_METHOD_POST ", " OGS_SBI_HTTP_METHOD_OPTIONS, api, app_meta));
                                    NfServer::populateResponse(response, "", OGS_SBI_HTTP_STATUS_NO_CONTENT);
                                    ogs_assert(true == Open5GSSBIServer::sendResponse(stream, *response));
                                } else {
                                    std::ostringstream err;
                                    err << "Distribution Session [" << ptr_resource1 << "], method [" << method
                                        << "] is not allowed for a Distribution Session"; 
                                    ogs_error("%s", err.str().c_str());
                                    ogs_assert(true == NfServer::sendError(stream, OGS_SBI_HTTP_STATUS_MEHTOD_NOT_ALLOWED,
                                                                        2, message, app_meta, api, std::nullopt, err.str()));
                                }
                            }
                        } else {
                            /* is .../dist-sessions */
                            /* POST method allowed by TS 29.581 */
                            /* We also include OPTIONS method for RESTful introspection */
                            if (method == OGS_SBI_HTTP_METHOD_POST) {
                                DistributionSession::_apiSessionCreate(stream, message, request, api, app_meta);
                            } else if (method == OGS_SBI_HTTP_METHOD_OPTIONS) {
                                std::shared_ptr<Open5GSSBIResponse> response(NfServer::newResponse(
                                                    std::nullopt, std::nullopt, std::nullopt, std::nullopt, 0, 
                                                    OGS_SBI_HTTP_METHOD_POST ", " OGS_SBI_HTTP_METHOD_OPTIONS, api, app_meta));
                                NfServer::populateResponse(response, "", OGS_SBI_HTTP_STATUS_NO_CONTENT);
                                ogs_assert(true == Open5GSSBIServer::sendResponse(stream, *response));
                            } else {
                                std::ostringstream err;
                                err << "Distribution Session [" << ptr_resource1 << "], method [" << method
                                    << "] is not allowed for a Distribution Session";
                                ogs_error("%s", err.str().c_str());
                                ogs_assert(true == NfServer::sendError(stream, OGS_SBI_HTTP_STATUS_MEHTOD_NOT_ALLOWED,
                                                                          2, message, app_meta, api, std::nullopt, err.str()));
                            }
                        }
                    } else {
                        std::ostringstream err;
                        err << "Unknown object type \"" << resource0 << "\" in MBSTF Distribution Session API";
                        ogs_error("%s", err.str().c_str());
                        ogs_assert(true == NfServer::sendError(stream, ProblemCause::RESOURCE_URI_STRUCTURE_NOT_FOUND, 1, message,
                                                            app_meta, api, "Bad request", err.str()));
                    }
                } else {
                    static const char *err = "Missing resource name from URL path";
                    ogs_error("%s", err);
                    ogs_assert(true == NfServer::sendError(stream, ProblemCause::RESOURCE_URI_STRUCTURE_NOT_FOUND, 0, message, app_meta,
                                                std::nullopt, "Missing resource name", err));
                }
            } /* else: should not be reachable unless we've forgotten to implement a whole, recognised, API service name */
            return true;
        }
    case OGS_EVENT_SBI_CLIENT:
        {
            for (auto &[dist_sess_id, dist_sess] : App::self().context()->distributionSessions) {
                for (auto &[subsc_id, subsc] : dist_sess->m_eventSubscriptions) {
                    if (subsc.processClientResponse(event)) return true;
                }
            }
        }
    case LocalEvents::SEND_NOTIFICATION:
        {
            DistributionSessionNotificationEvent dist_event(event);
            const auto &subsc = dist_event.distributionSessionSubscription();
            ogs_debug("Sending notifications for subscription %p", &subsc);
            subsc.sendNotifications();
            return true;
        }
    default:
        break;
    }
    return false;
}

const DistSessionState &DistributionSession::getState() const
{
    auto create_req_data = m_createReqData;
    const auto &dist_session = create_req_data->getDistSession();
    const DistSession::DistSessionStateType &dist_sess_state = dist_session->getDistSessionState();

    if (dist_sess_state) {
        return *dist_sess_state;
    }
    static const DistSessionState no_val = DistSessionState();
    return no_val;
}

DistributionSession &DistributionSession::setState(const DistSessionState &dist_sess_state)
{
    auto create_req_data = m_createReqData;
    auto &dist_session = create_req_data->getDistSession();
    if (dist_sess_state != *dist_session->getDistSessionState()) {
        DistSession::DistSessionStateType new_sess_state(new DistSessionState(dist_sess_state));
        dist_session->setDistSessionState(new_sess_state);
        _transitionTo(dist_sess_state.getValue());
    }
    return *this;
}

const ObjDistributionData::ObjAcquisitionIdsPullType &DistributionSession::getObjectAcquisitionPullUrls() const
{
    std::shared_ptr<CreateReqData> create_req_data = distributionSessionReqData();
    std::shared_ptr<DistSession> dist_session = create_req_data->getDistSession();
    const std::optional<std::shared_ptr<ObjDistributionData> > &object_distribution_data = dist_session->getObjDistributionData();
    if (object_distribution_data.has_value()) {
        std::shared_ptr<ObjDistributionData> object_distribution_data_ptr = object_distribution_data.value();
        return object_distribution_data_ptr->getObjAcquisitionIdsPull();
    } else {
        ogs_error("ObjectDistributionData is not available");
        static const ObjDistributionData::ObjAcquisitionIdsPullType empty_result;
        return empty_result;
    }
}

const std::optional<std::string> &DistributionSession::getDestIpAddr() const
{
    std::shared_ptr<CreateReqData> create_req_data = distributionSessionReqData();
    std::shared_ptr<DistSession> dist_session = create_req_data->getDistSession();
    const std::optional<std::shared_ptr< UpTrafficFlowInfo > > &up_traffic_flow_info = dist_session->getUpTrafficFlowInfo();
    if (up_traffic_flow_info.has_value()) {
        std::shared_ptr<UpTrafficFlowInfo> up_traffic_flow = up_traffic_flow_info.value();
        const std::shared_ptr<IpAddr> ipAddr = up_traffic_flow->getDestIpAddr();
        if (ipAddr) {
            return ipAddr->getIpv4Addr();
        }
    }

    static const std::optional<std::string> empty = std::nullopt;
    return empty;
}

const std::optional<std::string> &DistributionSession::getTunnelAddr() const
{
    std::shared_ptr<CreateReqData> create_req_data = distributionSessionReqData();
    std::shared_ptr<DistSession> dist_session = create_req_data->getDistSession();
    std::optional<std::shared_ptr<TunnelAddress> > mb_upf_tun_addr = dist_session->getMbUpfTunAddr();
    if (mb_upf_tun_addr.has_value()) {
        return mb_upf_tun_addr.value()->getIpv4Addr();
    }

    static const std::optional<std::string> empty = std::nullopt;
    return empty;
}

in_port_t DistributionSession::getPortNumber() const
{
    in_port_t port_number = 0;
    std::shared_ptr<CreateReqData> create_req_data = distributionSessionReqData();
    std::shared_ptr<DistSession> dist_session = create_req_data->getDistSession();
    std::optional<std::shared_ptr<UpTrafficFlowInfo> > up_traffic_flow_info = dist_session->getUpTrafficFlowInfo();
    if (up_traffic_flow_info.has_value()) {
        std::shared_ptr<UpTrafficFlowInfo> up_traffic_flow = up_traffic_flow_info.value();
        port_number = static_cast<in_port_t>(up_traffic_flow->getPortNumber());
    }
    return port_number;
}

in_port_t DistributionSession::getTunnelPortNumber() const
{
    in_port_t port_number = 0;
    std::shared_ptr<CreateReqData> create_req_data = distributionSessionReqData();
    std::shared_ptr<DistSession> dist_session = create_req_data->getDistSession();
    std::optional<std::shared_ptr<TunnelAddress> > mb_upf_tun_addr = dist_session->getMbUpfTunAddr();
    if (mb_upf_tun_addr.has_value()) {
        port_number = static_cast<in_port_t>(mb_upf_tun_addr.value()->getPortNumber());
    }
    return port_number;
}

uint32_t DistributionSession::getRateLimit() const
{
    std::optional<BitRate> mbr = getMbr();

    if (mbr) {
        try {
            return static_cast<uint32_t>(mbr.value().bitRate()/1000.0);
        } catch (const std::invalid_argument &e) {
            throw std::runtime_error("Invalid MBR value");
        } catch (const std::out_of_range &e) {
            throw std::runtime_error("MBR value out of range");
        }
    }

    return 0;
}

std::optional<BitRate> DistributionSession::getMbr() const
{
    std::shared_ptr<CreateReqData> create_req_data = distributionSessionReqData();
    std::shared_ptr<DistSession> dist_session = create_req_data->getDistSession();
    const std::optional<std::string> &mbr = dist_session->getMbr();

    if (mbr) {
        return BitRate(mbr.value());
    }
    return std::nullopt;
}

const std::optional<std::string> &DistributionSession::getObjectIngestBaseUrl() const
{
    std::shared_ptr<CreateReqData> create_req_data = distributionSessionReqData();
    std::shared_ptr<DistSession> dist_session = create_req_data->getDistSession();
    const std::optional<std::shared_ptr<ObjDistributionData> > &object_distribution_data = dist_session->getObjDistributionData();
    if (object_distribution_data.has_value()) {
        std::shared_ptr<ObjDistributionData> object_distribution_data_ptr = object_distribution_data.value();
        return object_distribution_data_ptr->getObjIngestBaseUrl();
    } else {
        ogs_error("ObjectDistributionData is not available");
        static const std::optional<std::string> null_value = std::nullopt;
        return null_value;
    }
}

const std::string &DistributionSession::getObjectAcquisitionMethod() const
{
    std::shared_ptr<CreateReqData> create_req_data = distributionSessionReqData();
    std::shared_ptr<DistSession> dist_session = create_req_data->getDistSession();
    const std::optional<std::shared_ptr<ObjDistributionData> > &object_distribution_data = dist_session->getObjDistributionData();
    if (object_distribution_data.has_value()) {
        std::shared_ptr<ObjDistributionData> object_distribution_data_ptr = object_distribution_data.value();
        std::shared_ptr< ObjAcquisitionMethod > obj_acquisition_method = object_distribution_data_ptr->getObjAcquisitionMethod();
        return obj_acquisition_method->getString();
    } else {
        ogs_error("ObjectDistributionData is not available");
        static const std::string empty_obj_acquisition_method = std::string();
        return empty_obj_acquisition_method;
    }
}

void DistributionSession::setObjectIngestBaseUrl(std::string ingest_base_url)
{
    const std::shared_ptr<CreateReqData> create_req_data = distributionSessionReqData();
    std::shared_ptr<DistSession> dist_session = create_req_data->getDistSession();
    const std::optional<std::shared_ptr<ObjDistributionData> > &object_distribution_data = dist_session->getObjDistributionData();
    if (object_distribution_data.has_value()) {
        std::shared_ptr<ObjDistributionData> object_distribution_data_ptr = object_distribution_data.value();
        const std::optional<std::string> &base_url = ingest_base_url.empty() ? std::nullopt : std::optional<std::string>(ingest_base_url);
        object_distribution_data_ptr->setObjIngestBaseUrl(base_url);
    } else {
        ogs_error("ObjectDistributionData is not available");
    }
}

const std::optional<std::string> &DistributionSession::getObjectAcquisitionPushId() const
{
    std::shared_ptr<CreateReqData> create_req_data = distributionSessionReqData();
    std::shared_ptr<DistSession> dist_session = create_req_data->getDistSession();
    const std::optional<std::shared_ptr<ObjDistributionData> > &object_distribution_data = dist_session->getObjDistributionData();
    if (object_distribution_data.has_value()) {
        std::shared_ptr<ObjDistributionData> object_distribution_data_ptr = object_distribution_data.value();
        return object_distribution_data_ptr->getObjAcquisitionIdPush();
    } else {
        ogs_error("ObjectDistributionData is not available");
        static const std::optional<std::string> null_value = std::nullopt;
        return null_value;
    }
}

bool DistributionSession::setObjectAcquisitionIdPush(std::optional<std::string> &id) {
    std::shared_ptr<ObjDistributionData> object_distribution_data = get_object_distribution_data(*this);
    if (object_distribution_data) {
        return object_distribution_data->setObjAcquisitionIdPush(id);
    } else {
        ogs_error("ObjectDistributionData is not available");
        return false;
    }
    return false;

}

const std::string &DistributionSession::getObjectDistributionOperatingMode() const
{
    std::shared_ptr<ObjDistributionData> object_distribution_data = get_object_distribution_data(*this);
    if (object_distribution_data) {
        std::shared_ptr< ObjDistributionOperatingMode > operating_mode = object_distribution_data->getObjDistributionOperatingMode();
        return operating_mode->getString();
    } else {
        ogs_error("ObjectDistributionData is not available");
        static std::string emptyObjAcquisitionMethod = std::string();
        return emptyObjAcquisitionMethod;
    }
}

const std::optional<std::string> &DistributionSession::objectDistributionBaseUrl() const
{
    std::shared_ptr<CreateReqData> create_req_data = distributionSessionReqData();
    std::shared_ptr<DistSession> dist_session = create_req_data->getDistSession();
    const std::optional<std::shared_ptr<ObjDistributionData> > &object_distribution_data = dist_session->getObjDistributionData();
    if (object_distribution_data.has_value()) {
        std::shared_ptr<ObjDistributionData> object_distribution_data_ptr = object_distribution_data.value();
        return object_distribution_data_ptr->getObjDistributionBaseUrl();
    } else {
        ogs_error("ObjectDistributionData is not available");
        static const std::optional<std::string> null_value = std::nullopt;
        return null_value;
    }
}

const std::string &DistributionSession::addSubscription(const std::shared_ptr<DistSessionSubscription> &dist_session_susbc)
{
    DistributionSessionSubscription subsc(weak_from_this(), dist_session_susbc);
    auto it = m_eventSubscriptions.emplace(subsc.subscriptionId(), std::move(subsc)).first;
    return it->first;
}

const std::string &DistributionSession::addSubscription(CJson &json, bool as_request)
{
    std::shared_ptr<StatusSubscribeReqData> subsc_req(new StatusSubscribeReqData(json, as_request));
    return addSubscription(subsc_req->getSubscription());
}

const DistributionSessionSubscription &DistributionSession::getSubscription(const std::string &subscription_id) const
{
    auto it = m_eventSubscriptions.find(subscription_id);
    if (it == m_eventSubscriptions.end()) throw std::out_of_range("No such DistSession subscription Id");
    return it->second;
}

void DistributionSession::updateSubscription(const std::string &subscription_id, CJson &json, bool as_request)
{
    auto it = m_eventSubscriptions.find(subscription_id);
    if (it == m_eventSubscriptions.end()) {
        throw std::range_error("No such subscription");
    }
    it->second.update(json, as_request);
}

void DistributionSession::removeSubscription(const std::string &subscription_id)
{
    auto it = m_eventSubscriptions.find(subscription_id);
    if (it == m_eventSubscriptions.end()) {
        throw std::range_error("No such subscription");
    }
    m_eventSubscriptions.erase(it);
}

DistributionSession &DistributionSession::distributionSessionReqData(const std::shared_ptr<CreateReqData> &new_create_req_data)
{
    ModelParamsException ex("Invalid DistSession change", "CreateReqData", std::string(), ProblemCause::INVALID_MSG_FORMAT);

    /* Check changes comply with valid operation */
    auto old_create_req_data = distributionSessionReqData();
    auto old_dist_session = old_create_req_data->getDistSession();
    auto new_dist_session = new_create_req_data->getDistSession();
    if (new_dist_session->getDistSessionId() != old_dist_session->getDistSessionId()) {
        ex.addInvalidParameter("distSession.distSessionId", "Cannot change distSessionId");
    }
    auto old_obj_distribution_data = old_dist_session->getObjDistributionData();
    auto new_obj_distribution_data = new_dist_session->getObjDistributionData();
    if (old_obj_distribution_data && new_obj_distribution_data &&
        new_obj_distribution_data.value()->getObjDistributionOperatingMode() !=
                old_obj_distribution_data.value()->getObjDistributionOperatingMode()) {
        ex.addInvalidParameter("distSession.objDistributionData.objDistributionOperatingMode",
                                "Cannot change objDistributionOperatingMode");
    }

    /* If errors then report them */
    if (!ex.invalidParams.empty()) {
        throw ex;
    }

    /* New CreateReqData is valid, replace old one */
    m_createReqData = new_create_req_data;

    /* Reconfigure the controller using the new CreateReqData */
    if (m_controller) {
        m_controller->reconfigure();
    }

    /* Make sure we are in the right state */
    _transitionTo(new_dist_session->getDistSessionState()->getValue());

    /* Update the last-used and hash values to reflect the new CreateReqData */
    _setLastUsed();
    _setHash();

    return *this;
}

/**** private: ****/

DistributionSession::InitStateAction DistributionSession::Action::initState()
{
    return DistributionSession::InitStateAction();
}

DistributionSession::StateTransitionAction DistributionSession::Action::stateTransition(reftools::mbstf::DistSessionState::Enum new_state)
{
    return DistributionSession::StateTransitionAction(new_state);
}

void DistributionSession::_transitionTo(DistSessionState::Enum new_state)
{
    auto act = Action::stateTransition(new_state);
    m_currentStateFunction(act);
}

void DistributionSession::_changeState(void (DistributionSession::*f)(const DistributionSession::Action &action))
{
    m_currentStateFunction = std::bind(f, this, std::placeholders::_1);
    m_currentStateFunction(Action::initState());
}

void DistributionSession::_constructedState(const DistributionSession::Action &action)
{
    switch (action.getType()) {
    case Action::STATE_TRANSITION:
        {
            auto state_trans_act = dynamic_cast<const StateTransitionAction&>(action);
            switch (state_trans_act.newState()) {
            case DistSessionState::VAL_INACTIVE:
            case DistSessionState::VAL_ESTABLISHED:
            case DistSessionState::VAL_ACTIVE:
            case DistSessionState::VAL_DEACTIVATING:
                /* start transition to initial configured state */
                _changeState(&DistributionSession::_inactiveState);
                break;
            default:
                throw std::runtime_error("Request for unhandled state in DistSession");
            }
        }
        break;
    default:
        break;
    }
}

void DistributionSession::_inactiveState(const DistributionSession::Action &action)
{
    switch (action.getType()) {
    case Action::INIT_STATE:
        ogs_debug("DistributionSession(%p) entering INACTIVE state", this);
        m_controller->establishInactiveInputs();
        _registerEvent(DistributionSessionEvents::SESSION_DEACTIVATED);
        /* if we are not at the desired state, transition to the next */
        if (getState().getValue() != DistSessionState::VAL_INACTIVE) _changeState(&DistributionSession::_establishedState);
        break;
    case Action::STATE_TRANSITION:
        {
            auto state_trans_act = dynamic_cast<const StateTransitionAction&>(action);
            switch (state_trans_act.newState()) {
            case DistSessionState::VAL_INACTIVE:
                break;
            case DistSessionState::VAL_ESTABLISHED:
            case DistSessionState::VAL_ACTIVE:
                _changeState(&DistributionSession::_establishedState);
                break;
            case DistSessionState::VAL_DEACTIVATING:
                throw std::runtime_error("Invalid state transition in DistSession");
            default:
                throw std::runtime_error("Request for unhandled state in DistSession");
            }
        }
        break;
    default:
        break;
    }
}

void DistributionSession::_establishedState(const DistributionSession::Action &action)
{
    switch (action.getType()) {
    case Action::INIT_STATE:
        ogs_debug("DistributionSession(%p) entering ESTABLISHED state", this);
        m_controller->establishActiveInputs();
        _registerEvent(DistributionSessionEvents::DATA_INGEST_SESSION_ESTABLISHED);
        if (getState().getValue() != DistSessionState::VAL_ESTABLISHED) _changeState(&DistributionSession::_activeState);
        break;
    case Action::STATE_TRANSITION:
        {
            auto state_trans_act = dynamic_cast<const StateTransitionAction&>(action);
            switch (state_trans_act.newState()) {
            case DistSessionState::VAL_INACTIVE:
                /* Shutdown PullIngesters */
                _changeState(&DistributionSession::_inactiveState);
                break;
            case DistSessionState::VAL_ESTABLISHED:
                break;
            case DistSessionState::VAL_ACTIVE:
                /* Start ObjectPackager */
                _changeState(&DistributionSession::_activeState);
                break;
            case DistSessionState::VAL_DEACTIVATING:
                throw std::runtime_error("Invalid state transition in DistSession");
            default:
                throw std::runtime_error("Request for unhandled state in DistSession");
            }
        }
        break;
    default:
        break;
    }
}

void DistributionSession::_activeState(const DistributionSession::Action &action)
{
    switch (action.getType()) {
    case Action::INIT_STATE:
        ogs_debug("DistributionSession(%p) entering ACTIVE state", this);
        m_controller->activateOutput();
        _registerEvent(DistributionSessionEvents::SESSION_ACTIVATED);
        /* if we are not at the desired state, transition to the next */
        if (getState().getValue() != DistSessionState::VAL_ACTIVE) _changeState(&DistributionSession::_deactivatingState);
        break;
    case Action::STATE_TRANSITION:
        {
            auto state_trans_act = dynamic_cast<const StateTransitionAction&>(action);
            switch (state_trans_act.newState()) {
            case DistSessionState::VAL_DEACTIVATING:
            case DistSessionState::VAL_INACTIVE:
                _changeState(&DistributionSession::_deactivatingState);
                break;
            case DistSessionState::VAL_ESTABLISHED:
                throw std::runtime_error("Invalid state transition in DistSession");
            case DistSessionState::VAL_ACTIVE:
                break;
            default:
                throw std::runtime_error("Request for unhandled state in DistSession");
            }
        }
        break;
    default:
        break;
    }
}

void DistributionSession::_deactivatingState(const DistributionSession::Action &action)
{
    switch (action.getType()) {
    case Action::INIT_STATE:
        ogs_debug("DistributionSession(%p) entering DEACTIVATING state", this);
        m_controller->deactivateOutput();
        _registerEvent(DistributionSessionEvents::DATA_INGEST_SESSION_TERMINATED);
        /* once we've deactivated everything, always go to inactive state */
        if (getState().getValue() == DistSessionState::VAL_DEACTIVATING) {
            DistSessionState next_state;
            next_state = DistSessionState::VAL_INACTIVE;
            setState(next_state);
        } else {
            _changeState(&DistributionSession::_inactiveState);
        }
        break;
    case Action::STATE_TRANSITION:
        {
            auto state_trans_act = dynamic_cast<const StateTransitionAction&>(action);
            switch (state_trans_act.newState()) {
            case DistSessionState::VAL_INACTIVE:
                ogs_debug("Change to INACTIVE will happen once deactivation process is complete");
                break;
            case DistSessionState::VAL_ESTABLISHED:
            case DistSessionState::VAL_ACTIVE:
                throw std::runtime_error("Invalid state transition in DistSession");
            case DistSessionState::VAL_DEACTIVATING:
                break;
            default:
                throw std::runtime_error("Request for unhandled state in DistSession");
            }
        }
        break;
    default:
        break;
    }
}

void DistributionSession::_setLastUsed()
{
    m_lastUsed = std::chrono::system_clock::now();
}

void DistributionSession::_setHash()
{
    std::string json_str(m_createReqData->toJSON(true).serialise());
    m_hash = calculate_hash(std::vector<std::string::value_type>(json_str.begin(), json_str.end()));
}

void DistributionSession::_registerEvent(DistributionSessionEvents::EventTypeBitMask event_type)
{
    m_eventTimestamps.registerEvent(event_type);
    _sendSubscriptionNotifications();
}

void DistributionSession::_sendSubscriptionNotifications()
{
    for (auto &[subsc_id, subsc] : m_eventSubscriptions) {
        subsc.pushNotificationsEvent();
    }
}

void DistributionSession::_apiSessionCreate(Open5GSSBIStream &stream, Open5GSSBIMessage &message, Open5GSSBIRequest &request,
                           const std::optional<NfServer::InterfaceMetadata> &api,
                           const NfServer::AppMetadata &app_meta)
{
    /* static method */
    if (request.headerValue(OGS_SBI_CONTENT_TYPE, std::string()) != "application/json") {
        ogs_assert(true == NfServer::sendError(stream, ProblemCause::INVALID_MSG_FORMAT, 1, message, app_meta, api,
                                                "Unsupported Media Type", "Expected content type: application/json"));
        return;
    }

    CJson distSession(CJson::Null);
    try {
        distSession = CJson::parse(request.content());
    } catch (ModelException &ex) {
        send_model_error(ex, stream, 1, message, app_meta, api, "Bad Request",
                         "Unable to parse MBSTF Distribution Session as JSON");
        return;
    } catch (std::exception &ex) {
        static const char *err = "Unable to parse MBSTF Distribution Session as JSON.";
        ogs_error("%s", err);
        ogs_assert(true == NfServer::sendError(stream, ProblemCause::INVALID_MSG_FORMAT, 1, message, app_meta, api,
                                                "Bad MBSTF Distribution Session", err));
        return;
    }

    {
        std::string txt(distSession.serialise());
        ogs_debug("Request Parsed JSON: %s", txt.c_str());
    }

    std::shared_ptr<DistributionSession> distributionSession;
    try {
        distributionSession.reset(new DistributionSession(distSession, true));
        /* If a subscription came with the create request, add the subscription */
        const auto &dist_session = distributionSession->distributionSessionReqData()->getDistSession();
        const auto &opt_subsc = dist_session->getDistSessionSubscription();
        std::string subsc_id;
        if (opt_subsc) {
            subsc_id = distributionSession->addSubscription(opt_subsc.value());
            distributionSession->m_subscriptionLocation = std::format("{}/{}/subscriptions/{}", request.uri(), distributionSession->distributionSessionId(), subsc_id);
        }
    } catch (ModelException &err) {
        send_model_error(err, stream, 1, message, app_meta, api, "Bad Request",
                            "Error while populating MBSTF Distribution Session");
        return;
    } catch (std::exception &err) {
        char *error = ogs_msprintf("Error while populating MBSTF Distribution Session: %s", err.what());
        ogs_error("%s", error);
        ogs_assert(true == NfServer::sendError(stream, ProblemCause::INVALID_MSG_FORMAT, 1, message, app_meta, api,
                                                "Bad Request", error));
        ogs_free(error);
        return;
    }

    try {
        distributionSession->m_controller.reset(ControllerFactory::makeController(*distributionSession));
        if (!distributionSession->m_controller) {
            const std::string &mode = distributionSession->getObjectDistributionOperatingMode();
            char *error = ogs_msprintf("No handler found for objDistributionOperatingMode [%s]", mode.c_str());
            ogs_error("%s", error);
            ogs_assert(true == NfServer::sendError(stream, OGS_SBI_HTTP_STATUS_NOT_IMPLEMENTED, 1, message, app_meta, api,
                                                    "Not Implemented", error));
            ogs_free(error);
            return;
        }
    } catch (ModelException &err) {
        send_model_error(err, stream, 1, message, app_meta, api, "Bad Request",
                            "Error while populating MBSTF Distribution Session");
    } catch (std::exception &err) {
        ogs_error("Error while populating MBSTF Distribution Session: %s", err.what());
        char *error = ogs_msprintf("Invalid ObjDistributionData parameters [%s]", err.what());
        ogs_error("%s", error);
        ogs_assert(true == NfServer::sendError(stream, ProblemCause::INVALID_MSG_FORMAT, 1, message, app_meta, api,
                                                "Invalid ObjDistributionData parameters", error));
        ogs_free(error);
        return;
    }

    distributionSession->_transitionTo(distributionSession->getState().getValue());
    App::self().context()->addDistributionSession(distributionSession);

    // Subscribe to Events from the Controller - to be forwarded to DistributionSessionSubscriptions
    distributionSession->subscribeTo({ObjectIngester::IngestFailedEvent::event_name}, *distributionSession->m_controller);
    distributionSession->_sendSubscriptionNotifications();

    CJson create_rsp_data_json(distributionSession->json(false, true));
    std::string body(create_rsp_data_json.serialise());
    ogs_debug("Response Parsed JSON: %s", body.c_str());
    std::string location = std::format("{}/{}", request.uri(), distributionSession->distributionSessionId());
    std::optional<std::string> content_type;
    if (!body.empty()) {
        content_type = "application/json";
    }
    std::shared_ptr<Open5GSSBIResponse> response(NfServer::newResponse(location, content_type, distributionSession->generated(),
                                                                        distributionSession->hash().c_str(),
                                                                        App::self().context()->cacheControl.distMaxAge,
                                                                        std::nullopt, api, app_meta));
    ogs_assert(response);
    NfServer::populateResponse(response, body, OGS_SBI_HTTP_STATUS_CREATED);
    ogs_assert(true == Open5GSSBIServer::sendResponse(stream, *response));
}

void DistributionSession::_apiSessionDelete(Open5GSSBIStream &stream, Open5GSSBIMessage &message, Open5GSSBIRequest &request,
                           const std::optional<NfServer::InterfaceMetadata> &api,
                           const NfServer::AppMetadata &app_meta)
{
    try {
        App::self().context()->deleteDistributionSession(distributionSessionId());
        std::shared_ptr<Open5GSSBIResponse> response(NfServer::newResponse(std::nullopt, std::nullopt, std::nullopt,
                                                                            std::nullopt, 0, std::nullopt, api, app_meta));
        NfServer::populateResponse(response, "", OGS_SBI_HTTP_STATUS_NO_CONTENT);
        ogs_assert(true == Open5GSSBIServer::sendResponse(stream, *response));
    } catch (const std::out_of_range &e) {
        std::ostringstream err;
        err << "MBSTF Distribution Session [" << distributionSessionId() << "] does not exist.";
        ogs_error("%s", err.str().c_str());

        static const std::string param("{sessionId}");
        std::ostringstream reason;
        reason << "Invalid MBSTF Distribution Session identifier [" << distributionSessionId() << "]";
        std::map<std::string, std::string> invalid_params(NfServer::makeInvalidParams(param, reason.str()));

        ogs_assert(true == NfServer::sendError(stream, ProblemCause::SUBSCRIPTION_NOT_FOUND, 2, message, app_meta, api,
                                                "MBSTF Distribution Session not found", err.str(), std::nullopt, invalid_params));
    }
}

void DistributionSession::_apiSessionPatch(Open5GSSBIStream &stream, Open5GSSBIMessage &message, Open5GSSBIRequest &request,
                          const std::optional<NfServer::InterfaceMetadata> &api,
                          const NfServer::AppMetadata &app_meta)
{
    std::string content_type(message.contentType());
    if (content_type != OGS_SBI_CONTENT_PATCH_TYPE) {
        std::ostringstream err;
        err << "Content-Type [" << message.contentType() << "] unknown for PATCH method, expecting " OGS_SBI_CONTENT_PATCH_TYPE;
        ogs_error("%s", err.str().c_str());
        ogs_assert(true == NfServer::sendError(stream, ProblemCause::INVALID_MSG_FORMAT, 2, message, app_meta, api,
                                                "MBSTF Distribution Session patch bad MIME type", err.str()));
        return;
    }

    /* parse body */
    CJson patch_json(CJson::newNull());
    try {
        patch_json = CJson::parse(request.content());
    } catch (ModelException &err) {
        send_model_error(err, stream, 2, message, app_meta, api, "Message body is not valid JSON",
                            "MBSTF Distribution Session patch not valid JSON");
        return;
    }

    /* Apply patch */
    auto old_dist_sess = distributionSessionReqData();
    std::shared_ptr<reftools::mbstf::CreateReqData> new_dist_sess{};
    try {
        new_dist_sess.reset(old_dist_sess->newWithJSONPatches(patch_json));
    } catch (ModelException &err) {
        send_model_error(err, stream, 2, message, app_meta, api, "Unable to apply JSON Patch",
                            "MBSTF Distribution Session patch failed to apply");
        return;
    }

    /* New state is valid, replace old DistSession */
    try {
        distributionSessionReqData(new_dist_sess);
    } catch (ModelParamsException &ex) {
        ogs_error("%s", ex.what());
        send_model_params_error(ex, stream, 2, message, app_meta, api, "Invalid JSON Patch", "MBSTF Distribution Session patch");
        return;
    }

    CJson rsp_json = json(false);
    std::string body(rsp_json.serialise());
    ogs_debug("Generated JSON: %s", body.c_str());
    std::optional<std::string> rsp_content_type;
    if (!body.empty()) {
        rsp_content_type = "application/json";
    }
    std::shared_ptr<Open5GSSBIResponse> response(NfServer::newResponse(std::string(request.uri()), rsp_content_type, generated(),
                                                                hash().c_str(), App::self().context()->cacheControl.distMaxAge,
                                                                std::nullopt, api, app_meta));
    ogs_assert(response);
    NfServer::populateResponse(response, body, OGS_SBI_HTTP_STATUS_OK);
    ogs_assert(true == Open5GSSBIServer::sendResponse(stream, *response));
}

void DistributionSession::_apiSessionGet(Open5GSSBIStream &stream, Open5GSSBIMessage &message, Open5GSSBIRequest &request,
                        const std::optional<NfServer::InterfaceMetadata> &api,
                        const NfServer::AppMetadata &app_meta)
{
    CJson createdRspData_json(json(false));
    std::string body(createdRspData_json.serialise());
    ogs_debug("Generated JSON: %s", body.c_str());
    std::optional<std::string> content_type;
    if (!body.empty()) {
        content_type = "application/json";
    }
    std::shared_ptr<Open5GSSBIResponse> response(NfServer::newResponse(std::string(request.uri()), content_type, generated(),
                                                        hash().c_str(), App::self().context()->cacheControl.distMaxAge,
                                                        std::nullopt, api, app_meta));
    ogs_assert(response);
    NfServer::populateResponse(response, body, OGS_SBI_HTTP_STATUS_OK);
    ogs_assert(true == Open5GSSBIServer::sendResponse(stream, *response));
}

void DistributionSession::_apiSubscriptionCreate(Open5GSSBIStream &stream, Open5GSSBIMessage &message, Open5GSSBIRequest &request,
                                const std::optional<NfServer::InterfaceMetadata> &api,
                                const NfServer::AppMetadata &app_meta)
{
    if (request.headerValue(OGS_SBI_CONTENT_TYPE, std::string()) != "application/json") {
        ogs_assert(true == NfServer::sendError(stream, ProblemCause::INVALID_MSG_FORMAT, 1, message, app_meta, api,
                                                "Unsupported Media Type", "Expected content type: application/json"));
        return;
    }

    CJson dist_session_subsc_json(CJson::Null);
    std::string subsc_id;
    try {
        dist_session_subsc_json = CJson::parse(request.content());
        subsc_id = addSubscription(dist_session_subsc_json, true);
    } catch (ModelException &ex) {
        send_model_error(ex, stream, 4, message, app_meta, api, "Bad Request",
                            "Unable to parse MBSTF Distribution Session Subscription as JSON");
        return;
    } catch (std::exception &ex) {
        static const char *err = "Unable to parse MBSTF Distribution Session Subscription as JSON.";
        ogs_error("%s", err);
        ogs_assert(true == NfServer::sendError(stream, ProblemCause::INVALID_MSG_FORMAT, 4, message, app_meta, api,
                                                "Bad MBSTF Distribution Session Subscription", err));
        return;
    }

    const DistributionSessionSubscription *subsc = nullptr;
    try {
        subsc = &getSubscription(subsc_id);
    } catch (std::out_of_range &ex) {
        static const char *err = "Lost DistSession subscription after creation";
        ogs_error("%s", err);
        ogs_assert(true == NfServer::sendError(stream, ProblemCause::SYSTEM_FAILURE, 1, message, app_meta, api,
                                                  "Lost Distribution Session Subscription", err));
        return;
    }

    auto immediate_notifications = subsc->makeReportList();
    std::shared_ptr<DistSessionSubscription> api_subsc(new DistSessionSubscription(subsc->distSessionSubscription()));
    StatusSubscribeRspData rsp;
    rsp.setSubscription(api_subsc);
    if (!immediate_notifications->getEventReportList().empty()) {
        rsp.setReportList(immediate_notifications);
    }
    std::string rsp_body(rsp.toJSON(false).serialise());
    std::string location = std::format("{}/{}/subscriptions/{}", request.uri(), distributionSessionId(), subsc->subscriptionId());
    std::optional<std::string> content_type;
    if (!rsp_body.empty()) content_type = "application/json";
    std::shared_ptr<Open5GSSBIResponse> response(NfServer::newResponse(location, content_type, std::nullopt /* last-modified */,
                                                                        std::nullopt /* etag */,
                                                                        App::self().context()->cacheControl.distMaxAge,
                                                                        std::nullopt, api, app_meta));
    ogs_assert(response);
    NfServer::populateResponse(response, rsp_body, OGS_SBI_HTTP_STATUS_CREATED);
    ogs_assert(true == Open5GSSBIServer::sendResponse(stream, *response));
}

void DistributionSession::_apiSubscriptionDelete(const DistributionSessionSubscription &dist_sess_subsc,
                                Open5GSSBIStream &stream, Open5GSSBIMessage &message, Open5GSSBIRequest &request,
                                const std::optional<NfServer::InterfaceMetadata> &api,
                                const NfServer::AppMetadata &app_meta)
{
    removeSubscription(dist_sess_subsc.subscriptionId());
    std::shared_ptr<Open5GSSBIResponse> response(NfServer::newResponse(std::nullopt, std::nullopt, std::nullopt, std::nullopt, 0,
                                                                        std::nullopt, api, app_meta));
    ogs_assert(response);
    NfServer::populateResponse(response, std::string(), OGS_SBI_HTTP_STATUS_NO_CONTENT);
    ogs_assert(true == Open5GSSBIServer::sendResponse(stream, *response));
}

void DistributionSession::_apiSubscriptionPatch(const DistributionSessionSubscription &dist_sess_subsc,
                               Open5GSSBIStream &stream, Open5GSSBIMessage &message, Open5GSSBIRequest &request,
                               const std::optional<NfServer::InterfaceMetadata> &api,
                               const NfServer::AppMetadata &app_meta)
{
    CJson req_json(CJson::Null);
    try {
        req_json = CJson::parse(request.content());
        updateSubscription(dist_sess_subsc.subscriptionId(), req_json, true);
        std::string body(dist_sess_subsc.distSessionSubscription().toJSON(false).serialise());
        std::optional<std::string> content_type;
        if (!body.empty()) content_type = "application/json";
        std::shared_ptr<Open5GSSBIResponse> response(NfServer::newResponse(std::nullopt, content_type,
                                                                        std::nullopt /* last-modified */, std::nullopt /* etag */,
                                                                        App::self().context()->cacheControl.distMaxAge,
                                                                        std::nullopt, api, app_meta));
        ogs_assert(response);
        NfServer::populateResponse(response, body, OGS_SBI_HTTP_STATUS_OK);
        ogs_assert(true == Open5GSSBIServer::sendResponse(stream, *response));
    } catch (ModelException &ex) {
        send_model_error(ex, stream, 4, message, app_meta, api, "Bad Request",
                            "Unable to parse MBSTF Distribution Session Subscription Patch as JSON");
        return;
    } catch (std::exception &ex) {
        static const char *err = "Unable to parse MBSTF Distribution Session Subscription as JSON.";
        ogs_error("%s", err);
        ogs_assert(true == NfServer::sendError(stream, ProblemCause::INVALID_MSG_FORMAT, 1, message, app_meta, api,
                                                "Bad MBSTF Distribution Session Subscription", err));
        return;
    }
}

/**** Local private ****/

static std::shared_ptr<ObjDistributionData> get_object_distribution_data(const DistributionSession &distribution_session)
{
    std::shared_ptr<CreateReqData> create_req_data = distribution_session.distributionSessionReqData();
    std::shared_ptr<DistSession> dist_session = create_req_data->getDistSession();
    const std::optional<std::shared_ptr<ObjDistributionData> > &object_distribution_data = dist_session->getObjDistributionData();
    if (object_distribution_data.has_value()) {
        std::shared_ptr<ObjDistributionData> object_distribution_data_ptr = object_distribution_data.value();
        return object_distribution_data_ptr;
    } else {
        return nullptr;
    }

}

static void send_model_error(const ModelException &err, Open5GSSBIStream &stream, int path_segments, Open5GSSBIMessage &message,
                             const NfServer::AppMetadata &app_meta, const std::optional<NfServer::InterfaceMetadata> &api,
                             const std::string &no_cause_reason, const std::string &log_prefix)
{
    std::ostringstream error_oss;
    std::ostringstream oss;
    std::optional<std::map<std::string,std::string> > invalid_params = std::nullopt;

    if (!err.parameter.empty()) {
        invalid_params = std::map<std::string,std::string>{ {err.parameter, err.what()} };
        error_oss << err.parameter << ": ";
    }
    error_oss << err.what();
    const std::string &error = error_oss.str();

    if (err.cause) {
        auto cause = err.cause.value();
        oss << cause.reason() << ": " << error;
        ogs_assert(true == NfServer::sendError(stream, cause, path_segments, message, app_meta, api, cause.reason(), error, std::nullopt,
                                               invalid_params));
    } else {
        oss << no_cause_reason << ": " << error;
        ogs_assert(true == NfServer::sendError(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, path_segments, message, app_meta, api, no_cause_reason,
                                               error));
    }
    ogs_error("%s: %s", log_prefix.c_str(), oss.str().c_str());
}

static void send_model_params_error(const ModelParamsException &err, Open5GSSBIStream &stream, int path_segments,
                                    Open5GSSBIMessage &message, const NfServer::AppMetadata &app_meta,
                                    const std::optional<NfServer::InterfaceMetadata> &api, const std::string &no_cause_reason,
                                    const std::string &log_prefix)
{
    std::ostringstream error_oss;
    std::ostringstream oss;
    std::optional<std::map<std::string,std::string> > invalid_params = std::nullopt;

    error_oss << err.classname;
    if (!err.parameter.empty())
        error_oss << "." << err.parameter;
    error_oss << ": " << err.what();

    if (!err.invalidParams.empty()) {
        invalid_params = err.invalidParams;
        error_oss << std::endl << "Invalid parameters:";
        for (auto &[param, reason] : err.invalidParams) {
            error_oss << std::endl << "    " << param << ": " << reason;
        }
    }

    const std::string &error = error_oss.str();
    
    if (err.cause) {
        auto cause = err.cause.value();
        oss << cause.reason() << ": " << error;
        ogs_assert(true == NfServer::sendError(stream, cause, path_segments, message, app_meta, api, cause.reason(), error, std::nullopt,
                                               invalid_params));
    } else {
        oss << no_cause_reason << ": " << error;
        ogs_assert(true == NfServer::sendError(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, path_segments, message, app_meta, api, no_cause_reason,
                                               error));
    }
    ogs_error("%s: %s", log_prefix.c_str(), oss.str().c_str());
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
