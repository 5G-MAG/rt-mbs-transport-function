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
#include "hash.hh"
#include "MBSTFNetworkFunction.hh"
#include "ModelParamsException.hh"
#include "NfServer.hh"
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
#include "openapi/model/DistSession.h"
#include "openapi/model/DistSessionState.h"
#include "openapi/model/ObjDistributionData.h"
#include "openapi/model/ObjAcquisitionMethod.h"
#include "openapi/model/TunnelAddress.h"

#include "openapi/api/IndividualMBSDistributionSessionApi-info.h"
#include "TimerFunc.hh"

// Header include for this class
#include "DistributionSession.hh"

using fiveg_mag_reftools::CJson;
using fiveg_mag_reftools::ModelException;
using fiveg_mag_reftools::ProblemCause;
using reftools::mbstf::CreateReqData;
using reftools::mbstf::DistSession;
using reftools::mbstf::DistSessionState;
using reftools::mbstf::IpAddr;
using reftools::mbstf::ObjDistributionData;
using reftools::mbstf::UpTrafficFlowInfo;
using reftools::mbstf::ObjAcquisitionMethod;
using reftools::mbstf::ObjDistributionOperatingMode;
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
    :m_createReqData(std::make_shared<CreateReqData>(json, as_request))
    ,m_controller()
    //,m_eventSubscriptions()
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
    // TODO: if session is in ACTIVE state then send SESSION_DEACTIVED event to any event subscribers that are listening for it.
}

CJson DistributionSession::json(bool as_request = false) const
{
    return m_createReqData->toJSON(as_request);
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
                        std::string method(message.method());
                        const char *ptr_resource1 = message.resourceComponent(1);
                        if (method == OGS_SBI_HTTP_METHOD_POST) {
                            ogs_debug("POST response: status = %i", message.resStatus());
                            if (ptr_resource1) {
                                const char *ptr_resource2 = message.resourceComponent(2);
                                if (ptr_resource2) {
                                    std::string subresource(ptr_resource2);
                                    if (subresource == "subscriptions") {
                                        /* .../dist-sessions/{distSessionRef}/subscriptions */
                                        /* TODO: Implement create subscription operation */
                                        ogs_error("Attempt to use Distribution Session notifications");
                                        ogs_assert(true == NfServer::sendError(stream, OGS_SBI_HTTP_STATUS_NOT_IMPLEMENTED,
                                                                       3, message, app_meta, api,
                                                                       "Not Implemented", "Subscriptions not implemented yet"));
                                        return true;
                                    } else {
                                        std::ostringstream err;
                                        err << "Distribution Session [" << ptr_resource1 << "] sub resource [" << subresource
                                            << "] is not understood for POST method";
                                        ogs_error("%s", err.str().c_str());
                                        ogs_assert(true == NfServer::sendError(stream,
                                                                        ProblemCause::RESOURCE_URI_STRUCTURE_NOT_FOUND,
                                                                        3, message, app_meta, api, std::nullopt, err.str()));
                                        return true;
                                    }
                                } else {
                                    ogs_assert(true == NfServer::sendError(stream, OGS_SBI_HTTP_STATUS_MEHTOD_NOT_ALLOWED,
                                                                        2, message, app_meta, api, "Method not allowed",
                                                                        "Cannot POST to individual Distribution Sessions"));
                                    return true;
                                }
                            } else {
                                ogs_debug("In MBSTF Distribution session");
                                std::shared_ptr<DistributionSession> distributionSession;
                                ogs_debug("Request body: %s", request.content());
                                //ogs_debug("Request " OGS_SBI_CONTENT_TYPE ": %s", request.headerValue(OGS_SBI_CONTENT_TYPE, std::string()).c_str());
                                if (request.headerValue(OGS_SBI_CONTENT_TYPE, std::string()) != "application/json") {
                                    ogs_assert(true == NfServer::sendError(stream, ProblemCause::INVALID_MSG_FORMAT,
                                                                       1, message, app_meta, api, "Unsupported Media Type",
                                                                       "Expected content type: application/json"));
                                    return true;
                                }

                                CJson distSession(CJson::Null);
                                try {
                                    distSession = CJson::parse(request.content());
                                } catch (ModelException &ex) {
                                    send_model_error(ex, stream, 1, message, app_meta, api, "Bad Request",
                                                     "Unable to parse MBSTF Distribution Session as JSON");
                                    return true;
                                } catch (std::exception &ex) {
                                    static const char *err = "Unable to parse MBSTF Distribution Session as JSON.";
                                    ogs_error("%s", err);
                                    ogs_assert(true == NfServer::sendError(stream, ProblemCause::INVALID_MSG_FORMAT, 1, message,
                                                                        app_meta, api, "Bad MBSTF Distribution Session", err));
                                    return true;
                                }

                                {
                                    std::string txt(distSession.serialise());
                                    ogs_debug("Request Parsed JSON: %s", txt.c_str());
                                }

                                try {
                                    distributionSession.reset(new DistributionSession(distSession, true));
                                } catch (ModelException &err) {
                                    send_model_error(err, stream, 1, message, app_meta, api, "Bad Request",
                                                     "Error while populating MBSTF Distribution Session");
                                    return true;
                                } catch (std::exception &err) {
                                    char *error = ogs_msprintf("Error while populating MBSTF Distribution Session: %s", err.what());
                                    ogs_error("%s", error);
                                    ogs_assert(true == NfServer::sendError(stream, ProblemCause::INVALID_MSG_FORMAT, 1, message,
                                                                           app_meta, api, "Bad Request", error));
                                    ogs_free(error);
                                    return true;
                                }

                                try {

                                    distributionSession->m_controller.reset(ControllerFactory::makeController(*distributionSession));
                                    if(!distributionSession->m_controller) {
                                        const std::string &mode = distributionSession->getObjectDistributionOperatingMode();
                                        char *error = ogs_msprintf("No handler found for objDistributionOperatingMode [%s]",
                                                                   mode.c_str());
                                        ogs_error("%s", error);
                                        ogs_assert(true == NfServer::sendError(stream, OGS_SBI_HTTP_STATUS_NOT_IMPLEMENTED, 1,
                                                                               message, app_meta, api, "Not Implemented", error));
                                        ogs_free(error);
                                        return true;
                                    }
                                } catch (ModelException &err) {
                                    send_model_error(err, stream, 1, message, app_meta, api, "Bad Request",
                                                     "Error while populating MBSTF Distribution Session");
                                } catch (std::exception &err) {
                                    ogs_error("Error while populating MBSTF Distribution Session: %s", err.what());
                                    char *error = ogs_msprintf("Invalid ObjDistributionData parameters [%s]", err.what());
                                    ogs_error("%s", error);
                                    ogs_assert(true == NfServer::sendError(stream, ProblemCause::INVALID_MSG_FORMAT, 1, message,
                                                                           app_meta, api, "Invalid ObjDistributionData parameters",
                                                                           error));
                                    ogs_free(error);
                                    return true;
                                }

                                distributionSession->_transitionTo(distributionSession->getState().getValue());
                                

                                App::self().context()->addDistributionSession(distributionSession);

                                // TODO: Subscribe to Events from the Controller - to be forwarded to DistributionSessionSubscriptions

                                CJson createdReqData_json(distributionSession->json(false));
                                std::string body(createdReqData_json.serialise());
                                ogs_debug("Response Parsed JSON: %s", body.c_str());
                                std::ostringstream location;
                                location << request.uri() << "/" << distributionSession->distributionSessionId();
                                std::shared_ptr<Open5GSSBIResponse> response(NfServer::newResponse(location.str(),
                                                                                        body.empty()?nullptr:"application/json",
                                                                                        distributionSession->generated(),
                                                                                        distributionSession->hash().c_str(),
                                                                                        App::self().context()->cacheControl.distMaxAge,
                                                                                        std::nullopt/*nullptr*/, api, app_meta));
                                ogs_assert(response);
                                NfServer::populateResponse(response, body, OGS_SBI_HTTP_STATUS_CREATED);
                                ogs_assert(true == Open5GSSBIServer::sendResponse(stream, *response));
                                return true;
                            }
                        } else if (method == OGS_SBI_HTTP_METHOD_GET) {
                            if (!ptr_resource1) {
                                std::ostringstream err;
                                err << "Invalid method for resource [" << message.uri() << "]";
                                ogs_error("%s", err.str().c_str());
                                ogs_assert(true == NfServer::sendError(stream, OGS_SBI_HTTP_STATUS_MEHTOD_NOT_ALLOWED, 1,
                                                                       message, app_meta, api, "Method Not Allowed", err.str()));
                                return true;
                            }
                            std::string dist_session_id(ptr_resource1);
                            try {
                                int response_code = OGS_SBI_HTTP_STATUS_OK;

                                std::shared_ptr<DistributionSession> distSess = DistributionSession::find(dist_session_id);
                                CJson createdReqData_json(distSess->json(false));
                                std::string body(createdReqData_json.serialise());
                                ogs_debug("Generated JSON: %s", body.c_str());
                                std::shared_ptr<Open5GSSBIResponse> response(NfServer::newResponse(std::string(request.uri()),
                                                        body.empty()?nullptr:"application/json",
                                                        distSess->generated(),
                                                        distSess->hash().c_str(),
                                                        App::self().context()->cacheControl.distMaxAge,
                                                        std::nullopt/*nullptr*/, api, app_meta));
                                ogs_assert(response);
                                NfServer::populateResponse(response, body, response_code);
                                ogs_assert(true == Open5GSSBIServer::sendResponse(stream, *response));
                            } catch (const std::out_of_range &e) {
                                std::ostringstream err;
                                err << "MBSTF Distribution Session [" << dist_session_id << "] does not exist.";
                                ogs_error("%s", err.str().c_str());

                                static const std::string param("{sessionId}");
                                std::ostringstream reason;
                                reason << "Invalid MBSTF Distribution Session identifier [" << dist_session_id << "]";
                                std::map<std::string, std::string> invalid_params(
                                                                            NfServer::makeInvalidParams(param, reason.str()));

                                ogs_assert(true == NfServer::sendError(stream, ProblemCause::SUBSCRIPTION_NOT_FOUND, 2, message,
                                                                        app_meta, api, "MBSTF Distribution Session not found",
                                                                        err.str(), std::nullopt, invalid_params));
                            }
                            return true;
                        } else if (method == OGS_SBI_HTTP_METHOD_DELETE) {
                            if (ptr_resource1 && !message.resourceComponent(2)) {
                                std::string dist_session_id(ptr_resource1);
                                try {
                                    App::self().context()->deleteDistributionSession(dist_session_id);
                                    std::shared_ptr<Open5GSSBIResponse> response(NfServer::newResponse(std::nullopt, std::nullopt,
                                                                std::nullopt, std::nullopt, 0, std::nullopt, api, app_meta));
                                    NfServer::populateResponse(response, "", OGS_SBI_HTTP_STATUS_NO_CONTENT);
                                    ogs_assert(true == Open5GSSBIServer::sendResponse(stream, *response));
                                } catch (const std::out_of_range &e) {
                                    std::ostringstream err;
                                    err << "MBSTF Distribution Session [" << dist_session_id << "] does not exist.";
                                    ogs_error("%s", err.str().c_str());

                                    static const std::string param("{sessionId}");
                                    std::ostringstream reason;
                                    reason << "Invalid MBSTF Distribution Session identifier [" << dist_session_id << "]";
                                    std::map<std::string, std::string> invalid_params(NfServer::makeInvalidParams(param,
                                                                 reason.str()));

                                    ogs_assert(true == NfServer::sendError(stream, ProblemCause::SUBSCRIPTION_NOT_FOUND, 2, message,
                                                            app_meta, api, "MBSTF Distribution Session not found", err.str(),
                                                            std::nullopt, invalid_params));
                                }
                            } else {
                                ogs_assert(true == NfServer::sendError(stream, OGS_SBI_HTTP_STATUS_MEHTOD_NOT_ALLOWED, 2,
                                                            message, app_meta, api, "Method Not Allowed",
                                                            "The DELETE method is not allowed for this path"));
                            }
                            return true;
                        } else if (method == OGS_SBI_HTTP_METHOD_PATCH) {
                            if (!ptr_resource1) {
                                static const char *err = "MBSTF Distribution Session update operation without distSessionId";
                                ogs_error("%s", err);
                                static const std::string param("{sessionId}");
                                std::map<std::string, std::string> invalid_params(NfServer::makeInvalidParams(param,
                                                            "Missing MBSTF Distribution Session identifier"));
                                ogs_assert(true == NfServer::sendError(stream, ProblemCause::SUBSCRIPTION_NOT_FOUND, 1, message,
                                                            app_meta, api, "MBSTF Distribution Session not found", err,
                                                            std::nullopt, invalid_params));
                                return true;
                            }
                            std::string dist_session_id(ptr_resource1);
                            std::shared_ptr<DistributionSession> distSess{};
                            try {
                                distSess = DistributionSession::find(dist_session_id);
                            } catch (const std::out_of_range &e) {
                                std::ostringstream err;
                                err << "MBSTF Distribution Session [" << dist_session_id << "] does not exist.";
                                ogs_error("%s", err.str().c_str());

                                static const std::string param("{sessionId}");
                                std::ostringstream reason;
                                reason << "Invalid MBSTF Distribution Session identifier [" << dist_session_id << "]";
                                std::map<std::string, std::string> invalid_params(
                                                                            NfServer::makeInvalidParams(param, reason.str()));

                                ogs_assert(true == NfServer::sendError(stream, ProblemCause::SUBSCRIPTION_NOT_FOUND, 2, message,
                                                                        app_meta, api, "MBSTF Distribution Session not found",
                                                                        err.str(), std::nullopt, invalid_params));
                                return true;
                            }
                            const char *ptr_resource2 = message.resourceComponent(2);
                            if (ptr_resource2) {
                                std::ostringstream err;
                                err << "MBSTF Distribution Session [" << dist_session_id << "] sub resource [" << ptr_resource2 << "] not understood for PATCH method.";
                                ogs_error("%s", err.str().c_str());
                                ogs_assert(true == NfServer::sendError(stream, ProblemCause::INVALID_API, 3, message,
                                                            app_meta, api, "MBSTF Distribution Session invalid sub resource",
                                                            err.str()));
                                return true;
                            }

                            /* check MIME type */
                            std::string content_type(message.contentType());
                            if (content_type != OGS_SBI_CONTENT_PATCH_TYPE) {
                                std::ostringstream err;
                                err << "Content-Type [" << message.contentType() << "] unknown for PATCH method, expecting " OGS_SBI_CONTENT_PATCH_TYPE;
                                ogs_error("%s", err.str().c_str());
                                ogs_assert(true == NfServer::sendError(stream, ProblemCause::INVALID_MSG_FORMAT, 2, message,
                                                            app_meta, api, "MBSTF Distribution Session patch bad MIME type",
                                                            err.str()));
                                return true;
                            }

                            /* parse body */
                            CJson json(CJson::newNull());
                            try {
                                json = CJson::parse(request.content());
                            } catch (ModelException &err) {
                                send_model_error(err, stream, 2, message, app_meta, api, "Message body is not valid JSON",
                                                       "MBSTF Distribution Session patch not valid JSON");
                                return true;
                            }

                            /* Apply patch */
                            auto oldDistSess = distSess->distributionSessionReqData();
                            std::shared_ptr<reftools::mbstf::CreateReqData> newDistSess{};
                            try {
                                newDistSess.reset(oldDistSess->newWithJSONPatches(json));
                            } catch (ModelException &err) {
                                send_model_error(err, stream, 2, message, app_meta, api, "Unable to apply JSON Patch",
                                                         "MBSTF Distribution Session patch failed to apply");
                                return true;
                            }

                            /* New state is valid, replace old DistSession */
                            try {
                                distSess->distributionSessionReqData(newDistSess);
                            } catch (ModelParamsException &ex) {
                                ogs_error("%s", ex.what());
                                send_model_params_error(ex, stream, 2, message, app_meta, api, "Invalid JSON Patch",
                                                        "MBSTF Distribution Session patch");
                                return true;
                            }
                            json = distSess->json(false);
                            std::string body(json.serialise());
                            ogs_debug("Generated JSON: %s", body.c_str());
                            std::shared_ptr<Open5GSSBIResponse> response(NfServer::newResponse(std::string(request.uri()),
                                                        body.empty()?nullptr:"application/json",
                                                        distSess->generated(),
                                                        distSess->hash().c_str(),
                                                        App::self().context()->cacheControl.distMaxAge,
                                                        std::nullopt, api, app_meta));
                            ogs_assert(response);
                            NfServer::populateResponse(response, body, OGS_SBI_HTTP_STATUS_OK);
                            ogs_assert(true == Open5GSSBIServer::sendResponse(stream, *response));
                            return true;
                        } else if (method == OGS_SBI_HTTP_METHOD_OPTIONS) {
                            if (ptr_resource1) {
                                const char *ptr_resource2 = message.resourceComponent(2);
                                if (ptr_resource2) {
                                    std::string resource2(ptr_resource2);
                                    if (resource2 == "subscriptions") {
                                        std::shared_ptr<Open5GSSBIResponse> response(NfServer::newResponse(std::nullopt, std::nullopt, std::nullopt, std::nullopt, 0, /*OGS_SBI_HTTP_METHOD_POST ", " OGS_SBI_HTTP_METHOD_DELETE ", " */ OGS_SBI_HTTP_METHOD_OPTIONS, api, app_meta));
                                        NfServer::populateResponse(response, "", OGS_SBI_HTTP_STATUS_NO_CONTENT);
                                        ogs_assert(true == Open5GSSBIServer::sendResponse(stream, *response));
                                    } else {
                                        ogs_assert(true == NfServer::sendError(stream,
                                                            ProblemCause::RESOURCE_URI_STRUCTURE_NOT_FOUND, 3, message,
                                                            app_meta, api, "Not found", "Resource path not known"));
                                    }
                                } else {
                                    /* .../dist-sessions/{distSessionRef} */
                                    std::shared_ptr<Open5GSSBIResponse> response(NfServer::newResponse(std::nullopt, std::nullopt, std::nullopt, std::nullopt, 0, OGS_SBI_HTTP_METHOD_GET ", " OGS_SBI_HTTP_METHOD_DELETE ", " OGS_SBI_HTTP_METHOD_PATCH ", " OGS_SBI_HTTP_METHOD_OPTIONS, api, app_meta));
                                    NfServer::populateResponse(response, "", OGS_SBI_HTTP_STATUS_NO_CONTENT);
                                    ogs_assert(true == Open5GSSBIServer::sendResponse(stream, *response));
                                }
                            } else {
                                /* .../dist-sessions */
                                std::shared_ptr<Open5GSSBIResponse> response(NfServer::newResponse(std::nullopt, std::nullopt, std::nullopt, std::nullopt, 0, OGS_SBI_HTTP_METHOD_POST ", " OGS_SBI_HTTP_METHOD_OPTIONS, api, app_meta));
                                NfServer::populateResponse(response, "", OGS_SBI_HTTP_STATUS_NO_CONTENT);
                                ogs_assert(true == Open5GSSBIServer::sendResponse(stream, *response));
                            }
                            return true;
                        } else {
                            std::ostringstream err;

                            err << "Invalid method [" << message.method() << "] for " << request.uri();
                            ogs_error("%s", err.str().c_str());
                            ogs_assert(true == NfServer::sendError(stream, OGS_SBI_HTTP_STATUS_MEHTOD_NOT_ALLOWED, 1, message,
                                                                    app_meta, api, "Method Not Allowed", err.str()));
                            return true;
                        }
                    } else {
                        std::ostringstream err;
                        err << "Unknown object type \"" << resource0 << "\" in MBSTF Distribution Session API";
                        ogs_error("%s", err.str().c_str());
                        ogs_assert(true == NfServer::sendError(stream, ProblemCause::RESOURCE_URI_STRUCTURE_NOT_FOUND, 1, message,
                                                            app_meta, api, "Bad request", err.str()));
                        return true;
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
