/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Push Object Ingester
 ******************************************************************************
 * Copyright: (C)2025 British Broadcasting Corporation
 * Author(s): Dev Audsin <dev.audsin@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include <arpa/inet.h>
#include <sys/socket.h>

#include <memory>
#include <stdexcept>
#include <utility>
#include <chrono>
#include <iostream>
#include <string>

#include <microhttpd.h>
#include <netdb.h>
#include <uuid/uuid.h>

#include "common.hh"
#include "App.hh"
#include "hash.hh"
#include "ObjectListController.hh"
#include "ObjectStore.hh"

#include "PushObjectIngester.hh"

MBSTF_NAMESPACE_START

//static MHD_Result gatherHeaders(void *cls, MHD_ValueKind kind, char const *key, char const *value);
static void request_completion_callback(void *cls, struct MHD_Connection *connection, void **con_cls,
                                        enum MHD_RequestTerminationCode termination_code);
static MHD_Result handle_request(void *cls, struct MHD_Connection *connection, const char *url, const char *method,
                                 const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls);
static std::optional<PushObjectIngester::Request::time_type> parse_http_date_time(const std::optional<std::string> &date_time_str);

/********************** PushObjectIngester::Request ***********************/

PushObjectIngester::Request::Request(struct MHD_Connection *mhd_connection, PushObjectIngester &poi)
    :m_mhdConnection(mhd_connection)
    ,m_mhdResponse(nullptr)
    ,m_pushObjectIngester(poi)
    ,m_objectId()
    ,m_method()
    ,m_urlPath()
    ,m_protocolVersion()
    ,m_etag()
    ,m_contentType()
    ,m_expires()
    ,m_lastModified()
    ,m_bodyBlocks()
    ,m_totalBodySize(0)
    ,m_statusCode(0)
    ,m_errorReason()
    ,m_noMoreBodyData(false)
    ,m_mutex(new std::recursive_mutex)
    ,m_condVar()
{
}

bool PushObjectIngester::Request::addBodyBlock(const std::vector<unsigned char> &body_block)
{
    std::lock_guard<std::recursive_mutex> lock(*m_mutex);
    m_bodyBlocks.push_back(body_block);
    m_totalBodySize += body_block.size();

    return true;
}

void PushObjectIngester::Request::completed(struct MHD_Connection *connection,
                                            enum MHD_RequestTerminationCode term_code)
{
    std::lock_guard<std::recursive_mutex> lock(*m_mutex);

    ogs_debug("PushObjectIngester::Request::terminated(%p, %u)", connection, term_code);
    ogs_info("End of request for %s", std::string(m_urlPath).c_str());
    m_noMoreBodyData = true;
    m_condVar.notify_all();
    // if (term_code != MHD_REQUEST_TERMINATED_COMPLETED_OK) m_pushObjectIngester.emitObjectIngestFailedEvent();
}

bool PushObjectIngester::Request::setError(unsigned int status_code, const std::string &reason)
{
    if (m_noMoreBodyData) return false;
    m_statusCode = status_code;
    m_errorReason = reason;
    return true;
}

std::optional<std::string> PushObjectIngester::Request::getHeader(const std::string &field) const
{
    std::lock_guard<std::recursive_mutex> lock(*m_mutex);

    const char *ret = MHD_lookup_connection_value(m_mhdConnection, MHD_HEADER_KIND, field.c_str());

    if (ret == nullptr) {
        return std::nullopt; // No value found
    }

    return std::string(ret); // Wrap the string in std::optional
}

void PushObjectIngester::Request::processRequest()
{
    auto now = std::chrono::system_clock::now();
    static const std::string app_octet("application/octet-stream");
    const auto &last_modified = m_lastModified.value_or(now);
    const auto &content_type = m_contentType.value_or(app_octet);

    std::string url(m_urlPath);
    if (url.front() == '/') {
        url = m_pushObjectIngester.getIngestServerPrefix() + url.substr(1,url.size()-1);
    }

    std::optional<std::string> object_distrib_base_url = std::nullopt;
    try {
        ObjectController &control(dynamic_cast<ObjectController&>(m_pushObjectIngester.controller()));
        object_distrib_base_url = control.getObjectDistributionBaseUrl();
    } catch (std::bad_cast &ex) {
        // Ignore bad cast, we just won't set the distribution base url if this happens
    }

    {
        std::ostringstream oss;
        oss << "Object transferring to ObjectStore: content-type=" << content_type << ", url=" << url << ", id=" << m_urlPath << ", modified=" << last_modified;
        ogs_debug("%s", oss.str().c_str());
    }

    ObjectStore::Metadata metadata(m_objectId, content_type, url, url, m_urlPath, last_modified, m_pushObjectIngester.getIngestServerPrefix(), object_distrib_base_url);
    metadata.cacheExpires(m_expires?m_expires.value():(std::chrono::system_clock::now() + std::chrono::minutes(ObjectStore::Metadata::cacheExpiry())));

    // Pull all body blocks together into one vector
    std::vector<unsigned char> body;
    ogs_debug("Building body of %zu bytes", m_totalBodySize);
    body.reserve(m_totalBodySize);
    for (auto& block : m_bodyBlocks) {
        ogs_debug("Adding body block of %zu bytes", block.size());
        body.insert(body.end(), block.begin(), block.end());
    }

    if (m_objectId.empty()) {
        m_objectId = m_pushObjectIngester.controller().nextObjectId();
    }

    m_pushObjectIngester.objectStore().addObject(m_objectId, std::move(body), std::move(metadata));
    m_statusCode = 200;
}

void PushObjectIngester::Request::requestHandler(struct MHD_Connection *connection)
{
    std::lock_guard<std::recursive_mutex> lock(*m_mutex);
    m_mhdConnection = connection;
    m_mhdResponse = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);

    ogs_debug("Request::requestHandler: url = %s, method = %s", m_urlPath.c_str(), m_method.c_str());

    //if (m_urlPath.substr(0, 4) != "http" || m_urlPath.substr(0, 2) == "//") {
    //    setError(404, "Not Found");
    //} else
    if (m_method != "PUSH" && m_method != "PUT" && m_method != "POST") {
        setError(405, "Method Not Allowed");
    } else {
        processRequest();
    }

    if (m_statusCode >= 400 && m_statusCode <= 499) {
        m_pushObjectIngester.emitObjectIngestFailedEvent(m_urlPath, ObjectIngester::IngestFailedEvent::CLIENT_ERROR);
    } else if (m_statusCode >= 500 && m_statusCode <= 599) {
        m_pushObjectIngester.emitObjectIngestFailedEvent(m_urlPath, ObjectIngester::IngestFailedEvent::SERVER_ERROR);
    }

    ogs_info("Queue response (%u) for %s to microhttpd", m_statusCode, m_urlPath.c_str());
    // Queue the request
    MHD_queue_response(connection, m_statusCode, m_mhdResponse);
    MHD_destroy_response(m_mhdResponse);
}

/********************** PushObjectIngester::ObjectPushEvent ***************/

PushObjectIngester::ObjectPushEvent *PushObjectIngester::ObjectPushEvent::makeStartEvent(const std::shared_ptr<Request> &request)
{
    return new PushObjectIngester::ObjectPushEvent("ObjectPushStart", request);
}

PushObjectIngester::ObjectPushEvent *PushObjectIngester::ObjectPushEvent::makeBlockReceivedEvent(const std::shared_ptr<Request> &request)
{
    return new PushObjectIngester::ObjectPushEvent("ObjectPushBlockReceived", request);
}

PushObjectIngester::ObjectPushEvent *PushObjectIngester::ObjectPushEvent::makeTrailersReceivedEvent(const std::shared_ptr<Request> &request)
{
    return new PushObjectIngester::ObjectPushEvent("ObjectPushTrailersReceived", request);
}

PushObjectIngester::ObjectPushEvent::~ObjectPushEvent()
{
}

PushObjectIngester::ObjectPushEvent::ObjectPushEvent(const std::string &typ, const std::shared_ptr<Request> &request)
    :Event(typ)
    ,m_request(request)
{
}

/********************** PushObjectIngester ********************************/

PushObjectIngester::~PushObjectIngester()
{
    abort(); // Stop the worker thread first
    stop();  // Then stop the HTTP daemon
}

bool PushObjectIngester::start()
{
    if (m_mhdDaemon) return false;

    ogs_info("PushObjectIngester[%p]::start(): Starting MHD", this);
    m_sockaddr.ss_family = AF_INET;
    struct sockaddr_in *sockaddr = reinterpret_cast<struct sockaddr_in *>(&m_sockaddr);
    sockaddr->sin_addr.s_addr = INADDR_ANY; // TODO: get this from a configuration file variable (default: INADDR_ANY)
    sockaddr->sin_port = htons(0);

    {
        std::lock_guard<std::recursive_mutex> lock(m_mtx);
        m_mhdDaemon = MHD_start_daemon(
                                    MHD_USE_SELECT_INTERNALLY,
                                    0,
                                    NULL, NULL,
                                    handle_request, this,
                                    MHD_OPTION_NOTIFY_COMPLETED, request_completion_callback, this,
                                    MHD_OPTION_SOCK_ADDR, (union MHD_DaemonInfo *)sockaddr,
                                    MHD_OPTION_END
                                    );
        m_condVar.notify_all();
        // emitObjectPushListeningEvent();
    }
    ogs_debug("PushObjectIngester[%p]::start(): Started MHD (%p)", this, m_mhdDaemon);

    return m_mhdDaemon != 0;
}

bool PushObjectIngester::stop()
{
    std::lock_guard<std::recursive_mutex> lock(m_mtx);

    ogs_debug("PushObjectIngester[%p]::stop(): Stopping MHD (%p)", this, m_mhdDaemon);

    if (m_mhdDaemon == 0) return false;

    MHD_stop_daemon(m_mhdDaemon);
    // emitObjectPushClosedEvent();

    m_activeRequests.clear();

    // Forget the old daemon
    m_mhdDaemon = 0;

    return true;
}

bool PushObjectIngester::addRequest(const std::shared_ptr<PushObjectIngester::Request> &req)
{
    {
        std::lock_guard<std::recursive_mutex> lock(m_mtx);
        m_activeRequests.push_back(req);
        ogs_debug( "Added new request, there are now %ld active requests", m_activeRequests.size());
    }
    ObjectPushEvent *evt = ObjectPushEvent::makeStartEvent(req);
    bool result = sendEventSynchronous(*evt);
    if (result) {
        ogs_debug("Request accepted, receiving...");
    }
    delete evt;
    return result;
}

void PushObjectIngester::removeRequest(const std::shared_ptr<PushObjectIngester::Request> &req)
{

    std::lock_guard<std::recursive_mutex> lock(m_mtx);
    for (std::list<std::shared_ptr<PushObjectIngester::Request> >::iterator it = m_activeRequests.begin();
         it != m_activeRequests.end();
         ++it) {
        if (*it == req) {
            it = m_activeRequests.erase(it);
            ogs_info("Removing request. There are now %ld active requests.", m_activeRequests.size());
            break;
        }
    }
}

void PushObjectIngester::doObjectIngest() {
    if (!workerCancelled() && start()) {
        // Once we've started the Push server we don't need this thread anymore
        abort();
    }
}

void PushObjectIngester::addedBodyBlock(const std::shared_ptr<Request> &request, std::vector<unsigned char>::size_type block_size,
                        std::vector<unsigned char>::size_type body_size)
{
    std::shared_ptr<Event> evt(ObjectPushEvent::makeBlockReceivedEvent(request));
    sendEventAsynchronous(evt);
}

const std::string &PushObjectIngester::getIngestServerPrefix()
{
    if (m_urlPrefix.empty()) {
        {
            // Wait for microhttpd to start up
            std::lock_guard<std::recursive_mutex> lock(m_mtx);
            while(!m_mhdDaemon) m_condVar.wait(m_mtx);
        }

        // Get the server details from microhttpd
        const union MHD_DaemonInfo *daemon_info = MHD_get_daemon_info(m_mhdDaemon, MHD_DAEMON_INFO_LISTEN_FD);
        if (daemon_info != nullptr && daemon_info->listen_fd != -1) {
            int sock_fd = daemon_info->listen_fd;
            socklen_t addr_len = sizeof(m_sockaddr);
            if (getsockname(sock_fd, reinterpret_cast<struct sockaddr*>(&m_sockaddr), &addr_len) == 0) {
                switch(m_sockaddr.ss_family ) {
                case AF_INET:
                    {
                        struct sockaddr_in *sin = reinterpret_cast<struct sockaddr_in*>(&m_sockaddr);
                        m_port = ntohs(sin->sin_port);
                        // If bind address is ANY, use the default route local address
                        if (sin->sin_addr.s_addr == INADDR_ANY) {
                            int def_route_sock = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, 0);
                            static const struct sockaddr_in known_public_ipv4 = {
                                .sin_family=AF_INET,
                                .sin_port=htons(53),
                                .sin_addr={static_cast<in_addr_t>(0x08080808)} /* 8.8.8.8 (dns.google.com) */
                            };
                            struct sockaddr_in local_def_route;
                            socklen_t local_def_route_len = sizeof(local_def_route);
                            connect(def_route_sock, reinterpret_cast<const struct sockaddr*>(&known_public_ipv4),
                                        sizeof(known_public_ipv4));
                            getsockname(def_route_sock, reinterpret_cast<struct sockaddr*>(&local_def_route),
                                        &local_def_route_len);
                            close(def_route_sock);
                            sin->sin_addr.s_addr = local_def_route.sin_addr.s_addr;
                        }
                    }
                    break;
                case AF_INET6:
                    {
                        struct sockaddr_in6 *sin6 = reinterpret_cast<struct sockaddr_in6*>(&m_sockaddr);
                        m_port = ntohs(sin6->sin6_port);
                        // If bind address is ANY, use the default route local address
                        if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
                            int def_route_sock = socket(AF_INET6, SOCK_DGRAM|SOCK_CLOEXEC, 0);
                            static const struct sockaddr_in6 known_public_ipv6 = {
                                .sin6_family=AF_INET6,
                                .sin6_port=htons(53),
                                .sin6_addr={ { { 0x20,0x01,0x48,0x60,0x48,0x60,0,0,0,0,0,0,0,0,0x88,0x88 } } } /* 2001:4860:4860::8888 (dns.google.com) */
                            };
                            struct sockaddr_in6 local_def_route;
                            socklen_t local_def_route_len = sizeof(local_def_route);
                            connect(def_route_sock, reinterpret_cast<const struct sockaddr*>(&known_public_ipv6),
                                        sizeof(known_public_ipv6));
                            getsockname(def_route_sock, reinterpret_cast<struct sockaddr*>(&local_def_route),
                                        &local_def_route_len);
                            close(def_route_sock);
                            memcpy(&sin6->sin6_addr, &local_def_route.sin6_addr, sizeof(struct in6_addr));
                        }
                    }
                    break;
                default:
                    ogs_error("The Push Server address family not understood %i", m_sockaddr.ss_family);
                    m_urlPrefix.clear();
                    return m_urlPrefix;
                }
                ogs_info("PUSH SERVER PORT: %d", m_port);

                // Get the IP address
                char host[NI_MAXHOST];
                if (getnameinfo(reinterpret_cast<struct sockaddr*>(&m_sockaddr), addr_len, host, sizeof(host), nullptr, 0, 0) == 0) {
                    m_domain = host;
                }
                if (getnameinfo(reinterpret_cast<struct sockaddr*>(&m_sockaddr), addr_len, host, sizeof(host), nullptr, 0, NI_NUMERICHOST) == 0) {
                    m_IPAddress = host;
                }
                if (!m_domain.empty()) {
                    m_urlPrefix = "http://" + m_domain + ":" + std::to_string(m_port) + "/";
                } else if (!m_IPAddress.empty()) {
                    m_urlPrefix = "http://" + m_IPAddress + ":" + std::to_string(m_port) + "/";
                } else {
                    ogs_error("getnameinfo error: %d", errno);
                }
            }
        } else {
            ogs_error("Failed to get daemon info from microhttpd");
        }
    }

    return m_urlPrefix;
}

/********* private functions **********/

#if 0
static MHD_Result gatherHeaders(void *cls, MHD_ValueKind kind, char const *key, char const *value)
{
    std::list<std::pair<std::string, std::string> > *headers =
        reinterpret_cast<std::list<std::pair<std::string, std::string> >*>(cls);

    headers->push_back(std::make_pair(std::string(key), std::string(value)));

    return MHD_YES;
}
#endif

static void request_completion_callback(void *cls, struct MHD_Connection *connection, void **con_cls, enum MHD_RequestTerminationCode termination_code)
{
    PushObjectIngester *ingester = reinterpret_cast<PushObjectIngester*>(cls);

    // Convert *con_cls into a shared pointer
    std::shared_ptr<PushObjectIngester::Request> &req = *reinterpret_cast<std::shared_ptr<PushObjectIngester::Request>*>(*con_cls);

    ogs_debug("request_completion_callback[%u]", termination_code);

    req->completed(connection, termination_code);

    ingester->removeRequest(req);

    delete reinterpret_cast<std::shared_ptr<PushObjectIngester::Request>*>(*con_cls);
    *con_cls = nullptr;
}

static MHD_Result handle_request(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls)
{
    PushObjectIngester *ingester = reinterpret_cast<PushObjectIngester*>(cls);
    ogs_debug("handle_request[%p, %p, %s, %s, %s, %p, %lu, %p]", cls, connection, url, method, version, upload_data, *upload_data_size, *con_cls);

    if (*con_cls == nullptr) {
        ogs_debug("handle_request: creating new PushObjectIngester::Request('%s', '%s', '%s')", url, method, version);
        PushObjectIngester::Request *req = new PushObjectIngester::Request(connection, *ingester);
        req->urlPath(url);
        req->method(method);
        req->protocolVersion(version);
        req->etag(req->getHeader("ETag"));
        req->contentType(req->getHeader("Content-Type"));
        std::optional<std::string> cache_control(req->getHeader("Cache-Control"));
        if (cache_control) {
            const std::string &cache_control_value(cache_control.value());
            if (cache_control_value.starts_with("max-age=")) {
                std::optional<std::string> age(req->getHeader("Age"));
                unsigned long max_age = std::stoul(cache_control_value.substr(8,cache_control_value.size()-8));
                if (age) {
                    unsigned long age_val = std::stoul(age.value());
                    if (age_val >= max_age) {
                        max_age = 0;
                    } else {
                        max_age -= age_val;
                    }
                }
                req->expiryTime(std::chrono::system_clock::now() + std::chrono::seconds(max_age));
            }
        }
        req->lastModified(parse_http_date_time(req->getHeader("Last-Modified")));
        std::shared_ptr<PushObjectIngester::Request> *req_ptr = new std::shared_ptr<PushObjectIngester::Request>(req);
        *con_cls = req_ptr;
        if(ingester->addRequest(*req_ptr)) return MHD_YES;
        return MHD_NO;
    }

    std::shared_ptr<PushObjectIngester::Request> req = *reinterpret_cast<std::shared_ptr<PushObjectIngester::Request>*>(*con_cls);

    if (*upload_data_size > 0) {
        ogs_debug("handle_request: Adding %zu bytes of ingest data", *upload_data_size);
        req->addBodyBlock(std::vector<unsigned char>(upload_data, upload_data + *upload_data_size));
        ingester->addedBodyBlock(req, *upload_data_size, req->bodySize());
        *upload_data_size = 0;
    } else if (*upload_data_size == 0) {
        ogs_debug("handle_request: Completed request processing.");
        ogs_info("Received client %s request for %s", method, url);
        req->requestHandler(connection);
    } else if (*upload_data_size < 0) {
        ogs_info("handle_request: Request cancelled.");
        *upload_data_size = 0;
        return MHD_NO;
    }

    ogs_debug("handle_request: Request processed.");

    return MHD_YES;
}

static std::optional<PushObjectIngester::Request::time_type> parse_http_date_time(const std::optional<std::string> &date_time_str)
{
    if (!date_time_str.has_value()) return std::nullopt;

    PushObjectIngester::Request::time_type date_time;
    std::istringstream iss(date_time_str.value());
    iss.imbue(std::locale("C"));
    iss >> std::chrono::parse("%a, %d %b %Y %H:%M:%S GMT", date_time); // RFC822/RFC1123
    if (iss.fail()) {
        iss.str(date_time_str.value());
        iss >> std::chrono::parse("%A, %d-%b-%y %H:%M:%S GMT", date_time); // RFC1036
        if (iss.fail()) {
            iss.str(date_time_str.value());
            iss >> std::chrono::parse("%a %b %d %H:%M:%S %Y", date_time); // ANSI C asctime format
        }
    }
    if (iss.fail()) return std::nullopt;

    return date_time;
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
