/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: the HTTP server of the co-located MBS AS
 ******************************************************************************
 * License: 5G-MAG Public License v1
 *
 * Licensed under the License terms and conditions for use, reproduction, and
 * distribution of 5G-MAG software (the "License").  You may not use this file
 * except in compliance with the License.  You may obtain a copy of the License at
 * https://www.5g-mag.com/reference-tools.  Unless required by applicable law or
 * agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied.
 *
 * See the License for the specific language governing permissions and limitations
 * under the License.
 */

#include <microhttpd.h>

#include <chrono>
#include <cstdio>
#include <mutex>
#include <random>
#include <string>
#include <utility>

#include "ogs-sbi.h" // include before "common.hh" to ensure correct logging domain

#include "common.hh"
#include "MbsAsResponse.hh"
#include "MbsAsServer.hh"

MBSTF_NAMESPACE_START

bool MbsAsServer::splitUrl(const std::string &url, std::string &session_id, std::string &path)
{
    if (url.size() < 4 || url.front() != '/') return false;
    const auto slash = url.find('/', 1);
    if (slash == std::string::npos || slash == 1 || slash + 1 >= url.size()) return false;
    session_id = url.substr(1, slash - 1);
    path = url.substr(slash);
    return true;
}

namespace {

std::optional<std::string> requestHeader(struct MHD_Connection *connection, const char *name)
{
    const char *value = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, name);
    if (!value) return std::nullopt;
    return std::string(value);
}

std::string makeBoundary()
{
    static std::mutex mutex;
    static std::mt19937_64 generator{std::random_device{}()};
    uint64_t a, b;
    {
        std::lock_guard<std::mutex> lock(mutex);
        a = generator();
        b = generator();
    }
    char text[48];
    std::snprintf(text, sizeof(text), "mbsas-%016llx%016llx", static_cast<unsigned long long>(a), static_cast<unsigned long long>(b));
    return text;
}

MHD_Result queue(struct MHD_Connection *connection, const mbsas::Reply &reply, const std::string &server_header)
{
    struct MHD_Response *response = MHD_create_response_from_buffer(reply.body.size(),
            const_cast<unsigned char *>(reply.body.data()), MHD_RESPMEM_MUST_COPY);
    if (!response) return MHD_NO;
    for (const auto &header : reply.headers) MHD_add_response_header(response, header.first.c_str(), header.second.c_str());
    if (!server_header.empty()) MHD_add_response_header(response, "Server", server_header.c_str());
    const MHD_Result result = MHD_queue_response(connection, reply.status, response);
    MHD_destroy_response(response);
    return result;
}

}  // namespace

static MHD_Result handleRequest(void *cls, struct MHD_Connection *connection, const char *url, const char *method,
                                const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls)
{
    auto *server = static_cast<std::pair<std::shared_ptr<RepairRegistry>, std::string> *>(cls);
    const std::string http_method(method ? method : "");
    const std::string request_url(url ? url : "");
    /* Every answer is logged at debug level with the request that was made and the status given, which is what shows a repair at work. */
    auto answer = [&](const mbsas::Reply &reply) -> MHD_Result {
        const char *range = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Range");
        ogs_debug("MBS AS: %s %s%s%s -> %u (%zu octets)", http_method.c_str(), request_url.c_str(), range ? " Range: " : "", range ? range : "", reply.status, reply.body.size());
        return queue(connection, reply, server->second);
    };

    // A request has no body here; one that carries data has it taken and ignored, as libmicrohttpd asks of a handler.
    if (*upload_data_size != 0) {
        *upload_data_size = 0;
        return MHD_YES;
    }

    if (http_method != "GET" && http_method != "HEAD") {
        mbsas::Reply reply;
        reply.status = 405;
        reply.headers.emplace_back("Allow", "GET, HEAD");
        return answer(reply);
    }

    std::string session_id, path;
    std::shared_ptr<const RepairObjectStore::Object> object;
    if (url && MbsAsServer::splitUrl(url, session_id, path)) {
        object = server->first->get(session_id, path, RepairObjectStore::clock_type::now());
    }
    if (!object) {
        mbsas::Reply reply;
        reply.status = 404;
        return answer(reply);
    }

    mbsas::Conditions conditions;
    conditions.ifMatch = requestHeader(connection, "If-Match");
    conditions.ifNoneMatch = requestHeader(connection, "If-None-Match");
    conditions.ifModifiedSince = requestHeader(connection, "If-Modified-Since");
    conditions.ifRange = requestHeader(connection, "If-Range");
    conditions.range = requestHeader(connection, "Range");
    return answer(mbsas::respond(http_method, conditions, *object, makeBoundary()));
}

MbsAsServer::MbsAsServer(const struct sockaddr_storage &address, const std::shared_ptr<RepairRegistry> &registry, const std::string &server_header,
                         std::chrono::seconds housekeeping)
    :m_daemon(nullptr), m_context(nullptr), m_registry(registry), m_housekeepingStop(false)
{
    // The daemon's own copy of what the handler needs: a pointer that lives as long as the daemon does.
    auto *context = new std::pair<std::shared_ptr<RepairRegistry>, std::string>(registry, server_header);
    /* MHD_USE_ERROR_LOG: without it a refusal to start returns NULL with no reason given. */
    m_daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY | MHD_USE_ERROR_LOG, 0, NULL, NULL, handleRequest, context,
                                MHD_OPTION_SOCK_ADDR, reinterpret_cast<const struct sockaddr *>(&address),
                                MHD_OPTION_END);
    if (!m_daemon) {
        ogs_error("The MBS AS could not listen on its configured address");
        delete context;
        return;
    }
    m_context = context;
    if (housekeeping.count() > 0) {
        m_housekeeping = std::thread([this, housekeeping]() {
            std::unique_lock<std::mutex> lock(m_housekeepingMutex);
            while (!m_housekeepingStop) {
                if (m_housekeepingWake.wait_for(lock, housekeeping, [this]() { return m_housekeepingStop; })) break;
                lock.unlock();
                const auto dropped = m_registry->purgeExpired(RepairObjectStore::clock_type::now());
                if (dropped) ogs_debug("MBS AS: dropped %zu repair objects whose retention had run out", dropped);
                lock.lock();
            }
        });
    }
}

MbsAsServer::~MbsAsServer()
{
    {
        std::lock_guard<std::mutex> lock(m_housekeepingMutex);
        m_housekeepingStop = true;
    }
    m_housekeepingWake.notify_all();
    if (m_housekeeping.joinable()) m_housekeeping.join();
    if (m_daemon) MHD_stop_daemon(m_daemon);
    delete static_cast<std::pair<std::shared_ptr<RepairRegistry>, std::string> *>(m_context);
}

uint16_t MbsAsServer::port() const
{
    if (!m_daemon) return 0;
    const union MHD_DaemonInfo *info = MHD_get_daemon_info(m_daemon, MHD_DAEMON_INFO_BIND_PORT);
    return info ? info->port : 0;
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
