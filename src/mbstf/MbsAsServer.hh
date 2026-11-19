#ifndef MBSTF_MBS_AS_SERVER_HH
#define MBSTF_MBS_AS_SERVER_HH
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

#include <sys/socket.h>

#include <cstdint>
#include <memory>
#include <string>

#include "common.hh"
#include "RepairRegistry.hh"

struct MHD_Daemon;

MBSTF_NAMESPACE_START

/** The HTTP server at reference point MBS-4-UC through which the MBSTF Client repairs objects from the MBS AS that is co-located with the
 * MBSTF (TS 26.502 V19.5.0 clause 4.3.4: "its functions may be co-located with other Network Functions such as the MBSTF").
 *
 * A request is "/{distributionSessionId}/{path}": the identifier selects the session in the registry and the path is the path of the
 * object's repair location (TS 26.517 V19.2.0 clause 6.2.4.4). What is answered, and how, is decided by mbsas::respond(); this class
 * only carries the request headers in and the answer out. The server is a libmicrohttpd daemon, as the MBSTF's object push server is.
 */
class MbsAsServer {
public:
    /**
     * \param address        where to listen; a port of zero lets the system choose, which port() then tells.
     * \param registry       the objects to serve.
     * \param server_header  the value of the Server response header field (clause 8.2.3.3.5).
     */
    MbsAsServer(const struct sockaddr_storage &address, const std::shared_ptr<RepairRegistry> &registry, const std::string &server_header);
    MbsAsServer(const MbsAsServer &) = delete;
    MbsAsServer &operator=(const MbsAsServer &) = delete;
    ~MbsAsServer();

    /** Whether the server is listening. */
    bool running() const { return m_daemon != nullptr; }

    /** The port the server listens on, or zero when it is not running. */
    uint16_t port() const;

    /** The identifier and path of a request URL, "/{id}/{path}", or false when it has no identifier or no path after it. */
    static bool splitUrl(const std::string &url, std::string &session_id, std::string &path);

private:
    struct MHD_Daemon *m_daemon;
    void *m_context;  //!< what the request handler needs, owned here, freed after the daemon has stopped
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* MBSTF_MBS_AS_SERVER_HH */
