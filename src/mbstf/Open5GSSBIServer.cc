/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Open5GS SBI Server interface
 ******************************************************************************
 * Copyright: (C)2024 British Broadcasting Corporation
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

#include "ogs-app.h"
#include "ogs-sbi.h"

#include <memory>
#include <stdexcept>

#include "common.hh"
#include "App.hh"
#include "TimerFunc.hh"
#include "Open5GSEvent.hh"
#include "Open5GSTimer.hh"
#include "Open5GSYamlDocument.hh"
#include "Open5GSSBIStream.hh"

#include "Open5GSSBIServer.hh"

MBSTF_NAMESPACE_START

Open5GSSBIServer::Open5GSSBIServer()
{
}

Open5GSSBIServer::Open5GSSBIServer(ogs_sbi_server_t *server)
    :m_ogsServer(server)
{
}

Open5GSSBIServer::Open5GSSBIServer(ogs_socknode_t *node,  ogs_sockopt_t *option)
{
    m_ogsServer = ogs_sbi_server_add(node->addr, option);
    ogs_assert(m_ogsServer);
}

Open5GSSBIServer::~Open5GSSBIServer()
{
}

void Open5GSSBIServer::ogsSBIServerAdvertise(ogs_sockaddr_t *addr) {
    if (addr && ogs_app()->parameter.no_ipv4 == 0) {
        ogs_sbi_server_set_advertise(this->ogsSBIServer(), AF_INET, addr);
    }
}

bool Open5GSSBIServer::sendError(Open5GSSBIStream &stream, int status_code, std::optional<Open5GSSBIMessage> message,
                                 const char *reason, const char *value)
{
    return ogs_sbi_server_send_error(stream.ogsSBIStream(), status_code, message.has_value()?message->ogsSBIMessage():nullptr, reason, value);
}

bool Open5GSSBIServer::sendResponse(Open5GSSBIStream &stream, Open5GSSBIResponse &response)
{
    response.setOwner(false); // ogs_sbi_response is being passed to ogs_sbi_server now
    return ogs_sbi_server_send_response(stream.ogsSBIStream(), response.ogsSBIResponse());
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
