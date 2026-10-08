/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Open5GS SBI Client class
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

#include "Open5GSSBIClient.hh"

MBSTF_NAMESPACE_START

Open5GSSBIClient::Open5GSSBIClient()
{
}

Open5GSSBIClient::Open5GSSBIClient(ogs_sbi_client_t *client)
    :m_ogsClient(client)
{
}

Open5GSSBIClient::Open5GSSBIClient(const std::string &url)
{

    OpenAPI_uri_scheme_e scheme = OpenAPI_uri_scheme_NULL;
    ogs_sockaddr_t *addr = NULL;
    bool rc;

    rc = ogs_sbi_getaddr_from_uri(&scheme, &addr, (char *)url.c_str());
    if (rc == false || scheme == OpenAPI_uri_scheme_NULL) {
         ogs_error("Failed to get sockaddr from uri");
         throw std::runtime_error("Failed to get sockaddr from uri!");
     }
     m_ogsClient = ogs_sbi_client_add(scheme, addr);
     ogs_assert(m_ogsClient);
     m_ownsClient = true;
     ogs_freeaddrinfo(addr);
}

Open5GSSBIClient::Open5GSSBIClient(const char *hostname, int port)
{
    ogs_sockaddr_t *addr = NULL;
    OpenAPI_uri_scheme_e scheme = OpenAPI_uri_scheme_http;
    int rv;

    rv = ogs_getaddrinfo(&addr, AF_UNSPEC, hostname, port, 0);
    if (rv != OGS_OK) {
        ogs_error("getaddrinfo failed");
        throw std::runtime_error("getaddrinfo failed!");
    }

    if (addr == nullptr) {
        ogs_error("Could not get the address of the Application Server");
        throw std::runtime_error("Unable to get client address!");
    }

    m_ogsClient = ogs_sbi_client_add(scheme, addr);
    ogs_assert(m_ogsClient);
    m_ownsClient = true;

    ogs_freeaddrinfo(addr);
}

Open5GSSBIClient::~Open5GSSBIClient()
{
    /* A client is allocated from a pool of a fixed size (max.peer) for each one created, and nothing else
       frees it, so a long-running process that creates one per notification address runs the pool dry and
       ogs_sbi_client_add() then ends the process. The registry is checked first: ogs_sbi_client_remove_all()
       at shutdown removes the clients itself, and removing one twice would free it twice. */
    if (m_ownsClient && m_ogsClient) {
        ogs_sbi_client_t *registered = nullptr, *next = nullptr;
        ogs_list_for_each_safe(&ogs_sbi_self()->client_list, next, registered) {
            if (registered == m_ogsClient) {
                ogs_sbi_client_remove(m_ogsClient);
                break;
            }
        }
    }
    m_ogsClient = nullptr;
}

bool Open5GSSBIClient::sendRequest(ogs_sbi_client_cb_f client_notify_cb,  std::shared_ptr<Open5GSSBIRequest> request, void *data)
{
    ogs_sbi_client_send_request(this->ogsSBIClient(), client_notify_cb, request->ogsSBIRequest(), (void *)data);
    //ogs_sbi_request_free(request->ogsSBIRequest());

    return 1;
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */

