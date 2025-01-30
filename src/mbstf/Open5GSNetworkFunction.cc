/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Open5GS Application interface
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

// Open5GS header includes
#include "ogs-app.h"
#include "ogs-core.h"
#include "ogs-sbi.h"

// Standard Template Library header includes
#include <memory>
#include <stdexcept>
#include <netdb.h>  
#include <sys/types.h>
#include <sys/socket.h>

// App header includes
#include "common.hh"
#include "App.hh"
#include "MBSTFNetworkFunction.hh"
#include "MBSTFEventHandler.hh"
#include "Open5GSEvent.hh"
#include "Open5GSSockAddr.hh"
#include "Open5GSTimer.hh"
#include "Open5GSYamlDocument.hh"
#include "TimerFunc.hh"

// This class header include
#include "Open5GSNetworkFunction.hh"

MBSTF_NAMESPACE_START

Open5GSNetworkFunction::Open5GSNetworkFunction()
    :m_eventThread(nullptr)
    ,m_serviceName(nullptr)
    ,m_supportedFeatures(nullptr)
    ,m_apiVersion(nullptr)
    ,m_serverName()
    ,m_addr()
{
    if (ogs_env_set("TZ", "UTC") != OGS_OK) {
        throw std::runtime_error("Failed to set clock to UTC");
    }
    if (ogs_env_set("LC_TIME", "C") != OGS_OK) {
        throw std::runtime_error("Failed to set time locale to C");
    }
    
    //ogs_sbi_context_init(nfType());
}

class EventTerminationTimerFunc : public TimerFunc {
public:
    EventTerminationTimerFunc() :TimerFunc() {};
    EventTerminationTimerFunc(EventTerminationTimerFunc &&) = delete;
    EventTerminationTimerFunc(const EventTerminationTimerFunc&) = delete;
    EventTerminationTimerFunc &operator=(EventTerminationTimerFunc &&) = delete;
    EventTerminationTimerFunc &operator=(const EventTerminationTimerFunc &) = delete;
    virtual ~EventTerminationTimerFunc() {};

    virtual void trigger() {};
};

static EventTerminationTimerFunc __event_term_timer_func;

Open5GSNetworkFunction::~Open5GSNetworkFunction()
{
    // Terminate Open5GS SBI FSMs
    ogs_sbi_nf_instance_t *nf_instance = NULL;
    ogs_list_for_each(&ogs_sbi_self()->nf_instance_list, nf_instance) {
        ogs_sbi_nf_fsm_fini(nf_instance);
    }

    std::shared_ptr<Open5GSTimer> event_term_timer(addTimer(__event_term_timer_func));
    event_term_timer->start(ogs_time_from_msec(300));

    ogs_queue_term(ogs_app()->queue);
    ogs_pollset_notify(ogs_app()->pollset);
    
    stopEventHandler();
    
    removeTimer(event_term_timer);
    event_term_timer.reset();

    sbiClose();

    ogs_sbi_context_final();
}

static void timer_function(void *real_fn)
{
    TimerFunc *timer_func = reinterpret_cast<TimerFunc*>(real_fn);
    timer_func->trigger();
}

std::shared_ptr<Open5GSTimer> Open5GSNetworkFunction::addTimer(TimerFunc &timer_func)
{
    ogs_timer_t *timer = ogs_timer_add(ogs_app()->timer_mgr, timer_function, &timer_func);
    std::shared_ptr<Open5GSTimer> ret(nullptr);

    if (timer) {
        ret.reset(new Open5GSTimer(timer));
    }

    return ret;
}

void Open5GSNetworkFunction::removeTimer(const std::shared_ptr<Open5GSTimer> &timer)
{
    ogs_timer_delete(timer->ogsTimer());
}

Open5GSYamlDocument Open5GSNetworkFunction::configFileDocument() const
{
    return Open5GSYamlDocument(ogs_app()->document);
}

int Open5GSNetworkFunction::pushEvent(const std::shared_ptr<Open5GSEvent> &event)
{
    int rv = 0;
    rv = ogs_queue_push(ogs_app()->queue, event->ogsEvent());
    if (rv !=OGS_OK) {
        ogs_error("OGS Queue Push failed %d", rv);
        //ogs_sbi_response_free(response);
        ogs_event_free(event->ogsEvent());
        return OGS_ERROR;
    }
    return OGS_OK;

}

bool Open5GSNetworkFunction::configureLoggingDomain()
{
    return ogs_log_config_domain(ogs_app()->logger.domain, ogs_app()->logger.level) == OGS_OK;
}

bool Open5GSNetworkFunction::sbiParseConfig(const char *app_section, const char *nrf_section, const char *scp_section)
{
    return ogs_sbi_context_parse_config(app_section, nrf_section, scp_section) == OGS_OK;
}

static int server_cb(ogs_sbi_request_t *request, void *data)
{
    ogs_event_t *e = NULL;
    int rv;

    ogs_assert(request);
    ogs_assert(data);

    e = ogs_event_new(OGS_EVENT_SBI_SERVER);
    ogs_assert(e);

    e->sbi.request = request;
    e->sbi.data = data;

    rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        ogs_error("ogs_queue_push() failed:%d", (int)rv);
        ogs_sbi_request_free(request);
        ogs_event_free(e);
        return OGS_ERROR;
    }

    return OGS_OK;
}

bool Open5GSNetworkFunction::setNFServiceInfo(const char *serviceName, const char *supportedFeatures, const char *apiVersion, const std::shared_ptr<Open5GSSockAddr> &addr)
{
    m_serviceName = serviceName;
    m_supportedFeatures = supportedFeatures;
    m_apiVersion = apiVersion;
    m_addr = addr;
    return true;

}

int Open5GSNetworkFunction::setNFService() {
    ogs_uuid_t uuid;
    char id[OGS_UUID_FORMATTED_LENGTH + 1];
    ogs_sbi_nf_service_t *nf_service = NULL;

    ogs_uuid_get(&uuid);
    ogs_uuid_format(id, &uuid);

    ogs_info("NF UUID: %s", id);

    nf_service = ogs_sbi_nf_service_add(ogs_sbi_self()->nf_instance, id, m_serviceName,
                                        ogs_app()->sbi.server.no_tls == false ? OpenAPI_uri_scheme_https : OpenAPI_uri_scheme_http);
    ogs_assert(nf_service);

    addAddressesToNFService(nf_service, m_addr);
    ogs_sbi_nf_service_add_version(nf_service, OGS_SBI_API_V1, m_apiVersion, NULL);
    nf_service->supported_features = ogs_strdup(m_supportedFeatures);
    ogs_info("MBSTF Service [%s]", nf_service->name);
    if (!nf_service) return OGS_ERROR;

    return OGS_OK;
}

const std::string &Open5GSNetworkFunction::serverName()
{
    if (m_serverName.empty()) setServerName();
    return m_serverName;
}

int Open5GSNetworkFunction::setServerName(void) {

    ogs_sbi_server_t *server = NULL;
    char server_name[NI_MAXHOST];

    ogs_list_for_each(&ogs_sbi_self()->server_list, server) {

        ogs_sockaddr_t *advertise = NULL;
        int res = 0;

        advertise = server->advertise;
        if (!advertise)
            advertise = server->node.addr;
        ogs_assert(advertise);
	res = getnameinfo((struct sockaddr *) &advertise->sa,
                      ogs_sockaddr_len(advertise),
                      server_name, NI_MAXHOST,
                      NULL, 0, NI_NAMEREQD);

        if(res) {
            ogs_debug("Unable to retrieve server name: %d\n", res);
            continue;
        } else {
            ogs_debug("node=%s", server_name);
            ogs_info("SERVER NAME NODE=%s", server_name);
	    m_serverName = server_name;
            return 1;
        }
    }
    return 0;
}

bool Open5GSNetworkFunction::sbiOpen()
{
    ogs_sbi_nf_instance_t *nf_instance = ogs_sbi_self()->nf_instance;

    ogs_sbi_nf_fsm_init(nf_instance);
    ogs_sbi_nf_instance_build_default(nf_instance);

    if (setNFService() != OGS_OK) {
        return OGS_ERROR;
    }

    nf_instance = ogs_sbi_self()->nrf_instance;
    if (nf_instance) {
        ogs_sbi_nf_fsm_init(nf_instance);
    }

    return ogs_sbi_server_start_all(server_cb) == OGS_OK;
}

void Open5GSNetworkFunction::sbiClose()
{
    ogs_sbi_client_stop_all();
    ogs_sbi_server_stop_all();
}


bool Open5GSNetworkFunction::startEventHandler()
{
    m_eventThread = ogs_thread_create(Open5GSNetworkFunction::eventThread, NULL);
    return !!m_eventThread;
}

void Open5GSNetworkFunction::stopEventHandler()
{
    if (m_eventThread) ogs_thread_destroy(m_eventThread);
}


void Open5GSNetworkFunction::eventThread(void *data)
{
    ogs_fsm_t fsm;
    int rv;

    ogs_fsm_init(&fsm, reinterpret_cast<void*>(Open5GSNetworkFunction::stateInitial),
                       reinterpret_cast<void*>(Open5GSNetworkFunction::stateFinal),
                       reinterpret_cast<void*>(0));

    do {
        ogs_pollset_poll(ogs_app()->pollset, ogs_timer_mgr_next(ogs_app()->timer_mgr));
        ogs_timer_mgr_expire(ogs_app()->timer_mgr);
        do {
            ogs_event_t *e = NULL;
            rv = ogs_queue_trypop(ogs_app()->queue, (void**)&e);
            ogs_assert(rv != OGS_ERROR);

            if (rv == OGS_DONE)
                goto done;

            if (rv == OGS_RETRY)
                break;

            ogs_assert(e);

            ogs_fsm_dispatch(&fsm, e);

            ogs_event_free(e);
        } while (true);
    } while (true);
done:
    ogs_fsm_fini(&fsm, 0);
}


void Open5GSNetworkFunction::addAddressesToNFService(ogs_sbi_nf_service_t *nf_service,
                                                     const std::shared_ptr<Open5GSSockAddr> &addrs)
{
    ogs_sockaddr_t *addr = NULL;

    for (ogs_copyaddrinfo(&addr, addrs->ogsSockAddr()); addr && nf_service->num_of_addr < OGS_SBI_MAX_NUM_OF_IP_ADDRESS;
         addr = addr->next) {
        bool is_port = true;
        int port = 0;

        if (addr->ogs_sa_family == AF_INET) {
            nf_service->addr[nf_service->num_of_addr].ipv4 = addr;
        } else if (addr->ogs_sa_family == AF_INET6) {
            nf_service->addr[nf_service->num_of_addr].ipv6 = addr;
        } else {
            continue;
        }

        port = OGS_PORT(addr);
        if (nf_service->scheme == OpenAPI_uri_scheme_https) {
            if (port == OGS_SBI_HTTPS_PORT) is_port = false;
        } else if (nf_service->scheme == OpenAPI_uri_scheme_http) {
            if (port == OGS_SBI_HTTP_PORT) is_port = false;
        }

        nf_service->addr[nf_service->num_of_addr].is_port = is_port;
        nf_service->addr[nf_service->num_of_addr].port = port;

        nf_service->num_of_addr++;
    }
}

void Open5GSNetworkFunction::stateInitial(ogs_fsm_t *s, ogs_event_t *e)
{
    ogs_assert(s);
    OGS_FSM_TRAN(s, Open5GSNetworkFunction::stateFunctional);
}

void Open5GSNetworkFunction::stateFunctional(ogs_fsm_t *s, ogs_event_t *e)
{
    const App &app = App::self();
    Open5GSFSM fsm(s);
    Open5GSEvent event(e);
    app.dispatchEvent(fsm, event);
}

void Open5GSNetworkFunction::stateFinal(ogs_fsm_t *s, ogs_event_t *e)
{
    ogs_assert(s);
}


MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
