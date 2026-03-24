/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Main app entry point
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

#include "ogs-core.h"
#include "ogs-sbi.h" // include before "common.hh" to ensure correct logging domain

#include <stdexcept>

#include "common.hh"
#include "Context.hh"
#include "MBSTFEventHandler.hh"
#include "MBSTFNetworkFunction.hh"
#include "Open5GSFSM.hh"
#include "Open5GSEvent.hh"
#include "Open5GSSockAddr.hh"
#include "openapi/api/IndividualMBSDistributionSessionApi-info.h"
#include "mbstf-version.h"

#include "App.hh"

MBSTF_NAMESPACE_USING;

static App *self = nullptr;
static EventHandler *event_handler = nullptr;

extern "C" int app_initialize(const char *const argv[])
{
    if (!self) {
        try {
            self = new App(argv);
            self->initialise();
            event_handler = new MBSTFEventHandler();
            self->registerEventHandler(event_handler);
            self->startEventHandler();
        } catch (std::exception &err) {
            ogs_error("Fatal error: %s", err.what());
            return OGS_ERROR;
        }
        return OGS_OK;
    }

    ogs_error("Attempt to initalise the application whilst already initialised");

    return OGS_ERROR;
}

extern "C" void app_terminate(void)
{
    if (event_handler) {
        self->registerEventHandler(nullptr);
        delete event_handler;
        event_handler = nullptr;
    }

    if (self) {
        delete self;
        self = nullptr;
        return;
    }

    ogs_error("Attempt to terminate when application whilst in a non-initialised state");

    return;
}

MBSTF_NAMESPACE_START

App::App(const char *const argv[])
    :m_app()     // initialise logging first
    ,m_context() // initialise logging first
    ,m_appMetadata(MBSTF_NAME, MBSTF_VERSION, "")
{
    initialise_logging();
    m_app.reset(new MBSTFNetworkFunction());
    m_app->initialise();
    m_context.reset(new Context());

    m_app->configureLoggingDomain();
}

void App::initialise()
{
    static const char serviceName[] = "nmbstf-distsession" /* NMBSTF_DISTSESSION_API_NAME has the wrong case */;
    static const char supportedFeatures[] = "0";
    static const char apiVersion[] = NMBSTF_DISTSESSION_API_VERSION;

    if (!m_context->parseConfig()) {
        throw std::runtime_error("Unable to load MBSTF configuration!");
    }
    if (!m_app->sbiParseConfig("mbstf")) {
        throw std::runtime_error("Open5GS parse SBI configuration failed!");
    }

    std::vector<std::shared_ptr<Open5GSSockAddr> > addrs(m_context->DistributionSessionServerAddress());
    m_app->setNFServiceInfo(serviceName, supportedFeatures, apiVersion, addrs, m_context->totalMaxBitRateSoftLimit);

    std::string nf_name("MBSTF-");
    nf_name += m_app->serverName();
    m_appMetadata.serverName(nf_name);

    if (!m_app->sbiOpen()) {
        throw std::runtime_error("Open SBI servers failed!");
    }
}

void App::startEventHandler()
{
    if (!m_app->startEventHandler()) {
        throw std::runtime_error("Unable to start event processing thread!");
    }
}

App::~App()
{
    m_context.reset();
    m_app.reset();
}

const App &App::self()
{
    if (!::self) {
        throw std::runtime_error("Application is not initialised!");
    }
    return *::self;
}

EventHandler *App::registerEventHandler(EventHandler *event_handler)
{
    EventHandler *old = m_eventHandler;
    m_eventHandler = event_handler;
    return old;
}

Open5GSYamlDocument App::configDocument() const
{
    return m_app->configFileDocument();
}

int App::queuePush(const std::shared_ptr<Open5GSEvent> &event) const
{
   return m_app->pushEvent(event);

}


void App::dispatchEvent(Open5GSFSM &fsm, Open5GSEvent &event) const
{
    if (m_eventHandler) {
        m_eventHandler->dispatch(fsm, event);
    }
}

const NfServer::AppMetadata &App::mbstfAppMetadata() const
{
    return m_appMetadata;
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
