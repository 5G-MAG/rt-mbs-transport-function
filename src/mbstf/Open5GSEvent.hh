#ifndef _MBS_TF_OPEN5GS_EVENT_HH_
#define _MBS_TF_OPEN5GS_EVENT_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Open5GS Event interface
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

#include "ogs-proto.h"

#include <memory>

#include "Open5GSSBIMessage.hh"
#include "Open5GSSBIRequest.hh"
#include "Open5GSSBIResponse.hh"

#include "common.hh"

MBSTF_NAMESPACE_START

class Open5GSEvent {
public:
    Open5GSEvent(ogs_event_t *event) :m_event(event) {};
    Open5GSEvent() = delete;
    Open5GSEvent(Open5GSEvent &&other) = delete;
    Open5GSEvent(const Open5GSEvent &other) = delete;
    Open5GSEvent &operator=(Open5GSEvent &&other) = delete;
    Open5GSEvent &operator=(const Open5GSEvent &other) = delete;
    virtual ~Open5GSEvent() {};

    ogs_event_t *ogsEvent() { return m_event; };
    const ogs_event_t *ogsEvent() const { return m_event; };

    int id() const { return m_event?(m_event->id):0; };
    int timerId() const { return m_event?(m_event->timer_id):0; };
    Open5GSSBIRequest sbiRequest() const { return Open5GSSBIRequest(m_event?(m_event->sbi.request):nullptr, false); };
    Open5GSSBIResponse sbiResponse() const { return Open5GSSBIResponse(m_event?(m_event->sbi.response):nullptr, false); };
    void *sbiData() const { return m_event?(m_event->sbi.data):nullptr; };
    Open5GSSBIMessage sbiMessage() const { return Open5GSSBIMessage(m_event?(m_event->sbi.message):nullptr, false); };
    void sbiMessage(Open5GSSBIMessage &message) { if (!m_event) return; m_event->sbi.message = message.ogsSBIMessage(); message.setOwner(false); };
    void sbiResponse(Open5GSSBIResponse &response) { if (!m_event) return; m_event->sbi.response = response.ogsSBIResponse(); response.setOwner(false); };
    void sbiRequest(Open5GSSBIRequest &request) { if (!m_event) return; m_event->sbi.request = request.ogsSBIRequest(); request.setOwner(false); };
    void setSbiData(void *data) { if (!m_event) return; m_event->sbi.data = data; };

private:
    ogs_event_t *m_event;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_OPEN5GS_EVENT_HH_ */
