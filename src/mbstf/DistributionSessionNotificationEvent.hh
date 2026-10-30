#ifndef _MBS_TF_DISTRIBUTION_SESSION_NOTIFICATION_EVENT_HH_
#define _MBS_TF_DISTRIBUTION_SESSION_NOTIFICATION_EVENT_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Distribution Session Notification Event
 ******************************************************************************
 * Copyright: (C)2025 British Broadcasting Corporation
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
#include <string>

#include "common.hh"
#include "Open5GSEvent.hh"

MBSTF_NAMESPACE_START

class DistributionSessionNotificationEvent : public Open5GSEvent {
public:
    /* Constructors and Destructor */
    DistributionSessionNotificationEvent(Open5GSEvent &event);
    /* Carries the ids, not the subscription: the event is handled later on the event thread, by when the session may
       have gone (a refused create destroys the session it built), so it is looked up again there. */
    DistributionSessionNotificationEvent(const std::string &dist_session_id, const std::string &subscription_id);
    DistributionSessionNotificationEvent() = delete;
    DistributionSessionNotificationEvent(DistributionSessionNotificationEvent &&other) = delete;
    DistributionSessionNotificationEvent(const DistributionSessionNotificationEvent &other) = delete;

    virtual ~DistributionSessionNotificationEvent() {};

    /* operators */
    DistributionSessionNotificationEvent &operator=(DistributionSessionNotificationEvent &&other) = delete;
    DistributionSessionNotificationEvent &operator=(const DistributionSessionNotificationEvent &other) = delete;

    const std::string &distributionSessionId() const;
    const std::string &subscriptionId() const;
    void releaseEventData();
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_DISTRIBUTION_SESSION_NOTIFICATION_EVENT_HH_ */
