#ifndef _MBS_TF_DISTRIBUTION_SESSION_SUBSCRIPTION_HH_
#define _MBS_TF_DISTRIBUTION_SESSION_SUBSCRIPTION_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Distribution Session Subscription class
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

#include <chrono>
#include <list>
#include <memory>
#include <optional>
#include <string>

#include "common.hh"
#include "DistributionSessionEvents.hh"
#include "Open5GSSBIClient.hh"
#include "openapi/model/DistSessionSubscription.h"

namespace fiveg_mag_reftools {
    class CJson;
}

namespace reftools::mbstf {
    class DistSessionEventReportList;
}

MBSTF_NAMESPACE_START

class DistributionSession;
class Open5GSEvent;

class DistributionSessionSubscription {
public:
    using DateTime = std::chrono::system_clock::time_point;

    /* Constructors and Destructor */
    DistributionSessionSubscription(const std::weak_ptr<DistributionSession> &dist_session, fiveg_mag_reftools::CJson &json,
                                    bool as_request);
    DistributionSessionSubscription(const std::weak_ptr<DistributionSession> &dist_session,
                                    const std::shared_ptr<reftools::mbstf::DistSessionSubscription> &dist_session_subsc);
    DistributionSessionSubscription() = delete;
    DistributionSessionSubscription(DistributionSessionSubscription &&other);
    DistributionSessionSubscription(const DistributionSessionSubscription &other);

    virtual ~DistributionSessionSubscription();

    /* operators */
    DistributionSessionSubscription &operator=(DistributionSessionSubscription &&other);
    DistributionSessionSubscription &operator=(const DistributionSessionSubscription &other);
    bool operator==(const DistributionSessionSubscription &other) const;
    bool operator!=(const DistributionSessionSubscription &other) const { return !(*this == other); };

    /* Getters */
    const std::string &subscriptionId() const { return m_subscriptionId; };
    const int eventTypes() const { return m_eventTypes; }; /* returns ORed DistributionSessionEvents::EventTypeBitMask */
    const std::string &notifyUri() const;
    const std::optional<std::string> &correlationId() const;
    const std::optional<DateTime> &expiryTime() const { return m_expiryTime; };
    const std::optional<std::string> &nfcInstanceId() const;

    /* Setters */
    DistributionSessionSubscription &update(fiveg_mag_reftools::CJson &json, bool as_request=false);

    /* OpenAPI type constructors */
    const reftools::mbstf::DistSessionSubscription &distSessionSubscription() const { return m_distSessionSubscription; };
    std::shared_ptr<reftools::mbstf::DistSessionEventReportList> makeReportList() const;

    /** Push local SEND_NOTIFICATIONS event
     * This will push an event onto the event queue which will call sendNotifications() from the event thread
     */
    void pushNotificationsEvent() const;

    /** Send Notifications to client
     * This will find the current report list and if not empty will open a client connection and send the report list to the
     * notifyUri location.
     */
    void sendNotifications() const;

    bool processClientResponse(const Open5GSEvent &event);

private:
    void _setEventFlags();
    void _setExpiryTime();
    void _setSubscriptionId();

    std::weak_ptr<DistributionSession> m_distributionSession; /* Parent distribution session */
    
    std::string m_subscriptionId;
    int m_eventTypes; /* ORed EventTypeBitMask */
    reftools::mbstf::DistSessionSubscription m_distSessionSubscription;
    std::optional<DateTime> m_expiryTime;
    std::optional<std::string> m_subscriptionLocation;

    struct CacheType {
        CacheType() : lastReportedEventTimes(), client() {};
        CacheType(const CacheType &other) : lastReportedEventTimes(other.lastReportedEventTimes), client() {};
        CacheType(CacheType &&other) : lastReportedEventTimes(std::move(other.lastReportedEventTimes)), client(std::move(other.client)) {};
        CacheType &operator=(const CacheType &other) {lastReportedEventTimes = other.lastReportedEventTimes; client.reset(); return *this; };
        CacheType &operator=(CacheType &&other) {lastReportedEventTimes = std::move(other.lastReportedEventTimes); client = std::move(other.client); return *this; };
        DistributionSessionEvents lastReportedEventTimes;
        std::unique_ptr<Open5GSSBIClient> client;
    } *m_cache;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_DISTRIBUTION_SESSION_SUBSCRIPTION_HH_ */
