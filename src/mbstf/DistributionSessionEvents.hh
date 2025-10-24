#ifndef _MBS_TF_DISTRIBUTION_SESSION_EVENTS_HH_
#define _MBS_TF_DISTRIBUTION_SESSION_EVENTS_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Distribution Session Event Timestamps class
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
#include <optional>

#include "common.hh"

MBSTF_NAMESPACE_START

class DistributionSessionEvents {
public:
    using DateTime = std::chrono::system_clock::time_point;

    typedef enum {
        NONE = 0,
        DATA_INGEST_FAILURE = 0x01,
        SESSION_DEACTIVATED = 0x02,
        SESSION_ACTIVATED = 0x04,
        SERVICE_MANAGEMENT_FAILURE = 0x08,
        DATA_INGEST_SESSION_ESTABLISHED = 0x10,
        DATA_INGEST_SESSION_TERMINATED = 0x20
    } EventTypeBitMask;

    /* event timestamps */
    std::optional<DateTime> dataIngestFailure;
    std::optional<DateTime> sessionDeactivated;
    std::optional<DateTime> sessionActivated;
    std::optional<DateTime> serviceManagementFailure;
    std::optional<DateTime> dataIngestSessionEstablished;
    std::optional<DateTime> dataIngestSessionTerminated;

    /* Constructors and Destructor */
    DistributionSessionEvents();
    DistributionSessionEvents(const DistributionSessionEvents &other);
    DistributionSessionEvents(DistributionSessionEvents &&other);
    
    virtual ~DistributionSessionEvents();

    /* operators */
    DistributionSessionEvents &operator=(DistributionSessionEvents &&other);
    DistributionSessionEvents &operator=(const DistributionSessionEvents &other);
    bool operator==(const DistributionSessionEvents &other) const;
    bool operator!=(const DistributionSessionEvents &other) const { return !(*this == other); };

    int updatedSince(const DistributionSessionEvents &other) const; /* returns event type bits */
    const std::optional<DateTime> &timepointForEventType(EventTypeBitMask event_type) const;

    const std::optional<DateTime> &registerEvent(EventTypeBitMask event_type);

private:
    std::optional<DateTime> &timepointForEventType(EventTypeBitMask event_type);
    const std::optional<DateTime> &__timepointForEventType(EventTypeBitMask event_type) const;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_DISTRIBUTION_SESSION_EVENTS_HH_ */
