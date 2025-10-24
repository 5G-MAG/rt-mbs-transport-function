/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Distribution Session Events
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
#include <exception>
#include <memory>
#include <optional>

#include "common.hh"

#include "DistributionSessionEvents.hh"

MBSTF_NAMESPACE_START

/* Constructors and Destructor */
DistributionSessionEvents::DistributionSessionEvents()
    :dataIngestFailure()
    ,sessionDeactivated()
    ,sessionActivated()
    ,serviceManagementFailure()
    ,dataIngestSessionEstablished()
    ,dataIngestSessionTerminated()
{
}

DistributionSessionEvents::DistributionSessionEvents(const DistributionSessionEvents &other)
    :dataIngestFailure(other.dataIngestFailure)
    ,sessionDeactivated(other.sessionDeactivated)
    ,sessionActivated(other.sessionActivated)
    ,serviceManagementFailure(other.serviceManagementFailure)
    ,dataIngestSessionEstablished(other.dataIngestSessionEstablished)
    ,dataIngestSessionTerminated(other.dataIngestSessionTerminated)
{
}

DistributionSessionEvents::DistributionSessionEvents(DistributionSessionEvents &&other)
    :dataIngestFailure(std::move(other.dataIngestFailure))
    ,sessionDeactivated(std::move(other.sessionDeactivated))
    ,sessionActivated(std::move(other.sessionActivated))
    ,serviceManagementFailure(std::move(other.serviceManagementFailure))
    ,dataIngestSessionEstablished(std::move(other.dataIngestSessionEstablished))
    ,dataIngestSessionTerminated(std::move(other.dataIngestSessionTerminated))
{
}
    
DistributionSessionEvents::~DistributionSessionEvents()
{
}

/* operators */
DistributionSessionEvents &DistributionSessionEvents::operator=(DistributionSessionEvents &&other)
{
    dataIngestFailure = std::move(other.dataIngestFailure);
    sessionDeactivated = std::move(other.sessionDeactivated);
    sessionActivated = std::move(other.sessionActivated);
    serviceManagementFailure = std::move(other.serviceManagementFailure);
    dataIngestSessionEstablished = std::move(other.dataIngestSessionEstablished);
    dataIngestSessionTerminated = std::move(other.dataIngestSessionTerminated);
    return *this;
}

DistributionSessionEvents &DistributionSessionEvents::operator=(const DistributionSessionEvents &other)
{
    dataIngestFailure = other.dataIngestFailure;
    sessionDeactivated = other.sessionDeactivated;
    sessionActivated = other.sessionActivated;
    serviceManagementFailure = other.serviceManagementFailure;
    dataIngestSessionEstablished = other.dataIngestSessionEstablished;
    dataIngestSessionTerminated = other.dataIngestSessionTerminated;
    return *this;
}

bool DistributionSessionEvents::operator==(const DistributionSessionEvents &other) const
{
    return dataIngestFailure == other.dataIngestFailure &&
           sessionDeactivated == other.sessionDeactivated &&
           sessionActivated == other.sessionActivated &&
           serviceManagementFailure == other.serviceManagementFailure &&
           dataIngestSessionEstablished == other.dataIngestSessionEstablished &&
           dataIngestSessionTerminated == other.dataIngestSessionTerminated;
}

int DistributionSessionEvents::updatedSince(const DistributionSessionEvents &other) const
{
    int event_types = 0;
    if (dataIngestFailure && (!other.dataIngestFailure || other.dataIngestFailure.value() < dataIngestFailure.value()))
        event_types |= DATA_INGEST_FAILURE;
    if (sessionDeactivated && (!other.sessionDeactivated || other.sessionDeactivated.value() < sessionDeactivated.value()))
        event_types |= SESSION_DEACTIVATED;
    if (sessionActivated && (!other.sessionActivated || other.sessionActivated.value() < sessionActivated.value()))
        event_types |= SESSION_ACTIVATED;
    if (serviceManagementFailure && (!other.serviceManagementFailure ||
                                     other.serviceManagementFailure.value() < serviceManagementFailure.value()))
        event_types |= SERVICE_MANAGEMENT_FAILURE;
    if (dataIngestSessionEstablished && (!other.dataIngestSessionEstablished ||
                                         other.dataIngestSessionEstablished.value() < dataIngestSessionEstablished.value()))
        event_types |= DATA_INGEST_SESSION_ESTABLISHED;
    if (dataIngestSessionTerminated && (!other.dataIngestSessionTerminated ||
                                        other.dataIngestSessionTerminated.value() < dataIngestSessionTerminated.value()))
        event_types |= DATA_INGEST_SESSION_TERMINATED;

    return event_types;
}

const std::optional<DistributionSessionEvents::DateTime> &DistributionSessionEvents::timepointForEventType(EventTypeBitMask event_type) const
{
    return __timepointForEventType(event_type);
}

const std::optional<DistributionSessionEvents::DateTime> &DistributionSessionEvents::registerEvent(EventTypeBitMask event_type)
{
    auto &tp = timepointForEventType(event_type);
    tp = DateTime::clock::now();
    return tp;
}

/*** private: ***/
std::optional<DistributionSessionEvents::DateTime> &DistributionSessionEvents::timepointForEventType(EventTypeBitMask event_type)
{
    return const_cast<std::optional<DateTime>&>(__timepointForEventType(event_type));
}

const std::optional<DistributionSessionEvents::DateTime> &DistributionSessionEvents::__timepointForEventType(EventTypeBitMask event_type) const
{
    switch (event_type) {
    case DATA_INGEST_FAILURE:
        return dataIngestFailure;
    case SESSION_DEACTIVATED:
        return sessionDeactivated;
    case SESSION_ACTIVATED:
        return sessionActivated;
    case SERVICE_MANAGEMENT_FAILURE:
        return serviceManagementFailure;
    case DATA_INGEST_SESSION_ESTABLISHED:
        return dataIngestSessionEstablished;
    case DATA_INGEST_SESSION_TERMINATED:
        return dataIngestSessionTerminated;
    default:
        break;
    }
    throw std::range_error("Bad event type given to DistributionSessionEvents::timepointForEventType()");
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
