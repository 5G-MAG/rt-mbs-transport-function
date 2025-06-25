/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: DASH Manifest Handler class
 ******************************************************************************
 * Copyright: (C)2025 British Broadcasting Corporation
 * Author(s): Dev Audsin <dev.audsin@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */
#include <chrono>
#include <string>
#include <cstring>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <exception>
#include <optional>
#include <algorithm>
#include <uuid/uuid.h>

#include <libmpd++/SegmentAvailability.hh>

#include "ogs-app.h"
#include "common.hh"
#include "DistributionSession.hh"
#include "ManifestHandler.hh"
#include "ManifestHandlerFactory.hh"
#include "ObjectController.hh"
#include "ObjectStore.hh"
#include "PullObjectIngester.hh"

#include "DASHManifestHandler.hh"

using namespace std::literals::chrono_literals;

LIBMPDPP_NAMESPACE_USING_ALL;

MBSTF_NAMESPACE_START

using time_type = std::chrono::system_clock::time_point;

static LIBMPDPP_NAMESPACE_CLASS(MPD) ingest_manifest(const ObjectStore::Object &new_manifest);

DASHManifestHandler::DASHManifestHandler(const ObjectStore::Object &object, ObjectController *controller, bool pull_distribution)
    :ManifestHandler(controller, pull_distribution)
    ,m_mpd(ingest_manifest(object))
    ,m_manifest(&object)
    ,m_refreshMpd(false)
{
    m_mpd.selectAllRepresentations();

    //Use selectedInitializationSegments() to fetch Initialization Segments

    m_extraPullObjects = m_mpd.selectedInitializationSegments();
    addMPDRefreshToExtraPullObjects();
    ogs_debug("Extra Objects to pull: %zu", m_extraPullObjects.size());
    for (auto &is : m_extraPullObjects) {
      std::ostringstream oss;
      oss << is;
      ogs_debug("    %s", oss.str().c_str());
    }


}

DASHManifestHandler::~DASHManifestHandler()
{
}

std::pair<ManifestHandler::time_type, ManifestHandler::ingest_list> DASHManifestHandler::nextIngestItems()
{

    std::list<PullObjectIngester::IngestItem> ingest_items;
    static const std::string empty;
    auto current_time = std::chrono::system_clock::now();
    std::optional<std::chrono::system_clock::time_point> time_to_update;
    std::string manifest_url;
    time_type fetch_time;

    std::list<LIBMPDPP_NAMESPACE_CLASS(SegmentAvailability)> media_segments = m_mpd.selectedSegmentAvailability();
    media_segments.insert(media_segments.end(), m_extraPullObjects.begin(), m_extraPullObjects.end());
    for (auto &ms: media_segments) {
        if(ms.availabilityStartTime() < current_time)
	    ms.availabilityStartTime(current_time);
    }
    ogs_info("MEDIA SEGS: %zu", media_segments.size());
    for (auto &sa : media_segments) {
      std::ostringstream oss;
      oss << sa;
      ogs_debug("    %s", oss.str().c_str());
    }

    if(!media_segments.empty()) {

        media_segments.sort();

        ogs_info("AVAILABLE SEGS: SORTED  %zu", media_segments.size());
	for (auto &seg : media_segments) {
            std::ostringstream oss;
            oss << seg;
            ogs_debug("    %s", oss.str().c_str());
        }

        auto first_media_segment = media_segments.front();
        fetch_time = first_media_segment.availabilityStartTime();

        ingest_items.emplace_back(nextObjectId(), first_media_segment.segmentURL(), empty,
                                    m_controller->distributionSession().getObjectIngestBaseUrl(),
				    m_controller->distributionSession().objectDistributionBaseUrl(),
                                    first_media_segment.availabilityEndTime());
        removeExtraPullObjectsEntry(first_media_segment);

	try {
            if(first_media_segment.segmentURL()  == manifest_url) m_refreshMpd = true;
        } catch (std::domain_error &err) {
            ogs_error("Invalid Segment URL: %s", err.what());
	    throw;
        }
        auto it = media_segments.begin();
        // Iterate from second element.
        for ( ++it; it != media_segments.end(); ++it ) {

            if(it->availabilityStartTime() != fetch_time) break;
	    removeExtraPullObjectsEntry(*it);
	    ingest_items.emplace_back(nextObjectId(), it->segmentURL(), empty,
                                      m_controller->distributionSession().getObjectIngestBaseUrl(),
                                      m_controller->distributionSession().objectDistributionBaseUrl(),
                                      it->availabilityEndTime());

             if(it->segmentURL()  == manifest_url) m_refreshMpd = true;

        }
    }

    return std::make_pair(fetch_time, ingest_items);
}

void DASHManifestHandler::addMPDRefreshToExtraPullObjects()
{

      if (m_pullDistribution && m_mpd.hasMinimumUpdatePeriod()) {
        auto min_update_time = m_manifest->second.receivedTime() + m_mpd.minimumUpdatePeriod().value();
        auto time_to_update = m_manifest->second.hasExpiryTime() ? std::max(min_update_time, m_manifest->second.ExpiryTime()): min_update_time;
         m_extraPullObjects.push_back(SegmentAvailability(time_to_update, 0s, m_manifest->second.getFetchedUrl(), m_mpd.availabilityEndTime()));

     }
}


void DASHManifestHandler::removeExtraPullObjectsEntry(const SegmentAvailability &segment)
{
    for (auto it = m_extraPullObjects.begin(); it != m_extraPullObjects.end(); it++)
    {
       if(it->segmentURL() == segment.segmentURL()) {
          m_extraPullObjects.erase(it);
	  break;
       }

    }

}


std::string DASHManifestHandler::nextObjectId()
{
    return generateUUID();
}

std::string DASHManifestHandler::generateUUID() {
    uuid_t uuid;
    uuid_generate_random(uuid);
    char uuid_str[37];
    uuid_unparse(uuid, uuid_str);
    return std::string(uuid_str);
}


ManifestHandler::durn_type DASHManifestHandler::getDefaultDeadline()
{
    // TODO: get the segment length from the DASH MPD
    return 4s;
}

bool DASHManifestHandler::update(const ObjectStore::Object &new_manifest)
{
    // Process the new MPD and see what has changed, throw an exception of the Object is not understood or invalid

    m_refreshMpd = false;
    m_mpd = ingest_manifest(new_manifest);
    m_mpd.selectAllRepresentations();
    //SelectedInitialistionSegments(): For everything init segments in the list schedule an ingester.
    m_extraPullObjects = m_mpd.selectedInitializationSegments();
    addMPDRefreshToExtraPullObjects();

    return true; // assume manifest updated, use false for no manifest change
}

void DASHManifestHandler::adjustAvailabilityStartTime() {
    if(!m_extraPullObjects.empty()) {
        time_type current_time = std::chrono::system_clock::now();
        for (auto &segment : m_extraPullObjects) {
            if (segment.availabilityStartTime() < current_time) {
                segment.availabilityStartTime(current_time);
            }
        }
        m_extraPullObjects.sort();
    }
}

static bool g_registered = ManifestHandlerFactory::registerManifestHandler("application/dash+xml", new ManifestHandlerConstructorClass<DASHManifestHandler>());

static LIBMPDPP_NAMESPACE_CLASS(MPD) ingest_manifest(const ObjectStore::Object &new_manifest)
{
    if ( new_manifest.second.mediaType() != "application/dash+xml" ){
         throw std::invalid_argument("Does not look like a DASH Manifest as the media type is invalid. Expected media type: application/dash+xml");
    }
    return LIBMPDPP_NAMESPACE_CLASS(MPD) (new_manifest.first, new_manifest.second.getFetchedUrl());


}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
