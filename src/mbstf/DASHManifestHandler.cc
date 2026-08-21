/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: DASH Manifest Handler class
 ******************************************************************************
 * Copyright: (C)2025 British Broadcasting Corporation
 * Author(s): Dev Audsin <dev.audsin@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */
#include <algorithm>
#include <chrono>
#include <cstring>
#include <exception>
#include <iostream>
#include <list>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

#include <uuid/uuid.h>

#include <libmpd++/SegmentAvailability.hh>

#include "ogs-app.h"
#include "ogs-sbi.h" // include before "common.hh" to ensure correct logging domain

#include "common.hh"
#include "App.hh"
#include "Context.hh"
#include "DistributionSession.hh"
#include "ManifestHandler.hh"
#include "ManifestHandlerFactory.hh"
#include "ObjectController.hh"
#include "ObjectStore.hh"
#include "Open5GSYamlIter.hh"
#include "PullObjectIngester.hh"

#include "DASHManifestHandler.hh"

using namespace std::literals::chrono_literals;

LIBMPDPP_NAMESPACE_USING_ALL;

MBSTF_NAMESPACE_START

namespace {
static struct {
    std::optional<std::chrono::milliseconds> mpdRepetitionRate = std::nullopt;
    bool compressMpd = false;
} g_config;

static void __tidy_config() {
    g_config.mpdRepetitionRate = std::nullopt;
    g_config.compressMpd = false;
}

static const std::chrono::milliseconds &__get_repetition_rate() {
    if (g_config.mpdRepetitionRate) {
        return g_config.mpdRepetitionRate.value();
    }
    auto &context = App::self().context();
    if (context && context->manifestGlobals.manifestRepetitionRate) {
        return context->manifestGlobals.manifestRepetitionRate.value();
    }
    static const std::chrono::milliseconds no_repetition_rate(-1);
    return no_repetition_rate;
}

static bool __set_repetition_rate(const std::string &value) {
    try {
        g_config.mpdRepetitionRate = Context::parseDuration(value);
    } catch (std::out_of_range &ex) {
        return false;
    }
    return true;
}

static bool __get_compress_mpd() {
    return g_config.compressMpd;
}

static bool __set_compress_mpd(bool compress_mpd) {
    g_config.compressMpd = compress_mpd;
    return true;
}
}

using time_type = std::chrono::system_clock::time_point;

static LIBMPDPP_NAMESPACE_CLASS(MPD) ingest_manifest(const std::shared_ptr<ObjectStore::Object> &new_manifest);

DASHManifestHandler::DASHManifestHandler(const std::shared_ptr<ObjectStore::Object> &object, ObjectController *controller, bool pull_distribution)
    :ManifestHandler(controller, pull_distribution)
    ,m_mpdMutex()
    ,m_mpd(ingest_manifest(object))
    ,m_manifest(object)
    ,m_refreshMpd(false)
{
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
    m_mpd.presentationType(MPD::STATIC);
    m_mpd.minimumUpdatePeriod(std::nullopt); // no more updates
}

std::pair<ManifestHandler::time_type, ManifestHandler::ingest_list> DASHManifestHandler::nextIngestItems()
{
    std::list<PullObjectIngester::IngestItem> ingest_items;
    static const std::string empty;
    auto current_time = std::chrono::system_clock::now();
    std::optional<std::chrono::system_clock::time_point> time_to_update;
    std::string manifest_url;
    time_type fetch_time;

    std::list<SegmentEntry> media_segments;
    {
        std::lock_guard<std::recursive_mutex> guard(m_mpdMutex);
        media_segments = std::move(augmentSegmentAvailabilityList(m_mpd.selectedSegmentAvailability(), false, false, false));
    }
    media_segments.insert(media_segments.end(), m_extraPullObjects.begin(), m_extraPullObjects.end());
    for (auto &ms: media_segments) {
        if(ms.availabilityStartTime() < current_time)
            ms.availabilityStartTime(current_time);
    }
    ogs_debug("MEDIA SEGS: %zu", media_segments.size());
    for (auto &sa : media_segments) {
      std::ostringstream oss;
      oss << sa;
      ogs_debug("    %s", oss.str().c_str());
    }

    if(!media_segments.empty()) {

        media_segments.sort();

        ogs_debug("AVAILABLE SEGS: SORTED  %zu", media_segments.size());
        for (auto &seg : media_segments) {
            std::ostringstream oss;
            oss << seg;
            ogs_debug("    %s", oss.str().c_str());
        }

        auto first_media_segment = media_segments.front();
        fetch_time = first_media_segment.availabilityStartTime();
        auto segment_url = first_media_segment.segmentURL();

        // Find existing object in the ObjectStore for same URL
        const auto &object_store = m_controller->objectStore();
        const auto &obj_ingest_base_url = m_controller->distributionSession().getObjectIngestBaseUrl();
        const auto &obj_dist_base_url = m_controller->distributionSession().objectDistributionBaseUrl();
        auto existing_obj = object_store->findMetadataByURL(segment_url);

        if (existing_obj) {
            ingest_items.emplace_back(*existing_obj, first_media_segment.availabilityEndTime(), first_media_segment.forceRecache(), first_media_segment.keepAfterSend(), first_media_segment.compressEntry());
        } else {
            ingest_items.emplace_back(nextObjectId(), first_media_segment.segmentURL(), empty, obj_ingest_base_url,
                                      obj_dist_base_url, first_media_segment.availabilityEndTime(), first_media_segment.forceRecache(), first_media_segment.keepAfterSend(), first_media_segment.compressEntry());
        }
        removeExtraPullObjectsEntry(first_media_segment);

        try {
            if (first_media_segment.segmentURL() == manifest_url) m_refreshMpd = true;
        } catch (std::domain_error &err) {
            ogs_error("Invalid Segment URL: %s", err.what());
            throw;
        }
        auto it = media_segments.begin();
        // Iterate from second element to find ones with the same availabilityStartTime() as the first and add them to result.
        for ( ++it; it != media_segments.end(); ++it ) {
            if (it->availabilityStartTime() != fetch_time) break;
            segment_url = it->segmentURL();
            existing_obj = object_store->findMetadataByURL(segment_url);
            removeExtraPullObjectsEntry(*it);
            if (existing_obj) {
                ingest_items.emplace_back(*existing_obj, it->availabilityEndTime(), it->forceRecache(), it->keepAfterSend(), it->compressEntry());
            } else {
                ingest_items.emplace_back(nextObjectId(), segment_url, empty, obj_ingest_base_url, obj_dist_base_url,
                                          it->availabilityEndTime(), it->forceRecache(), it->keepAfterSend(), it->compressEntry());
            }
            if (it->segmentURL() == manifest_url) m_refreshMpd = true;
        }
    }

    return std::make_pair(fetch_time, ingest_items);
}

void DASHManifestHandler::addMPDRefreshToExtraPullObjects()
{
    std::lock_guard<std::recursive_mutex> guard(m_mpdMutex);

    m_mpd.selectAllRepresentations();
    //SelectedInitialistionSegments(): For everything init segments in the list schedule an ingester.
    m_extraPullObjects = std::move(augmentSegmentAvailabilityList(m_mpd.selectedInitializationSegments(), false, true, false));

    std::chrono::system_clock::time_point resend_at;
    bool force_recache = false;

    auto repetition_rate = __get_repetition_rate();
    if (repetition_rate.count() > 0) {
        auto resend_base_time = m_manifest->second.lastSent();
        if (resend_base_time.time_since_epoch().count() == 0) {
            // Use last received time if we don't have a record of the last send time
            resend_base_time = m_manifest->second.receivedTime();
        }
        resend_at = resend_base_time + repetition_rate;
    }
    if (m_pullDistribution && m_mpd.hasMinimumUpdatePeriod()) {
        auto min_update_time = m_manifest->second.receivedTime() + m_mpd.minimumUpdatePeriod().value();
        if (resend_at.time_since_epoch().count() == 0 || min_update_time < resend_at) {
            resend_at = min_update_time;
            force_recache = true; // always force update fetch at update period
        }
    }
    if (resend_at.time_since_epoch().count() != 0) {
        m_extraPullObjects.emplace_back(resend_at, 0s, m_manifest->second.getFetchedUrl(),
                                        m_mpd.availabilityEndTime(), force_recache, true, __get_compress_mpd());
    }
}

void DASHManifestHandler::removeExtraPullObjectsEntry(const DASHManifestHandler::SegmentEntry &segment)
{
    m_extraPullObjects.remove_if([&segment](const SegmentEntry &item){ return item.segmentURL() == segment.segmentURL(); });
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

bool DASHManifestHandler::update(const std::shared_ptr<ObjectStore::Object> &new_manifest)
{
    // Process the new MPD and see what has changed, throw an exception of the Object is not understood or invalid

    auto new_mpd = ingest_manifest(new_manifest);
    {
        std::lock_guard<std::recursive_mutex> guard(m_mpdMutex);
        m_refreshMpd = false;
        if (m_mpd != new_mpd) {
            ogs_debug("New MPD update, changing MPD");
            m_mpd = new_mpd;
            m_manifest = new_manifest;
        }
    }
    addMPDRefreshToExtraPullObjects();

    return true; // update completed successfully
}

bool DASHManifestHandler::parseConfiguration(const std::string &section_name, Open5GSYamlIter &iter)
{
    if (section_name == "dashManifestHandler") {
        Open5GSYamlIter dash_iter(iter);
        while (dash_iter.next()) {
            std::string dash_key(dash_iter.key());
            if (dash_key == "compressMPDOnSend") {
                Open5GSYamlIter dash_compress_iter(dash_iter);
                if (dash_compress_iter.type() == YAML_SCALAR_NODE) {
                    __set_compress_mpd(dash_compress_iter.valueBool());
                } else {
                    throw std::out_of_range("Bad data type in configuration at mbstf.dashManifestHandler.compressMPDOnSend");
                }
            } else if (dash_key == "mpdRepetitionRate") {
                Open5GSYamlIter dash_rep_rate_iter(dash_iter);
                if (dash_rep_rate_iter.type() == YAML_SCALAR_NODE) {
                    __set_repetition_rate(dash_rep_rate_iter.value());
                } else {
                    throw std::out_of_range("Bad data type in configuration at mbstf.dashManifestHandler.mpdRepetitionRate");
                }
            } else {
                ogs_warn("Unknown key `mbstf.dashManifestHandler.%s` in configuration", dash_key.c_str());
            }
        }
        return true;
    }
    return false;
}

void DASHManifestHandler::tidyConfiguration()
{
    __tidy_config();
}

bool DASHManifestHandler::compressManifestOnSend() const
{
    return __get_compress_mpd();
}

std::list<DASHManifestHandler::SegmentEntry> DASHManifestHandler::augmentSegmentAvailabilityList(
                                                        std::list<LIBMPDPP_NAMESPACE_CLASS(SegmentAvailability)> &&segments,
                                                        bool force_recache, bool keep_after_send, bool compress_entry)
{
    std::list<SegmentEntry> result;
    while (!segments.empty()) {
        auto &seg = segments.front();
        result.emplace_back(std::move(seg), force_recache, keep_after_send, compress_entry);
        segments.pop_front();
    }
    return result;
}

/********** DASHManifestHandler::SegmentEntry ************/
DASHManifestHandler::SegmentEntry::SegmentEntry()
    :LIBMPDPP_NAMESPACE_CLASS(SegmentAvailability)()
    ,m_forceRecache(false)
    ,m_keepAfterSend(false)
    ,m_compressFile(false)
{
}

DASHManifestHandler::SegmentEntry::SegmentEntry(const DASHManifestHandler::SegmentEntry &other)
    :LIBMPDPP_NAMESPACE_CLASS(SegmentAvailability)(other)
    ,m_forceRecache(other.m_forceRecache)
    ,m_keepAfterSend(other.m_keepAfterSend)
    ,m_compressFile(other.m_compressFile)
{
}

DASHManifestHandler::SegmentEntry::SegmentEntry(DASHManifestHandler::SegmentEntry &&other)
    :LIBMPDPP_NAMESPACE_CLASS(SegmentAvailability)(std::move(other))
    ,m_forceRecache(other.m_forceRecache)
    ,m_keepAfterSend(other.m_keepAfterSend)
    ,m_compressFile(other.m_compressFile)
{
}

DASHManifestHandler::SegmentEntry::SegmentEntry(const LIBMPDPP_NAMESPACE_CLASS(SegmentAvailability) &seg_avail, bool force_recache,
                                                bool keep_after_send, bool compress_entry)
    :LIBMPDPP_NAMESPACE_CLASS(SegmentAvailability)(seg_avail)
    ,m_forceRecache(force_recache)
    ,m_keepAfterSend(keep_after_send)
    ,m_compressFile(compress_entry)
{
}

DASHManifestHandler::SegmentEntry::SegmentEntry(LIBMPDPP_NAMESPACE_CLASS(SegmentAvailability) &&seg_avail, bool force_recache,
                                                bool keep_after_send, bool compress_entry)
    :LIBMPDPP_NAMESPACE_CLASS(SegmentAvailability)(std::move(seg_avail))
    ,m_forceRecache(force_recache)
    ,m_keepAfterSend(keep_after_send)
    ,m_compressFile(compress_entry)
{
}

DASHManifestHandler::SegmentEntry::SegmentEntry(
                                const LIBMPDPP_NAMESPACE_CLASS(SegmentAvailability::time_type) &availability_start,
                                const LIBMPDPP_NAMESPACE_CLASS(SegmentAvailability::duration_type) &segment_length,
                                const LIBMPDPP_NAMESPACE_CLASS(URI) &segment_url,
                                const std::optional<LIBMPDPP_NAMESPACE_CLASS(SegmentAvailability::time_type)> &availability_end,
                                bool force_recache, bool keep_after_send, bool compress_entry)
    :LIBMPDPP_NAMESPACE_CLASS(SegmentAvailability)(availability_start, segment_length, segment_url, availability_end)
    ,m_forceRecache(force_recache)
    ,m_keepAfterSend(keep_after_send)
    ,m_compressFile(compress_entry)
{
}

DASHManifestHandler::SegmentEntry &DASHManifestHandler::SegmentEntry::operator=(const DASHManifestHandler::SegmentEntry &other) {
    LIBMPDPP_NAMESPACE_CLASS(SegmentAvailability::operator=)(other);
    m_forceRecache = other.m_forceRecache;
    m_keepAfterSend = other.m_keepAfterSend;
    m_compressFile = other.m_compressFile;
    return *this;
}

DASHManifestHandler::SegmentEntry &DASHManifestHandler::SegmentEntry::operator=(DASHManifestHandler::SegmentEntry &&other) {
    LIBMPDPP_NAMESPACE_CLASS(SegmentAvailability::operator=)(std::move(other));
    m_forceRecache = other.m_forceRecache;
    m_keepAfterSend = other.m_keepAfterSend;
    m_compressFile = other.m_compressFile;
    return *this;
}

static bool g_registered = ManifestHandlerFactory::registerManifestHandler("application/dash+xml", new ManifestHandlerConstructorClass<DASHManifestHandler>());

static LIBMPDPP_NAMESPACE_CLASS(MPD) ingest_manifest(const std::shared_ptr<ObjectStore::Object> &new_manifest)
{
    if ( new_manifest->second.mediaType() != "application/dash+xml" ){
         throw std::invalid_argument("Does not look like a DASH Manifest as the media type is invalid. Expected media type: application/dash+xml");
    }
    return LIBMPDPP_NAMESPACE_CLASS(MPD) (new_manifest->first, new_manifest->second.getFetchedUrl());
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
