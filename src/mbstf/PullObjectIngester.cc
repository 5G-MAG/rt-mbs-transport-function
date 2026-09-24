/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Pull Object Ingester
 ******************************************************************************
 * Copyright: (C)2025-2026 British Broadcasting Corporation
 * Author(s): Dev Audsin <dev.audsin@bbc.co.uk>
 *            David Waring <david.waring2@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */
#include "ogs-sbi.h" // include before "common.hh" to get correct logging domain

#include <memory>
#include <stdexcept>
#include <utility>
#include <chrono>
#include <iostream>
#include <string>

#include <libmpd++/BaseURL.hh>
#include <libmpd++/URI.hh>

#include "common.hh"
#include "App.hh"
#include "PullObjectIngester.hh"
#include "hash.hh"
#include "Curl.hh"
#include "ObjectStore.hh"

LIBMPDPP_NAMESPACE_USING(BaseURL);
LIBMPDPP_NAMESPACE_USING(URI);
using namespace std::literals::chrono_literals;

MBSTF_NAMESPACE_START

/***** PullObjectIngester::IngestItem methods *****/

PullObjectIngester::IngestItem::IngestItem(const ObjectStore::Metadata &object_meta,
                                           const std::optional<time_type> &download_deadline, bool force_recache,
                                           bool keep_after_send, bool compress_send)
    :m_objectId(object_meta.objectId())
    ,m_url(object_meta.getFetchedUrl())
    ,m_acquisitionId(object_meta.acquisitionId())
    ,m_objIngestBaseUrl(object_meta.objIngestBaseUrl())
    ,m_objDistributionBaseUrl(object_meta.objDistributionBaseUrl())
    ,m_deadline(download_deadline)
    ,m_forceRecache(force_recache)
    ,m_markAsKeepAfterSend(keep_after_send)
    ,m_markAsCompressedSend(compress_send)
    ,m_fetchFailures(0)
    ,m_availabilityStartTime(object_meta.availabilityStartTime())
    ,m_availabilityEndTime(object_meta.availabilityEndTime())
{
}

PullObjectIngester::IngestItem::IngestItem(const std::string &object_id, const std::string &url, const std::string &acquisition_id, const std::optional<std::string> &obj_ingest_base_url,  const std::optional<std::string> &obj_distribution_base_url, const std::optional<time_type> &download_deadline, bool force_recache, bool keep_after_send, bool compress_send, const std::optional<time_type> &availability_start_time, const std::optional<time_type> &availability_end_time)
    :m_objectId(object_id)
    ,m_url(url)
    ,m_acquisitionId(acquisition_id)
    ,m_objIngestBaseUrl(obj_ingest_base_url)
    ,m_objDistributionBaseUrl(obj_distribution_base_url)
    ,m_deadline(download_deadline)
    ,m_forceRecache(force_recache)
    ,m_markAsKeepAfterSend(keep_after_send)
    ,m_markAsCompressedSend(compress_send)
    ,m_fetchFailures(0)
    ,m_availabilityStartTime(availability_start_time)
    ,m_availabilityEndTime(availability_end_time)
{
}

PullObjectIngester::IngestItem::IngestItem(const IngestItem &other)
    :m_objectId(other.m_objectId)
    ,m_url(other.m_url)
    ,m_acquisitionId(other.m_acquisitionId)
    ,m_objIngestBaseUrl(other.m_objIngestBaseUrl)
    ,m_objDistributionBaseUrl(other.m_objDistributionBaseUrl)
    ,m_deadline(other.m_deadline)
    ,m_forceRecache(other.m_forceRecache)
    ,m_markAsKeepAfterSend(other.m_markAsKeepAfterSend)
    ,m_markAsCompressedSend(other.m_markAsCompressedSend)
    ,m_fetchFailures(other.m_fetchFailures)
    ,m_availabilityStartTime(other.m_availabilityStartTime)
    ,m_availabilityEndTime(other.m_availabilityEndTime)
{
}

PullObjectIngester::IngestItem::IngestItem(IngestItem &&other)
    :m_objectId(std::move(other.m_objectId))
    ,m_url(std::move(other.m_url))
    ,m_acquisitionId(std::move(other.m_acquisitionId))
    ,m_objIngestBaseUrl(std::move(other.m_objIngestBaseUrl))
    ,m_objDistributionBaseUrl(std::move(other.m_objDistributionBaseUrl))
    ,m_deadline(std::move(other.m_deadline))
    ,m_forceRecache(other.m_forceRecache)
    ,m_markAsKeepAfterSend(other.m_markAsKeepAfterSend)
    ,m_markAsCompressedSend(other.m_markAsCompressedSend)
    ,m_fetchFailures(other.m_fetchFailures)
    ,m_availabilityStartTime(std::move(other.m_availabilityStartTime))
    ,m_availabilityEndTime(std::move(other.m_availabilityEndTime))
{
}

/***** PullObjectIngester::PullIngestFailedEvent methods *****/

std::string PullObjectIngester::PullIngestFailedEvent::reprString() const {
    return std::format("PullIngestFailedEvent(<item>, \"{}\", {})", url(), static_cast<int>(failureType()));
}

/***** PullObjectIngester methods *****/

PullObjectIngester::~PullObjectIngester() {
    if (m_curl) m_curl->abortFetch();
    abort();
}

bool PullObjectIngester::fetch(const std::string &object_id, const std::optional<time_type> &download_deadline, bool force_recache, bool keep_after_send, bool compress_send, unsigned fetch_failures)
{
    std::lock_guard<std::recursive_mutex> lock(*m_ingestItemsMutex);

    // If this is a fetch for an already pending fetch object, just update the current fetch list item
    decltype(m_fetchList)::iterator it;
    for (it = m_fetchList.begin(); it != m_fetchList.end(); ++it) {
        if (it->objectId() == object_id) {
            if (download_deadline.has_value()) {
                it->deadline(download_deadline.value());
            }
            it->forceRecache(it->forceRecache() || force_recache);
            it->markAsKeepAfterSend(it->markAsKeepAfterSend() || keep_after_send);
            it->markAsCompressedSend(it->markAsCompressedSend() || compress_send);
            break;
        }
    }

    // otherwise we need a new fetch based on the ObjectStore entry
    if (it == m_fetchList.end()) {
        // Copied under the store's own lock: see ObjectStore::takeMetadataForIngest(). This
        // constructor always starts m_fetchFailures at 0 -- a genuinely new item is meant to -- so
        // a retry landing here (the object was already popped from m_fetchList by the failure that
        // is being retried; see fetch(IngestItem&&) below) must reapply its own prior count itself,
        // or ObjectManifestController's per-object consecutiveIngestFailuresBeforeDeactivate count
        // silently restarts from zero on every single failure and never reaches its limit.
        auto &new_item = m_fetchList.emplace_back(objectStore()->takeMetadataForIngest(object_id, keep_after_send, compress_send),
                                 download_deadline, force_recache);
        if (fetch_failures) new_item.fetchFailures(fetch_failures);
    }

    sortListByPolicy();
    m_ingestItemsCondVar.notify_all();

    return true;
}

bool PullObjectIngester::fetch(const IngestItem &item) {
    return fetch(std::move(IngestItem(item)));
}

bool PullObjectIngester::fetch(IngestItem &&item) {
    std::lock_guard<std::recursive_mutex> lock(*m_ingestItemsMutex);
    try {
        // Marked under the store's own lock rather than through a reference it has stopped
        // guarding: see ObjectStore::markForFetch(). Throws out_of_range when there is no previous
        // version, which the catch below already handles.
        objectStore()->markForFetch(item.objectId(), item.markAsKeepAfterSend(), item.markAsCompressedSend());
        return fetch(item.objectId(), item.deadline(), item.forceRecache(), item.markAsKeepAfterSend(), item.markAsCompressedSend(), item.fetchFailures());
    } catch (const std::out_of_range &ex) {
        // No previous version, this isn't a refresh, but may still be a re-request for an existing list item
        decltype(m_fetchList)::iterator it;
        for (it = m_fetchList.begin(); it != m_fetchList.end(); ++it) {
            if (it->objectId() == item.objectId()) {
                if (item.deadline().has_value()) {
                    it->deadline(item.deadline().value());
                }
                it->forceRecache(it->forceRecache() || item.forceRecache());
                it->markAsKeepAfterSend(it->markAsKeepAfterSend() || item.markAsKeepAfterSend());
                it->markAsCompressedSend(it->markAsCompressedSend() || item.markAsCompressedSend());
                break;
            }
        }

        // otherwise we need a new fetch based on the ObjectStore entry
        if (it == m_fetchList.end()) {
            m_fetchList.push_back(std::move(item));
        }

        sortListByPolicy();
        m_ingestItemsCondVar.notify_all();
    }
    return true;
}

void PullObjectIngester::sortListByPolicy() {
    m_fetchList.sort([](const IngestItem &a, const IngestItem &b) {
        if (a.deadline().has_value() && b.deadline().has_value()) {
            return a.deadline() < b.deadline();
        }
        return a.deadline().has_value();
    });
}

void PullObjectIngester::doObjectIngest() {
    if (!m_curl) {
        m_curl = std::make_shared<Curl>();
    }

    {
        std::lock_guard<std::recursive_mutex> lock(*m_ingestItemsMutex);
        if (m_fetchList.empty()) {
            m_ingestItemsCondVar.wait_for(*m_ingestItemsMutex, 500ms);
        }
        if (!m_fetchList.empty()) {
            // Make the GET request and get the number of bytes received
            auto item = m_fetchList.front();
            m_fetchList.pop_front();
            m_ingestItemsMutex->unlock(); // temp unlock while we fetch
            /* A copy taken under the store lock, not a reference into the store. This is read
               again further down, after the fetch below has run with the ingest list unlocked, and a
               store entry can be replaced by updateMetadata() or erased entirely while that is in
               flight. See ObjectStore::tryGetMetadata(). */
            std::optional<ObjectStore::Metadata> old_meta = objectStore()->tryGetMetadata(item.objectId());
            if (old_meta) {
                if (!item.forceRecache() && old_meta->hasExpiryTime() && old_meta->ExpiryTime() > ObjectStore::datetime_type::clock::now()) {
                    // Existing store item is still fresh
                    ogs_debug("Reusing cached object for %s instead of fetching again", item.url().c_str());
                    // "Update" (using same metadata) in the ObjectStore to set last used timestamps and trigger update event
                    ObjectStore::Metadata metadata(*old_meta);
                    try {
                        this->objectStore()->updateMetadata(old_meta->objectId(), std::move(metadata), true);
                    } catch (std::runtime_error &ex) {
                        ogs_warn("While reusing cached object %s: %s", item.url().c_str(), ex.what());
                        emitObjectPullIngestFailedEvent(item, item.url(), ObjectIngester::IngestFailedEvent::GENERAL_ERROR);
                    }
                    m_ingestItemsMutex->lock(); // lock so that the lock_guard can release properly
                    return;
                }
                const auto &file_desc = old_meta->fluteFileDescription();
                if (file_desc) {
                    ogs_debug("Refetching %s (TOI %u)...", item.url().c_str(), file_desc->toi());
                } else {
                    ogs_debug("Refetching %s...", item.url().c_str());
                }
            } else {
                ogs_debug("Fetching %s...", item.url().c_str());
            }

            const auto &deadline = item.deadline();
            std::chrono::milliseconds timeout(10000);
            if (deadline) {
                timeout = std::chrono::duration_cast<std::chrono::milliseconds>(
                                                            deadline.value() - std::chrono::system_clock::now());
            }
            long bytesReceived = -1;
            if (timeout > 0s) {
                if (old_meta) {
                    bytesReceived = m_curl->get(item.url(), timeout, old_meta->modified(), old_meta->entityTag());
                } else {
                    bytesReceived = m_curl->get(item.url(), timeout);
                }
            } else {
                // Already missed the deadline, act as though timed out
                bytesReceived = -1;
            }

            // Check the result
            if (bytesReceived >= 0) {
                ogs_debug("Received %ld bytes of data", bytesReceived);
                std::string fetched_url = URI(m_curl->getPermanentRedirectUrl()).resolveUsingBaseURLs(std::list<BaseURL>{BaseURL(item.url())}).str();
                if (fetched_url.empty()) fetched_url = item.url();

                /* An object with no media type cannot be described conformantly: TS 26.517 V18.6.0
                   clause 6.2.1 binds the MBSTF to the MBMS Download Profile, and TS 26.346 V18.2.0
                   clause L.4.2 lists Content-Type first among the attributes that "shall be carried
                   in the FDT sent by the FLUTE sender".

                   The origin not sending one is refused rather than inferred from the object's
                   filename or guessed from its content. This reference implementation is what an
                   MBS Application Provider integrates against, and covering for one that omits
                   Content-Type would hide the very shortcoming an integrator needs to see, rather
                   than let it surface as a clear ingest failure. Raised by review on
                   5G-MAG/rt-mbs-transport-function#74, which had this MBSTF inferring the type
                   before this. */
                std::string media_type = m_curl->getContentType();
                if (media_type.empty()) {
                    ogs_warn("Ingest of [%s] failed: the origin sent no Content-Type; an object with "
                             "no media type cannot be carried in a conformant FDT",
                             item.url().c_str());
                    emitObjectPullIngestFailedEvent(item, item.url(),
                                                    ObjectIngester::IngestFailedEvent::GENERAL_ERROR);
                    m_ingestItemsMutex->lock(); // lock so that the lock_guard can release properly
                    return;
                }

                ObjectStore::Metadata metadata(item.objectId(), media_type, item.url(), fetched_url, item.acquisitionId(), m_curl->getLastModified(), item.objIngestBaseUrl(), item.objDistributionBaseUrl());
                /* re-get metadata from ObjectStore as it may have changed, again as a copy taken
                   under the store lock rather than a reference it has stopped guarding */
                old_meta = objectStore()->tryGetMetadata(item.objectId());
                if (old_meta) {
                    metadata.fluteFileDescription(old_meta->fluteFileDescription());
                    metadata.keepAfterSend(old_meta->keepAfterSend() || item.markAsKeepAfterSend());
                } else {
                    metadata.keepAfterSend(item.markAsKeepAfterSend());
                }
                // TS 26.517 V18.6.0 clause 6.2.3.5 requires the object's availability start and end
                // times to be maintained per object in the object list. They reach the ingester on the
                // IngestItem and are stored here so ObjectListPackager can set File@Expires and
                // Cache-Control@Expires from them.
                metadata.availabilityStartTime(item.availabilityStartTime());
                metadata.availabilityEndTime(item.availabilityEndTime());

                unsigned long max_age = m_curl->getCacheControlMaxAge();
                unsigned long current_age = m_curl->getAge();
                metadata.cacheExpires(max_age ? std::chrono::system_clock::now() + std::chrono::seconds(max_age) - std::chrono::seconds(current_age) : std::chrono::system_clock::now() + std::chrono::seconds(ObjectStore::Metadata::cacheExpiry()));
                const std::string& etag = m_curl->getEtag();
                if (!etag.empty()) {
                    metadata.entityTag(etag);
                }
                auto response_code = m_curl->getResponseCode();
                if (response_code >= 200 && response_code <= 299) {
                    /* received object - store it */
                    try {
                        this->objectStore()->addObject(item.objectId(), std::move(m_curl->getData()), std::move(metadata), true);
                    } catch (std::runtime_error &ex) {
                        // Add to ObjectStore failed, send error
                        ogs_warn("While adding a new object: %s", ex.what());
                        emitObjectPullIngestFailedEvent(item, item.url(), ObjectIngester::IngestFailedEvent::GENERAL_ERROR);
                    }
                } else if (response_code == 304) {
                    /* Not Modified - just update metadata */
                    if (old_meta) {
                        metadata.mediaType(old_meta->mediaType()); // 304 may not have Content-Type due to no content
                        try {
                            this->objectStore()->updateMetadata(item.objectId(), std::move(metadata), true);
                        } catch (std::runtime_error &ex) {
                            // Update in ObjectStore failed, send error
                            ogs_warn("While updating object metadata: %s", ex.what());
                            emitObjectPullIngestFailedEvent(item, item.url(), ObjectIngester::IngestFailedEvent::GENERAL_ERROR);
                        }
                    }
                } else {
                    /* error response - do we throw the object away? */
                    ogs_debug("Fetch error %i", response_code);
                    emitObjectPullIngestFailedEvent(item, fetched_url, (response_code >= 400 && response_code <= 499)?ObjectIngester::IngestFailedEvent::CLIENT_ERROR:ObjectIngester::IngestFailedEvent::SERVER_ERROR);
                    this->objectStore()->updateError(item.objectId(), response_code, item.url(), false);
                }
            } else if (bytesReceived == -1) {
                ogs_error("Request timed out.");
                emitObjectPullIngestFailedEvent(item, item.url(), ObjectIngester::IngestFailedEvent::TIMED_OUT);
            } else {
                ogs_error("An error occurred while fetching the data.");
                emitObjectPullIngestFailedEvent(item, item.url(), ObjectIngester::IngestFailedEvent::GENERAL_ERROR);
            }
            m_ingestItemsMutex->lock();
            if (m_fetchList.empty()) sendEventAsynchronous(new ObjectPullQueueExhaustedEvent);
        }
    }
}

void PullObjectIngester::emitObjectPullIngestFailedEvent(const PullObjectIngester::IngestItem &item, const std::string &fetch_url,
                                                         IngestFailedEvent::FailureType fail_type)
{
    sendEventAsynchronous(PullIngestFailedEvent(item, fetch_url, fail_type));
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
