/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Object Manifest Handler class
 ******************************************************************************
 * Copyright: (C)2026 British Broadcasting Corporation
 * Author(s): David Waring <david.waring2@bbc.co.uk>
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

#include "ogs-app.h"
#include "ogs-sbi.h" // include before "common.hh" to ensure correct logging domain

#include <libmpd++/BaseURL.hh>
#include <libmpd++/URI.hh>

#include "common.hh"
#include "DistributionSession.hh"
#include "ManifestHandler.hh"
#include "ManifestHandlerFactory.hh"
#include "ObjectController.hh"
#include "ObjectStore.hh"
#include "PullObjectIngester.hh"
#include "utilities.hh"
#include "openapi/model/ObjectManifest.h"

#include "ObjectManifestHandler.hh"

using namespace std::literals::chrono_literals;
using fiveg_mag_reftools::ModelException;
using reftools::mbstf::ObjectManifest;
using reftools::mbstf::Object;

LIBMPDPP_NAMESPACE_USING(BaseURL);
LIBMPDPP_NAMESPACE_USING(URI);

MBSTF_NAMESPACE_START

using time_type = std::chrono::system_clock::time_point;

static ObjectManifest ingest_manifest(const std::shared_ptr<ObjectStore::Object> &new_manifest);

ObjectManifestHandler::ObjectManifestHandler(const std::shared_ptr<ObjectStore::Object> &object, ObjectController *controller,
                                             bool pull_distribution)
    :ManifestHandler(controller, pull_distribution)
    ,m_objectManifestMutex(new decltype(m_objectManifestMutex)::element_type())
    ,m_objectManifest(ingest_manifest(object))
    ,m_objectMetadataCache()
    ,m_manifestFile(object)
    ,m_refreshManifest(false)
{
    std::lock_guard<decltype(m_objectManifestMutex)::element_type> lock(*m_objectManifestMutex);
    auto now = datetime_type::clock::now();
    for (auto &obj : m_objectManifest.getObjects()) {
        if (!obj || !obj.value()) continue;
        auto fetch_time = now;
        auto &lft = obj.value()->getLatestFetchTime();
        if (lft && fetch_time >= iso8601_utc_str_to_time_point(lft.value())) continue;
        auto &eft = obj.value()->getEarliestFetchTime();
        if (eft) {
            auto eft_dt = iso8601_utc_str_to_time_point(eft.value());
            if (fetch_time < eft_dt) fetch_time = eft_dt;
        }
        m_objectMetadataCache.insert(std::make_pair(obj.value().get(), ObjectMetadataCache{fetch_time, false}));
    }
}

ObjectManifestHandler::~ObjectManifestHandler()
{
}

std::pair<ManifestHandler::time_type, ManifestHandler::ingest_list> ObjectManifestHandler::nextIngestItems()
{
    if (!m_manifestFile) {
        ogs_debug("No ObjectManifest file");
        return std::make_pair(ManifestHandler::time_type(), ManifestHandler::ingest_list());
    }

    ManifestHandler::time_type ingest_time;
    ManifestHandler::ingest_list ingest_items;

    auto current_time = std::chrono::system_clock::now();

    std::lock_guard<decltype(m_objectManifestMutex)::element_type> lock(*m_objectManifestMutex);

    if (m_pullDistribution) {
        auto &manifest_update_interval = m_objectManifest.getUpdateInterval();
        if (manifest_update_interval && !m_refreshManifest) {
            /* update manifest at last received time + update interval */
            ingest_time = m_manifestFile->second.receivedTime() + std::chrono::seconds(manifest_update_interval.value());
            ingest_items.push_back(PullObjectIngester::IngestItem(m_manifestFile->second));
            ogs_debug("%s", std::format("Added manifest refresh at {}", ingest_time).c_str());
        }
    }

    for (auto &obj : m_objectManifest.getObjects()) {
        /* No object, then skip this entry */
        if (!obj || !obj.value()) continue;

        /* If we've past the latest fetch time then skip this entry */
        auto &latest_fetch_time = obj.value()->getLatestFetchTime();
        datetime_type latest_fetch_dt;
        if (latest_fetch_time) {
            latest_fetch_dt = iso8601_utc_str_to_time_point(latest_fetch_time.value());
            if (latest_fetch_dt <= current_time) continue;
        }

        /* find the metadata entry for this object in the ObjectStore */
        auto &object_store = m_controller->objectStore();
        auto obj_locator = obj.value()->getLocator();
        auto obj_metadata_ptr = object_store.findMetadataByURL(obj_locator);

        auto it = m_objectMetadataCache.find(obj.value().get());
        if (it != m_objectMetadataCache.end() && !it->second.beenRequested) {
            ObjectStore::Metadata fetch_object_metadata;
            ManifestHandler::time_type obj_fetch_time = it->second.nextFetchTime;

            if (obj_metadata_ptr) {
                fetch_object_metadata = *obj_metadata_ptr;
                ogs_debug("%s", std::format("Object {} at {} to be refetched at {}", fetch_object_metadata.objectId(), obj_locator, obj_fetch_time).c_str());
            } else {
                fetch_object_metadata = ObjectStore::Metadata(nextObjectId(), std::string(), obj_locator, obj_locator, obj_locator, ObjectStore::Metadata::datetime_type());
                ogs_debug("%s", std::format("Object at {} to be fetched at {}", obj_locator, obj_fetch_time).c_str());
            }

            if (obj_fetch_time < current_time) obj_fetch_time = current_time;
            if (ingest_items.empty()) {
                ingest_time = obj_fetch_time;
            } else if (obj_fetch_time < ingest_time) {
                ogs_debug("Reset ingest list to contain the object");
                ingest_items.clear();
                ingest_time = obj_fetch_time;
            }
            if (ingest_time == obj_fetch_time) {
                ogs_debug("Adding object to ingest list");
                ingest_items.push_back(PullObjectIngester::IngestItem(fetch_object_metadata));
            }
        }
    }

    ogs_debug("%s", std::format("Return {} items to be fetched at {}", ingest_items.size(), ingest_time).c_str());

    return std::make_pair(ingest_time, ingest_items);
}

ManifestHandler::durn_type ObjectManifestHandler::getDefaultDeadline()
{
    return 10s; /* wait up to 10 seconds for objects in the manifest to arrive */
}

bool ObjectManifestHandler::update(const std::shared_ptr<ObjectStore::Object> &new_manifest_obj)
{
    // Process the new ObjectManifest and see what has changed, throw an exception of the Object is not understood or invalid

    std::lock_guard<decltype(m_objectManifestMutex)::element_type> lock(*m_objectManifestMutex);
    auto new_manifest = ingest_manifest(new_manifest_obj);
    m_manifestFile = new_manifest_obj;

    m_objectManifest.setUpdateInterval(new_manifest.getUpdateInterval());

    const auto &new_objects = new_manifest.getObjects();
    const auto &old_objects = m_objectManifest.getObjects();
    for (auto old_it = old_objects.begin(); old_it != old_objects.end(); old_it++) {
        if (!*old_it || !old_it->value()) continue;
        auto new_it = std::find_if(new_objects.begin(), new_objects.end(), [&old_it](const auto &new_obj) -> bool {
                                    if (!new_obj || !new_obj.value()) return false;
                                    return (old_it->value()->getLocator() == new_obj.value()->getLocator());
                                });
        if (new_it == new_objects.end()) {
            /* object removed from carousel */
            auto &object_store = m_controller->objectStore();
            object_store.removeObject(object_store.findMetadataByURL(old_it->value()->getLocator())->objectId());
            m_objectMetadataCache.erase(old_it->value().get());
            m_objectManifest.removeObjects(*old_it);
        } else {
            /* object same or update */
            (*old_it->value()) = std::move(*new_it->value());
            new_manifest.removeObjects(*new_it);
        }
    }

    auto now = datetime_type::clock::now();
    for (const auto &obj : new_objects) {
        if (!obj || !obj.value()) continue;
        auto fetch_time = now;
        auto &lft = obj.value()->getLatestFetchTime();
        if (lft && fetch_time >= iso8601_utc_str_to_time_point(lft.value())) continue;
        auto &eft = obj.value()->getEarliestFetchTime();
        if (eft) {
            auto eft_dt = iso8601_utc_str_to_time_point(eft.value());
            if (fetch_time < eft_dt) fetch_time = eft_dt;
        }
        m_objectMetadataCache.insert(std::make_pair(obj.value().get(), ObjectMetadataCache{fetch_time, false}));
        m_objectManifest.addObjects(obj);
    }

    m_refreshManifest = false;

    ObjectManifestChangeEvent evt;
    sendEventSynchronous(evt);

    return true; // update completed successfully
}

void ObjectManifestHandler::startedFetch(const PullObjectIngester::IngestItem &ingest_item)
{
    auto &api_objects = m_objectManifest.getObjects();
    auto api_obj_it = std::find_if(api_objects.begin(), api_objects.end(), [&ingest_item](const auto &obj) -> bool {
                            if (!obj || !obj.value()) return false;
                            if (ingest_item.acquisitionId() == obj.value()->getLocator()) return true;
                            return false;
                        });
    if (api_obj_it == api_objects.end()) {
        /* if the ingest item is the manifest, set the refreshing flag */
        if (ingest_item.objectId() == m_manifestFile->second.objectId()) {
            m_refreshManifest = true;
        }
    } else if (*api_obj_it && api_obj_it->value()) {
        auto obj_cache_it = m_objectMetadataCache.find(api_obj_it->value().get());
        if (obj_cache_it != m_objectMetadataCache.end()) {
            obj_cache_it->second.beenRequested = true;
        }
    }
}

std::string ObjectManifestHandler::nextObjectId()
{
    return generateUUID();
}

const ObjectManifest::ObjectsType &ObjectManifestHandler::getObjects() const
{
    std::lock_guard<decltype(m_objectManifestMutex)::element_type> lock(*m_objectManifestMutex);
    return m_objectManifest.getObjects();
}

std::list<std::shared_ptr<Object> > ObjectManifestHandler::getActiveObjects() const
{
    std::lock_guard<decltype(m_objectManifestMutex)::element_type> lock(*m_objectManifestMutex);
    std::list<std::shared_ptr<Object> > retval;

    auto now = std::chrono::system_clock::now();

    for (const auto &obj : m_objectManifest.getObjects()) {
        if (!obj || !obj.value()) continue;
        const auto &eft = obj.value()->getEarliestFetchTime();
        if (eft && iso8601_utc_str_to_time_point(eft.value()) > now) continue;
        const auto &lft = obj.value()->getLatestFetchTime();
        if (lft && iso8601_utc_str_to_time_point(lft.value()) < now) continue;
        retval.push_back(obj.value());
    }

    return retval;
}

double ObjectManifestHandler::getRepetitionIntervalForUrl(const std::string &url) const
{
    std::lock_guard<decltype(m_objectManifestMutex)::element_type> lock(*m_objectManifestMutex);
    for (const auto &obj : m_objectManifest.getObjects()) {
        if (!obj || !obj.value()) continue;
        const auto &rep_interval = obj.value()->getRepetitionInterval();
        auto locator = obj.value()->getLocator();
        if (locator == url) {
            if (rep_interval) {
                ogs_debug("Object %s has %lfs repetition interval", url.c_str(), static_cast<double>(rep_interval.value())/1000.0);
                return static_cast<double>(rep_interval.value())/1000.0;
            }
            return NAN;
        }
    }
    return NAN;
}

bool ObjectManifestHandler::isObjectURLActive(const std::string &url) const
{
    std::lock_guard<decltype(m_objectManifestMutex)::element_type> lock(*m_objectManifestMutex);
    auto now = std::chrono::system_clock::now();
    for (const auto &obj : m_objectManifest.getObjects()) {
        if (!obj || !obj.value()) continue;
        const auto &locator = obj.value()->getLocator();
        if (locator == url) {
            const auto &eft = obj.value()->getEarliestFetchTime();
            if (eft && iso8601_utc_str_to_time_point(eft.value()) > now) return false;
            const auto &lft = obj.value()->getLatestFetchTime();
            if (lft && iso8601_utc_str_to_time_point(lft.value()) < now) return false;
            return true;
        }
    }
    return false;
}

void ObjectManifestHandler::finishRequest(const std::string &url)
{
    std::lock_guard<decltype(m_objectManifestMutex)::element_type> lock(*m_objectManifestMutex);
    auto &object_store = m_controller->objectStore();
    for (const auto &obj : m_objectManifest.getObjects()) {
        if (!obj || !obj.value()) continue;
        std::string obj_locator = obj.value()->getLocator();
        if (obj_locator == url) {
            auto obj_meta_it = m_objectMetadataCache.find(obj.value().get());
            if (obj_meta_it != m_objectMetadataCache.end()) {
                obj_meta_it->second.beenRequested = false;
                auto obj_metadata_ptr = object_store.findMetadataByURL(obj_locator);
                auto &keep_updated_interval = obj.value()->getKeepUpdatedInterval();
                std::optional<datetime_type> next_fetch_time;
                if (obj_metadata_ptr) {
                    /* have the object so use cache expiry or keepUpdatedInterval, if available */
                    next_fetch_time = obj_metadata_ptr->ExpiryTime();
                    if (keep_updated_interval) {
                        auto update_time = obj_meta_it->second.nextFetchTime + std::chrono::seconds(keep_updated_interval.value());
                        if (update_time < next_fetch_time) next_fetch_time = update_time;
                    }
                } else {
                    /* Use keepUpdatedInterval, if available */
                    if (keep_updated_interval) {
                        next_fetch_time = obj_meta_it->second.nextFetchTime + std::chrono::seconds(keep_updated_interval.value());
                    }
                }

                if (next_fetch_time) {
                    obj_meta_it->second.nextFetchTime = next_fetch_time.value();
                } else {
                    /* no next fetch time, so remove from updates */
                    m_objectMetadataCache.erase(obj_meta_it);
                }
                ObjectManifestChangeEvent evt;
                sendEventSynchronous(evt);
            }
        }
    }
}

/* private: */

std::string ObjectManifestHandler::generateUUID() {
    uuid_t uuid;
    uuid_generate_random(uuid);
    char uuid_str[37];
    uuid_unparse(uuid, uuid_str);
    return std::string(uuid_str);
}

/* ManifestHandler registration */

static bool g_registered1 = ManifestHandlerFactory::registerManifestHandler("application/3gpp-mbs-object-manifest+json", new ManifestHandlerConstructorClass<ObjectManifestHandler>());
static bool g_registered2 = ManifestHandlerFactory::registerManifestHandler("application/3gpp-mbs-object-manifest+json;version=Rel17", new ManifestHandlerConstructorClass<ObjectManifestHandler>());
static bool g_registered3 = ManifestHandlerFactory::registerManifestHandler("application/3gpp-mbs-object-manifest+json;version=\"Rel17\"", new ManifestHandlerConstructorClass<ObjectManifestHandler>());

/* local functions */

static ObjectManifest ingest_manifest(const std::shared_ptr<ObjectStore::Object> &new_manifest)
{
    auto &new_metadata = new_manifest->second;
    ogs_debug("%s", std::format("ingest_manifest: mediaType() = {}", new_metadata.mediaType()).c_str());
    if (new_metadata.mediaType() != "application/3gpp-mbs-object-manifest+json" &&
        new_metadata.mediaType() != "application/3gpp-mbs-object-manifest+json;version=Rel17" &&
        new_metadata.mediaType() != "application/3gpp-mbs-object-manifest+json;version=\"Rel17\""){
         throw std::invalid_argument("Does not look like an ObjectManifest as the media type is invalid. Expected media type: application/3gpp-mbs-object-manifest+json;version=\"Rel17\"");
    }
    
    try {
        auto json = CJson::parse(std::string(reinterpret_cast<const char*>(new_manifest->first.data()), new_manifest->first.size()));
        return ObjectManifest(json, true);
    } catch (ModelException &ex) {
        ogs_debug("%s", std::format("Does not look like an ObjectManifest: {}", ex.what()).c_str());
        throw std::invalid_argument(std::format("Does not look like an ObjectManifest: {}", ex.what()));
    }
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
