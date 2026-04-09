/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Object store
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

#include <algorithm>
#include <memory>
#include <stdexcept>
#include <utility>
#include <chrono>
#include <thread>
#include <mutex>
#include <iostream>
#include <new>

#include "ogs-app.h"
#include "ogs-sbi.h" // include before "common.hh" to get correct logging domain

#include "common.hh"

#include "SubscriptionService.hh"
#include "Event.hh"
#include "ObjectStore.hh"

MBSTF_NAMESPACE_START

/*****************************************************************************
 * ObjectStore::Metadata class
 *****************************************************************************/

ObjectStore::Metadata::Metadata()
    :m_objectId()
    ,m_mediaType()
    ,m_originalUrl()
    ,m_fetchedUrl()
    ,m_acquisitionId()
    ,m_keepAfterSend(false)
    ,m_objIngestBaseUrl()
    ,m_objDistributionBaseUrl()
    ,m_cacheExpires(std::nullopt)
    ,m_receivedTime(std::chrono::system_clock::now())
    ,m_created(std::chrono::system_clock::now())
    ,m_modified(std::chrono::system_clock::now())
    ,m_fileDescription()
{
}

ObjectStore::Metadata::Metadata(const std::string &object_id, const std::string &media_type, const std::string &url, const std::string &fetched_url,
                 const std::string &acquisition_id,
                 const std::chrono::system_clock::time_point last_modified,
                 std::optional<std::string> obj_ingest_base_url,
                 std::optional<std::string> obj_distribution_base_url,
                 const std::optional<std::chrono::system_clock::time_point> &cache_expires)
    :m_objectId(object_id)
    ,m_mediaType(media_type)
    ,m_originalUrl(url)
    ,m_fetchedUrl(fetched_url)
    ,m_acquisitionId(acquisition_id)
    ,m_keepAfterSend(false)
    ,m_objIngestBaseUrl(obj_ingest_base_url)
    ,m_objDistributionBaseUrl(obj_distribution_base_url)
    ,m_cacheExpires(cache_expires)
    ,m_receivedTime(std::chrono::system_clock::now())
    ,m_created(std::chrono::system_clock::now())
    ,m_modified(last_modified)
    ,m_fileDescription()
{
}

ObjectStore::Metadata::Metadata(const Metadata &other)
    :m_objectId(other.m_objectId)
    ,m_mediaType(other.m_mediaType)
    ,m_originalUrl(other.m_originalUrl)
    ,m_fetchedUrl(other.m_fetchedUrl)
    ,m_acquisitionId(other.m_acquisitionId)
    ,m_keepAfterSend(other.m_keepAfterSend)
    ,m_objIngestBaseUrl(other.m_objIngestBaseUrl)
    ,m_objDistributionBaseUrl(other.m_objDistributionBaseUrl)
    ,m_cacheExpires(other.m_cacheExpires)
    ,m_receivedTime(other.m_receivedTime)
    ,m_created(other.m_created)
    ,m_modified(other.m_modified)
    ,m_fileDescription(other.m_fileDescription)
{
}

ObjectStore::Metadata::Metadata(Metadata &&other)
    :m_objectId(std::move(other.m_objectId))
    ,m_mediaType(std::move(other.m_mediaType))
    ,m_originalUrl(std::move(other.m_originalUrl))
    ,m_fetchedUrl(std::move(other.m_fetchedUrl))
    ,m_acquisitionId(std::move(other.m_acquisitionId))
    ,m_keepAfterSend(std::move(other.m_keepAfterSend))
    ,m_objIngestBaseUrl(std::move(other.m_objIngestBaseUrl))
    ,m_objDistributionBaseUrl(std::move(other.m_objDistributionBaseUrl))
    ,m_cacheExpires(std::move(other.m_cacheExpires))
    ,m_receivedTime(std::move(other.m_receivedTime))
    ,m_created(std::move(other.m_created))
    ,m_modified(std::move(other.m_modified))
    ,m_fileDescription(std::move(other.m_fileDescription))
{
}

ObjectStore::Metadata &ObjectStore::Metadata::operator=(const ObjectStore::Metadata &other)
{
    m_objectId = other.m_objectId;
    m_mediaType = other.m_mediaType;
    m_originalUrl = other.m_originalUrl;
    m_fetchedUrl = other.m_fetchedUrl;
    m_acquisitionId = other.m_acquisitionId;
    m_keepAfterSend = other.m_keepAfterSend;
    m_objIngestBaseUrl = other.m_objIngestBaseUrl;
    m_objDistributionBaseUrl = other.m_objDistributionBaseUrl;
    m_cacheExpires = other.m_cacheExpires;
    m_receivedTime = other.m_receivedTime;
    m_created = other.m_created;
    m_modified = other.m_modified;
    m_fileDescription = other.m_fileDescription;

    return *this;
}

ObjectStore::Metadata &ObjectStore::Metadata::operator=(ObjectStore::Metadata &&other)
{
    m_objectId = std::move(other.m_objectId);
    m_mediaType = std::move(other.m_mediaType);
    m_originalUrl = std::move(other.m_originalUrl);
    m_fetchedUrl = std::move(other.m_fetchedUrl);
    m_acquisitionId = std::move(other.m_acquisitionId);
    m_keepAfterSend = std::move(other.m_keepAfterSend);
    m_objIngestBaseUrl = std::move(other.m_objIngestBaseUrl);
    m_objDistributionBaseUrl = std::move(other.m_objDistributionBaseUrl);
    m_cacheExpires = std::move(other.m_cacheExpires);
    m_receivedTime = std::move(other.m_receivedTime);
    m_created = std::move(other.m_created);
    m_modified = std::move(other.m_modified);
    m_fileDescription = std::move(other.m_fileDescription);

    return *this;
}

bool ObjectStore::Metadata::operator==(const ObjectStore::Metadata& other) const
{
    return m_keepAfterSend == other.m_keepAfterSend &&
           m_cacheExpires == other.m_cacheExpires &&
           m_receivedTime == other.m_receivedTime &&
           m_created == other.m_created &&
           m_modified == other.m_modified &&
           m_objectId == other.m_objectId &&
           m_mediaType == other.m_mediaType &&
           m_originalUrl == other.m_originalUrl &&
           m_fetchedUrl == other.m_fetchedUrl &&
           m_acquisitionId == other.m_acquisitionId &&
           m_objIngestBaseUrl == other.m_objIngestBaseUrl &&
           m_objDistributionBaseUrl == other.m_objDistributionBaseUrl &&
           m_entityTag == other.m_entityTag &&
           m_fileDescription.get() == other.m_fileDescription.get();
}

/*****************************************************************************
 * ObjectStore class
 *****************************************************************************/

ObjectStore::ObjectStore(ObjectController &controller)
    :SubscriptionService()
    ,m_controller(controller)
{
}

ObjectStore::~ObjectStore()
{
}

void ObjectStore::addObject(const std::string& object_id, ObjectData &&object, Metadata &&metadata, bool synchronous_event) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);

    try {
        std::shared_ptr<Object> obj(new std::pair(std::move(object), std::move(metadata)));
        m_store.insert_or_assign(object_id, obj);
    } catch (const std::bad_alloc& e) {
        ogs_error("memory allocation failed: %s", e.what());

    }

    /* send event */
    std::shared_ptr<Event> event(new ObjectStore::ObjectAddedEvent(object_id));
    if (synchronous_event) {
        sendEventSynchronous(*event);
    } else {
        sendEventAsynchronous(event);
    }
}

void ObjectStore::updateMetadata(const std::string& object_id, Metadata &&metadata, bool synchronous_event)
{
    std::lock_guard<decltype(m_mutex)> lock(m_mutex);

    auto it = m_store.find(object_id);
    if (it == m_store.end()) {
        throw std::out_of_range(std::format("Attempt to update Object {}, but it is not in the ObjectStore", object_id));
    }

    it->second->second = std::move(metadata);

    /* send event */
    std::shared_ptr<Event> event(new ObjectStore::ObjectUpdatedEvent(object_id));
    if (synchronous_event) {
        sendEventSynchronous(*event);
    } else {
        sendEventAsynchronous(event);
    }
}

void ObjectStore::updateError(const std::string& object_id, int response_code, const std::string &url, bool synchronous_event)
{
    /* TODO: Evict Object? */

    /* send event */
    std::shared_ptr<Event> event(new ObjectStore::ObjectUpdateErrorEvent(object_id, response_code, url));
    if (synchronous_event) {
        sendEventSynchronous(*event);
    } else {
        sendEventAsynchronous(event);
    }
}

const ObjectStore::ObjectData& ObjectStore::getObjectData(const std::string& object_id) const {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    return  m_store.at(object_id)->first;
}

ObjectStore::ObjectData& ObjectStore::getObjectData(const std::string& object_id) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    return m_store.at(object_id)->first;
}

const ObjectStore::Metadata& ObjectStore::getMetadata(const std::string& object_id) const {
   std::lock_guard<std::recursive_mutex> lock(m_mutex);
   return m_store.at(object_id)->second;
}

ObjectStore::Metadata& ObjectStore::getMetadata(const std::string& object_id) {
   std::lock_guard<std::recursive_mutex> lock(m_mutex);
   return m_store.at(object_id)->second;
}

void ObjectStore::deleteObject(const std::string& object_id) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    m_store.erase(object_id);
    std::shared_ptr<Event> event(new ObjectStore::ObjectDeletedEvent(object_id));
    sendEventAsynchronous(event);
}

const std::shared_ptr<ObjectStore::Object> &ObjectStore::operator[](const std::string& object_id) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    return m_store.at(object_id);
}

std::shared_ptr<const ObjectStore::Object> ObjectStore::operator[](const std::string& object_id) const {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    return m_store.at(object_id);
}

bool ObjectStore::isStale(const std::string& object_id) const {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    auto it = m_store.find(object_id);
    if (it == m_store.end()) {
        return false;
    }

    const Metadata& metadata = it->second->second;
    return metadata.cacheExpires().has_value() && metadata.cacheExpires().value() < std::chrono::system_clock::now();
}

std::map<std::string, std::shared_ptr<ObjectStore::Object> > ObjectStore::getStale() const {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    std::map<std::string, std::shared_ptr<ObjectStore::Object>> stale_objects;

    for (const auto& pair : m_store) {
        const std::string& object_id = pair.first;
        if (isStale(object_id)) {
            stale_objects.emplace(object_id, pair.second);
        }
    }

    return stale_objects;
}

bool ObjectStore::removeObject(const std::string& object_id) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    auto it = m_store.find(object_id);
    if (it != m_store.end()) {
        m_store.erase(it);
        return true;
    } else {
        return false;
    }
}

bool ObjectStore::removeObjects(const std::list<std::string>& object_ids) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    for (const auto& object_id : object_ids) {
        auto it = m_store.find(object_id);
        if (it != m_store.end()) {
            m_store.erase(it);
        }
    }
    return true;
}

const ObjectStore::Metadata *ObjectStore::findMetadataByURL(const std::string &url) const
{
    auto it = std::find_if(m_store.begin(), m_store.end(), [&url](const decltype(m_store)::value_type &obj){
            auto &metadata = obj.second->second;
            return metadata.getOriginalUrl() == url || metadata.getFetchedUrl() == url;
        });
    if (it != m_store.end()) return &it->second->second;
    return nullptr;
}

void ObjectStore::reconfigureMetadatas(const std::optional<std::string> &ingest_base_url,
                                       const std::optional<std::string> &distribution_base_url)
{
    for (auto &[obj_id, obj] : m_store) {
        obj->second.objIngestBaseUrl(ingest_base_url);
        obj->second.objDistributionBaseUrl(distribution_base_url);
    }
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
