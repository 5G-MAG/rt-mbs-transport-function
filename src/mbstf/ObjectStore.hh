#ifndef _MBS_TF_OBJECT_STORE_HH_
#define _MBS_TF_OBJECT_STORE_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Object Store class
 ******************************************************************************
 * Copyright: (C)2025 British Broadcasting Corporation
 * Author(s): Dev Audsin <dev.audsin@bbc.co.uk>
 *            David Waring <david.waring2@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#pragma once

#include <chrono>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <thread>
#include <utility>
#include <vector>

#include <Transmitter.h>

#include "common.hh"
#include "Event.hh"
#include "SubscriptionService.hh"

MBSTF_NAMESPACE_START

class ObjectController;
class SubscriptionService;
class Event;

#define CACHE_EXPIRES 10
#define CHECK_EXPIRY_INTERVAL 10

class ObjectStore: public SubscriptionService {
public:
    using datetime_type = std::chrono::system_clock::time_point;

    class ObjectAddedEvent : public Event {
    public:
        ObjectAddedEvent(const std::string& object_id)
            : Event("ObjectAdded"), m_object_id(object_id) {}

        std::string objectId() const { return m_object_id; }
        virtual ~ObjectAddedEvent() {};

    private:
        std::string m_object_id;
    };

    class ObjectDeletedEvent : public Event {
    public:
        ObjectDeletedEvent(const std::string& object_id)
            : Event("ObjectDeleted"), m_object_id(object_id) {}

        std::string objectId() const { return m_object_id; }
        virtual ~ObjectDeletedEvent() {};

    private:
        std::string m_object_id;
    };

    class Metadata {
    public:
        using datetime_type = ObjectStore::datetime_type;

        Metadata();

        Metadata(const std::string &object_id,
                 const std::string &media_type,
                 const std::string &url,
                 const std::string &fetched_url,
                 const std::string &acquisition_id,
                 const datetime_type last_modified,
                 std::optional<std::string> objIngestBaseUrl = std::nullopt,
                 std::optional<std::string> objDistributionBaseUrl = std::nullopt,
                 const std::optional<datetime_type> &cache_expires = std::nullopt);

        Metadata(const Metadata &other);
        Metadata(Metadata &&other);

        Metadata& operator=(const Metadata& other);
        Metadata& operator=(Metadata&& other);

        bool operator==(const Metadata& other) const;
        bool operator!=(const Metadata& other) const {return !(*this == other);};

        virtual ~Metadata() {};

        const std::string &getOriginalUrl() const {return m_originalUrl;};

        const std::string &getFetchedUrl() const {return m_fetchedUrl;};

        const std::string &objectId() const { return m_objectId;};
        Metadata &objectId(const std::string &object_id) { m_objectId = object_id; return *this;};

        const std::string &acquisitionId() const { return m_acquisitionId;};
        Metadata &acquisitionId(const std::string &acquistion_id) { m_acquisitionId = acquistion_id; return *this;};

        const std::string &mediaType() const {return m_mediaType;};
        Metadata &mediaType(const std::string &media_type) {m_mediaType = media_type; return *this;};
        Metadata &mediaType(std::string &&media_type) {m_mediaType = std::move(media_type); return *this;};

	bool hasExpiryTime() const { return m_cacheExpires.has_value(); };
	const datetime_type &ExpiryTime() const { return m_cacheExpires.value();};
        const std::optional<datetime_type>& cacheExpires() const { return m_cacheExpires;};
        std::optional<datetime_type>& cacheExpires(const datetime_type &cacheExpires) {
            m_cacheExpires = cacheExpires;
            return m_cacheExpires;
        };
        static int cacheExpiry()  {return CACHE_EXPIRES;};
        static int cacheExpiryInterval()  {return CHECK_EXPIRY_INTERVAL;};

        const std::optional<std::string> &entityTag() const { return m_entityTag;};

        bool hasEntityTag() {return m_entityTag.has_value();};

        Metadata &entityTag(const std::optional<std::string>& entityTag) {m_entityTag = entityTag; if (m_fileDescription && entityTag) m_fileDescription->set_etag(entityTag.value()); return *this;};

	Metadata &keepAfterSend(bool keep_after_send) {m_keepAfterSend = keep_after_send; return *this;};
        bool keepAfterSend() const { return m_keepAfterSend;};

        const std::optional<std::string> &objIngestBaseUrl() const { return m_objIngestBaseUrl;};
        Metadata &objIngestBaseUrl(const std::optional<std::string> &obj_ingest_base_url) {
            m_objIngestBaseUrl = obj_ingest_base_url;
            return *this;
        };
        Metadata &objIngestBaseUrl(const std::string &obj_ingest_base_url) {
            m_objIngestBaseUrl = obj_ingest_base_url;
            return *this;
        };
        Metadata &objIngestBaseUrl(std::nullopt_t) {m_objIngestBaseUrl.reset(); return *this;};

        const std::optional<std::string> &objDistributionBaseUrl() const { return m_objDistributionBaseUrl;};
        Metadata &objDistributionBaseUrl(const std::optional<std::string> &obj_distrib_base_url) {
            m_objDistributionBaseUrl = obj_distrib_base_url;
            return *this;
        };
        Metadata &objDistributionBaseUrl(const std::string &obj_distrib_base_url) {
            m_objDistributionBaseUrl = obj_distrib_base_url;
            return *this;
        };
        Metadata &objDistributionBaseUrl(std::nullopt_t) {m_objDistributionBaseUrl.reset(); return *this;};

	const datetime_type &receivedTime() const { return m_receivedTime;};
        Metadata &receivedTime(const datetime_type &val) { m_receivedTime = val; return *this; };
        Metadata &receivedTime(datetime_type &&val) { m_receivedTime = std::move(val); return *this; };

	const datetime_type &created() const { return m_created;};
        Metadata &created(const datetime_type &val) { m_created = val; return *this; };
        Metadata &created(datetime_type &&val) { m_created = std::move(val); return *this; };

	const datetime_type &modified() const { return m_modified;};
        Metadata &modified(const datetime_type &val) { m_modified = val; return *this; };
        Metadata &modified(datetime_type &&val) { m_modified = std::move(val); return *this; };

        const std::shared_ptr<LibFlute::Transmitter::FileDescription> &fluteFileDescription() const { return m_fileDescription; };
        Metadata &fluteFileDescription(const std::shared_ptr<LibFlute::Transmitter::FileDescription> &fd_ptr) {
            m_fileDescription = fd_ptr;
            return *this;
        };
        Metadata &fluteFileDescription(std::shared_ptr<LibFlute::Transmitter::FileDescription> &&fd_ptr) {
            m_fileDescription = std::move(fd_ptr);
            return *this;
        };
        Metadata &fluteFileDescription(LibFlute::Transmitter::FileDescription *fd_ptr) {
            m_fileDescription.reset(fd_ptr);
            return *this;
        };

    private:
	std::string m_objectId;
        std::string m_mediaType;
        std::string m_originalUrl;
        std::string m_fetchedUrl;
        std::string m_acquisitionId;
	bool m_keepAfterSend;
        std::optional<std::string> m_objIngestBaseUrl;
        std::optional<std::string> m_objDistributionBaseUrl;
        std::optional<std::string> m_entityTag;
        std::optional<datetime_type> m_cacheExpires;
        datetime_type m_receivedTime;
        datetime_type m_created;
        datetime_type m_modified;
        std::shared_ptr<LibFlute::Transmitter::FileDescription> m_fileDescription;
    };

    using ObjectData = std::vector<unsigned char>;
    using Object = std::pair<ObjectData, Metadata>;

    ObjectStore() = delete;
    ObjectStore(ObjectController &controller);
    ObjectStore(const ObjectStore&) = delete;
    ObjectStore(ObjectStore&&) = delete;
    ~ObjectStore();
    ObjectStore &operator=(const ObjectStore&) = delete;
    ObjectStore &operator=(ObjectStore&&) = delete;

    void addObject(const std::string& object_id, ObjectData &&object, Metadata &&metadata);
    const ObjectData& getObjectData(const std::string& object_id) const;
    ObjectData& getObjectData(const std::string& object_id);
    const Metadata& getMetadata(const std::string& object_id) const;
    Metadata& getMetadata(const std::string& object_id);
    void deleteObject(const std::string& object_id);
    bool removeObject(const std::string& objectId);
    bool removeObjects(const std::list<std::string>& objectIds);
    std::list<std::pair<const std::string*, const Object*>> getExpired();
    const Object &operator[](const std::string& object_id) const;
    bool isStale(const std::string& object_id) const;
    std::map<std::string, const Object&> getStale() const;
    const std::map<std::string, Object> &getObjects() const { return m_store; };

    const Metadata *findMetadataByURL(const std::string &url) const;

    const ObjectController &objectController() const { return m_controller; };

private:
    void checkExpiredObjects();
    mutable std::recursive_mutex m_mutex;
    ObjectController &m_controller;
    std::map<std::string, Object> m_store;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_OBJECT_STORE_HH_ */
