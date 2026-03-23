#ifndef _MBS_TF_OBJECT_MANIFEST_HANDLER_HH_
#define _MBS_TF_OBJECT_MANIFEST_HANDLER_HH_
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
#include <chrono>
#include <list>
#include <string>
#include <thread>
#include <utility>

#include "common.hh"
#include "Event.hh"
#include "ManifestHandler.hh"
#include "ObjectStore.hh"
#include "PullObjectIngester.hh"
#include "SubscriptionService.hh"
#include "openapi/model/ObjectManifest.h"

MBSTF_NAMESPACE_START

class ObjectManifestHandler : public ManifestHandler {
public:
    using datetime_type = std::chrono::system_clock::time_point;

    class ObjectManifestChangeEvent : public Event {
    public:
        static constexpr const char *event_name = "ObjectManifestChange";

        ObjectManifestChangeEvent() : Event(event_name) {};
        ObjectManifestChangeEvent(const ObjectManifestChangeEvent &other) : Event(other) {};
        ObjectManifestChangeEvent(ObjectManifestChangeEvent &&other) : Event(std::move(other)) {};

        virtual ~ObjectManifestChangeEvent() {};

        virtual Event clone() const { return ObjectManifestChangeEvent(); };
        virtual Event *newClone() const { return new ObjectManifestChangeEvent; };
        virtual std::string reprString() const { return "ObjectManifestChangeEvent()"; };
    };

    ObjectManifestHandler() = delete;
    ObjectManifestHandler(const ObjectStore::Object &object, ObjectController *controller, bool pull_distribution);
    ObjectManifestHandler(const ObjectManifestHandler &) = delete;
    ObjectManifestHandler(ObjectManifestHandler &&) = delete;

    virtual ~ObjectManifestHandler();

    ObjectManifestHandler &operator=(const ObjectManifestHandler &) = delete;
    ObjectManifestHandler &operator=(ObjectManifestHandler &&) = delete;

    virtual std::pair<ManifestHandler::time_type, ManifestHandler::ingest_list> nextIngestItems();
    virtual ManifestHandler::durn_type getDefaultDeadline();
    virtual bool update(const ObjectStore::Object &new_manifest);
    virtual void startedFetch(const PullObjectIngester::IngestItem &item);

    virtual std::string nextObjectId();

    static unsigned int factoryPriority() { return 100; };
    const reftools::mbstf::ObjectManifest::ObjectsType &getObjects() const;
    std::list<std::shared_ptr<reftools::mbstf::Object> > getActiveObjects() const;

    double getRepetitionIntervalForUrl(const std::string &url) const;
    bool isObjectURLActive(const std::string &url) const;
    void finishRequest(const std::string &url);

private:
    struct ObjectMetadataCache {
        datetime_type nextFetchTime;
        bool beenRequested;
    };

    std::string resolveLocator(const std::string &relative_url) const;
    std::string generateUUID();

    std::unique_ptr<std::recursive_mutex> m_objectManifestMutex;
    reftools::mbstf::ObjectManifest  m_objectManifest;
    std::map<reftools::mbstf::Object*, ObjectMetadataCache> m_objectMetadataCache;
    const ObjectStore::Object *m_manifestFile;
    bool m_refreshManifest;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_OBJECT_MANIFEST_HANDLER_HH_ */
