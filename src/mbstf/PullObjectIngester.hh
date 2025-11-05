#ifndef _MBS_TF_PULL_OBJECT_INGESTER_HH_
#define _MBS_TF_PULL_OBJECT_INGESTER_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Pull Object Ingester class
 ******************************************************************************
 * Copyright: (C)2025 British Broadcasting Corporation
 * Author(s): Dev Audsin <dev.audsin@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */
#include <condition_variable>
#include <list>
#include <mutex>
#include <string>

#include "common.hh"
#include "Event.hh"
#include "ObjectIngester.hh"
#include "ObjectStore.hh"

MBSTF_NAMESPACE_START

class ObjectController;
class Curl;

class PullObjectIngester : public ObjectIngester {
public:

    using time_type = std::chrono::system_clock::time_point;

    class ObjectPullQueueExhaustedEvent : public Event {
    public:
        static constexpr const char *event_name = "ObjectPullQueueExhausted";
        ObjectPullQueueExhaustedEvent() :Event(event_name) {};
        virtual Event clone() const { return ObjectPullQueueExhaustedEvent(); };
        virtual Event *newClone() const { return new ObjectPullQueueExhaustedEvent; };
        virtual std::string reprString() const { return "ObjectPullQueueExhaustedEvent()"; };
    };

    class IngestItem {
    public:

        IngestItem() = delete;
        IngestItem(const ObjectStore::Metadata &object_meta, const std::optional<time_type> &download_deadline = std::nullopt);
	IngestItem(const std::string &object_id, const std::string &url, const std::string &acquisition_id,
                   const std::optional<std::string> &obj_ingest_base_url = std::nullopt,
                   const std::optional<std::string> &obj_distribution_base_url = std::nullopt,
                   const std::optional<time_type> &download_deadline = std::nullopt);
        IngestItem(const IngestItem &other);
        IngestItem(IngestItem &&other);
        virtual ~IngestItem() {};

        const std::string &objectId() const { return m_objectId; };
        IngestItem &objectId(const std::string &object_id) { m_objectId = object_id; return *this; };
        IngestItem &objectId(std::string &&object_id) { m_objectId = std::move(object_id); return *this; };

        const std::string &url() const { return m_url; };
        IngestItem &url(const std::string &url) { m_url = url; return *this; };
        IngestItem &url(std::string &&url) { m_url = std::move(url); return *this; };

        const std::string &acquisitionId() const { return m_acquisitionId; };
        IngestItem &acquisitionId(const std::string &acquisition_id) { m_acquisitionId = acquisition_id; return *this; };
        IngestItem &acquisitionId(std::string &&acquisition_id) { m_acquisitionId = std::move(acquisition_id); return *this; };

        const std::optional<std::string> &objIngestBaseUrl() const { return m_objIngestBaseUrl; };
        const std::optional<std::string> &objDistributionBaseUrl() const { return m_objDistributionBaseUrl; };

        bool hasDeadline() const { return m_deadline.has_value(); };
        const std::optional<time_type> &deadline() const { return m_deadline; };
	const time_type &getDeadline() const { return m_deadline.value(); };

        time_type deadline(const time_type &default_deadline) const { return m_deadline.value_or(default_deadline); };
        IngestItem &deadline(std::nullopt_t) { m_deadline.reset(); return *this; };
        IngestItem &deadline(const time_type &dl_deadline) { m_deadline = time_type(dl_deadline); return *this; };
        IngestItem &deadline(time_type &&dl_deadline) { m_deadline = std::move(dl_deadline); return *this; };

    private:
        std::string m_objectId;
        std::string m_url;
	std::string m_acquisitionId;
        std::optional<std::string> m_objIngestBaseUrl;
        std::optional<std::string> m_objDistributionBaseUrl;
        std::optional<time_type> m_deadline;
    };

    PullObjectIngester() = delete;
    PullObjectIngester(ObjectStore& object_store, ObjectController &controller, const std::list<IngestItem> &id_to_url_map)
      :ObjectIngester(object_store, controller)
      ,m_fetchList(id_to_url_map)
      ,m_ingestItemsMutex (new std::recursive_mutex)

    { sortListByPolicy(); startWorker(); };

    PullObjectIngester(ObjectStore& object_store, ObjectController &controller, std::list<IngestItem> &&id_to_url_map)
      :ObjectIngester(object_store, controller)
      ,m_fetchList(std::move(id_to_url_map))
      ,m_ingestItemsMutex (new std::recursive_mutex)

    { sortListByPolicy(); startWorker();};

    virtual ~PullObjectIngester();

    bool fetch(const IngestItem &item);
    bool fetch(IngestItem &&item);
    bool fetch(const std::string &object_id, const std::optional<time_type> &download_deadline);

    std::shared_ptr<Curl> curl() {return m_curl;};
    //static int client_notify_cb(int status, ogs_sbi_response_t *response, void *data);

protected:
    virtual void doObjectIngest();

private:
    void sortListByPolicy();
    std::list<IngestItem> m_fetchList;
    std::unique_ptr<std::recursive_mutex> m_ingestItemsMutex;
    std::condition_variable_any m_ingestItemsCondVar;
    std::shared_ptr<Curl> m_curl;

};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_MBSTF_PULL_OBJECT_INGESTER_HH_ */
