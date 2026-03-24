#ifndef _MBS_TF_OBJECT_CAROUSEL_PACKAGER_HH_
#define _MBS_TF_OBJECT_CAROUSEL_PACKAGER_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Object Carousel Packager class
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
#include <functional>
#include <list>
#include <memory>
#include <optional>
#include <string>

#include <netinet/in.h>

#include <boost/asio.hpp>

#include "common.hh"
#include "ObjectPackager.hh"
#include "ObjectStore.hh"

namespace reftools::mbstf {
    class Object;
}

MBSTF_NAMESPACE_START

class ObjectController;
class ObjectManifestHandler;

class ObjectCarouselPackager : public ObjectPackager {
public:
    using duration_type = std::chrono::duration<double>;
    using time_type = std::chrono::system_clock::time_point;

    class PackageItem {
    public:
        PackageItem() = delete;
        PackageItem(const std::shared_ptr<ObjectStore::Object> &object, const std::shared_ptr<const ObjectManifestHandler> &manifest_handler);
        PackageItem(const std::shared_ptr<ObjectStore::Object> &object, const duration_type &repetition_interval);
        PackageItem(const PackageItem &other);
        PackageItem(PackageItem &&other);
        virtual ~PackageItem() {};

        PackageItem &operator=(const PackageItem &other);
        PackageItem &operator=(PackageItem &&other);

        bool operator==(const std::shared_ptr<reftools::mbstf::Object> &obj) const;

        const std::shared_ptr<ObjectStore::Object> &object() { return m_object; };
        std::shared_ptr<const ObjectStore::Object> object() const { return m_object; };
        PackageItem &object(const std::shared_ptr<ObjectStore::Object> &object) { m_object = object; return *this; };
        PackageItem &object(std::shared_ptr<ObjectStore::Object> &&object) { m_object = std::move(object); return *this; };

        const duration_type &repetitionInterval() const { return m_repetitionInterval; };
        PackageItem &repetitionInterval(const duration_type &repetition_interval) {
            m_repetitionInterval = repetition_interval;
            return *this;
        };
        PackageItem &repetitionInterval(duration_type &&repetition_interval) {
            m_repetitionInterval = std::move(repetition_interval);
            return *this;
        };

        std::pair<time_type, time_type> nextTransmitStartWindow(double available_bit_rate) const;
        void startedTransmission(const duration_type &used_rep_interval);
        uint32_t toi() const { const auto &fd = m_object->second.fluteFileDescription(); return fd?fd->toi():0; };

    private:
        std::shared_ptr<ObjectStore::Object> m_object;
        duration_type m_repetitionInterval;
        time_type m_nextTransmissionStart;
    };

    ObjectCarouselPackager() = delete;
    ObjectCarouselPackager(ObjectStore &object_store, ObjectController &controller,
                       const std::list<PackageItem> &objects_to_package, const std::optional<std::string> &address,
                       uint32_t rateLimit, unsigned short mtu, in_port_t port,
                       const std::optional<std::string> &tunnel_address, in_port_t tunnel_port);
    ObjectCarouselPackager(ObjectStore &object_store, ObjectController &controller, std::list<PackageItem> &&objects_to_package,
                       const std::optional<std::string> &address, uint32_t rateLimit, unsigned short mtu, in_port_t port,
                       const std::optional<std::string> &tunnel_address, in_port_t tunnel_port);
    ObjectCarouselPackager(ObjectStore &object_store, ObjectController &controller, const std::optional<std::string> &address,
                       uint32_t rateLimit, unsigned short mtu, in_port_t port,
                       const std::optional<std::string> &tunnel_address, in_port_t tunnel_port);
    virtual ~ObjectCarouselPackager();

    bool add(const PackageItem &item);
    bool add(PackageItem &&item);
    bool remove(const PackageItem &item);
    const std::list<PackageItem> &getPackageItems() const { return m_packageItems; };

    bool updateFluteInfo(const std::string &address, in_port_t port,
                         uint32_t rateLimit,
                         const std::optional<std::string> &tunnel_address, in_port_t tunnel_port);

    virtual bool deactivate();
    virtual void flushQueue();

protected:
    virtual void doObjectPackage();

private:
    bool streamsAllocateToi(const std::function<std::pair<uint32_t, std::shared_ptr<ObjectStore::Object> >()> &get_toi_fn);
    void streamsRemoveToi(uint32_t toi);
    void scheduleCarousel();
    void ensureTransmitter();
    void errorInCarousel(const std::string &reason, ObjectPackager::PackagingFailedEvent::FailureType fail_type);
    void objectSendCompletion(std::string &object_id, bool queue_empty);
    void startScheduler();
    void abortScheduler();

    std::unique_ptr<std::recursive_mutex> m_packageItemsMutex;
    std::list<PackageItem> m_packageItems;
    std::condition_variable_any m_packagingUpdateCondVar;
    std::optional<boost::asio::ip::udp::endpoint> m_tunnelEndpoint;
    std::unique_ptr<std::recursive_mutex> m_streamsMutex;
    std::map<uint32_t, std::shared_ptr<ObjectStore::Object> > m_streams;
    std::thread m_schedulingThread;
    std::atomic_bool m_schedulingRunning;
    std::atomic_bool m_schedulingCancel;
    size_t m_maxStreams;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */

#endif /* _MBS_TF_OBJECT_CAROUSEL_PACKAGER_HH_ */
