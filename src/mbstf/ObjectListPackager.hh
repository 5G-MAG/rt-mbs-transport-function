#ifndef _MBS_TF_OBJECT_LIST_PACKAGER_HH_
#define _MBS_TF_OBJECT_LIST_PACKAGER_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Object List Packager class
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
#include <list>
#include <memory>
#include <optional>
#include <string>

#include <netinet/in.h>

#include <boost/asio.hpp>

#include "common.hh"
#include "ObjectPackager.hh"
#include "ObjectStore.hh"

MBSTF_NAMESPACE_START

class ObjectController;

class ObjectListPackager : public ObjectPackager {
public:
    using time_type = std::chrono::system_clock::time_point;

    class PackageItem {
    public:
        PackageItem();
        PackageItem(const std::shared_ptr<ObjectStore::Object> &object, const std::optional<time_type> &deadline = std::nullopt);
        PackageItem(const PackageItem &other);
        PackageItem(PackageItem &&other);
        virtual ~PackageItem() {};

        PackageItem &operator=(const PackageItem &other);
        PackageItem &operator=(PackageItem &&other);

        operator bool() const { return !!m_object; };

        const std::shared_ptr<ObjectStore::Object> &object() { return m_object; };
        std::shared_ptr<const ObjectStore::Object> object() const { return m_object; };
        PackageItem &object(const std::shared_ptr<ObjectStore::Object> &object) { m_object = object; return *this; };
        PackageItem &object(std::shared_ptr<ObjectStore::Object> &&object) { m_object = std::move(object); return *this; };

        bool hasDeadline() const { return m_deadline.has_value(); }
        const std::optional<time_type> &deadline() const { return m_deadline; }
        time_type deadline(const time_type &default_deadline) const { return m_deadline.value_or(default_deadline); }
        PackageItem &deadline(std::nullopt_t) { m_deadline.reset(); return *this; }
        PackageItem &deadline(const time_type &deadline) { m_deadline = deadline; return *this; }
        PackageItem &deadline(time_type &&deadline) { m_deadline = std::move(deadline); return *this; }


        /** Transmission order for the packaging queue.
         *
         * TS 26.517 V18.6.0 clause 6.2.3.5: "The MBSTF shall transmit each object in the object
         * list such that the last packet of the delivered FLUTE transmission object (including any
         * FEC recovery packets, when configured) is available at the MBSTF Client no later than its
         * availability start time."
         *
         * The deadline carried by a PackageItem is that availability start time, so ordering the
         * queue by it is what implements the clause. An item with no deadline sorts after every
         * item that has one: nothing is known about when it must arrive, so it cannot be allowed to
         * displace an object that does have a stated time.
         *
         * A named predicate rather than an inline comparator so that the ordering can be tested
         * directly, the queue itself being private and fed only through a live packager.
         */
        static bool earlierDeadlineFirst(const PackageItem &a, const PackageItem &b) {
            if (a.m_deadline.has_value() && b.m_deadline.has_value()) {
                return a.m_deadline < b.m_deadline;
            }
            return a.m_deadline.has_value();
        };
    private:
        std::shared_ptr<ObjectStore::Object> m_object;
        std::optional<time_type> m_deadline;
    };

    ObjectListPackager() = delete;
    ObjectListPackager(const std::shared_ptr<ObjectStore> &object_store, ObjectController &controller,
                       const std::list<PackageItem> &object_to_package, const SsmPort &ssm_port, uint32_t rateLimit,
                       unsigned short mtu, const std::optional<std::string> &tunnel_address, in_port_t tunnel_port);
    ObjectListPackager(const std::shared_ptr<ObjectStore> &object_store, ObjectController &controller,
                       std::list<PackageItem> &&object_to_package, const SsmPort &ssm_port, uint32_t rateLimit, unsigned short mtu,
                       const std::optional<std::string> &tunnel_address, in_port_t tunnel_port);
    ObjectListPackager(const std::shared_ptr<ObjectStore> &object_store, ObjectController &controller, const SsmPort &ssm_port,
                       uint32_t rateLimit, unsigned short mtu, const std::optional<std::string> &tunnel_address,
                       in_port_t tunnel_port,
                       const std::optional<std::shared_ptr<reftools::mbstf::FECConfig>> &fec_information = std::nullopt);
    virtual ~ObjectListPackager();

    bool add(const PackageItem &item);
    bool add(PackageItem &&item);

    bool updateFluteInfo(const SsmPort &ssm_port, uint32_t rateLimit, const std::optional<std::string> &tunnel_address,
                         in_port_t tunnel_port);

    virtual bool deactivate();
    virtual void flushQueue();

protected:
    virtual void doObjectPackage();

private:
    void sortListByPolicy();
    void objectSendCompletion(std::string &object_id, bool queue_empty);

    std::unique_ptr<std::recursive_mutex> m_packageItemsMutex;
    std::list<PackageItem> m_packageItems;
    std::optional<boost::asio::ip::udp::endpoint> m_tunnelEndpoint;
    std::shared_ptr<ObjectStore::Object> m_currentObject;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */

#endif /* _MBS_TF_OBJECT_LIST_PACKAGER_HH_ */
