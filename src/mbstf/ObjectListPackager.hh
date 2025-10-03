#ifndef _MBS_TF_OBJECT_LIST_PACKAGER_HH_
#define _MBS_TF_OBJECT_LIST_PACKAGER_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Object List Packager class
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

MBSTF_NAMESPACE_START

class ObjectController;
class ObjectStore;

class ObjectListPackager : public ObjectPackager {
public:
    using time_type = std::chrono::system_clock::time_point;

    class PackageItem {
    public:
        PackageItem() = delete;
        PackageItem(const std::string &object_id, const std::optional<time_type> &deadline = std::nullopt);
        PackageItem(const PackageItem &other);
        PackageItem(PackageItem &&other);
        virtual ~PackageItem() {};

        const std::string &objectId() const { return m_objectId; }
        PackageItem &objectId(const std::string &object_id) { m_objectId = object_id; return *this; }
        PackageItem &objectId(std::string &&object_id) { m_objectId = std::move(object_id); return *this; }

        bool hasDeadline() const { return m_deadline.has_value(); }
        const std::optional<time_type> &deadline() const { return m_deadline; }
        time_type deadline(const time_type &default_deadline) const { return m_deadline.value_or(default_deadline); }
        PackageItem &deadline(std::nullopt_t) { m_deadline.reset(); return *this; }
        PackageItem &deadline(const time_type &deadline) { m_deadline = deadline; return *this; }
        PackageItem &deadline(time_type &&deadline) { m_deadline = std::move(deadline); return *this; }

    private:
        std::string m_objectId;
        std::optional<time_type> m_deadline;
    };

    ObjectListPackager() = delete;
    ObjectListPackager(ObjectStore &object_store, ObjectController &controller,
                       const std::list<PackageItem> &object_to_package, const std::optional<std::string> &address,
                       uint32_t rateLimit, unsigned short mtu, in_port_t port,
                       const std::optional<std::string> &tunnel_address, in_port_t tunnel_port);
    ObjectListPackager(ObjectStore &object_store, ObjectController &controller, std::list<PackageItem> &&object_to_package,
                       const std::optional<std::string> &address, uint32_t rateLimit, unsigned short mtu, in_port_t port,
                       const std::optional<std::string> &tunnel_address, in_port_t tunnel_port);
    ObjectListPackager(ObjectStore &object_store, ObjectController &controller, const std::optional<std::string> &address,
                       uint32_t rateLimit, unsigned short mtu, in_port_t port,
                       const std::optional<std::string> &tunnel_address, in_port_t tunnel_port);
    virtual ~ObjectListPackager();

    bool add(const PackageItem &item);
    bool add(PackageItem &&item);

    bool updateFluteInfo(const std::string &address, in_port_t port,
                         uint32_t rateLimit,
                         const std::optional<std::string> &tunnel_address, in_port_t tunnel_port);

protected:
    virtual void doObjectPackage();

private:
    void sortListByPolicy();
    void objectSendCompletion(std::string &object_id);
    std::list<PackageItem> m_packageItems;
    std::optional<boost::asio::ip::udp::endpoint> m_tunnelEndpoint;
    std::unique_ptr<std::recursive_mutex> m_packageItemsMutex;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */

#endif /* _MBS_TF_OBJECT_LIST_PACKAGER_HH_ */
