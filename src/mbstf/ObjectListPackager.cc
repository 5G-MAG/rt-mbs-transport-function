/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: ObjectListPackager class
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
#include <exception>
#include <iostream>
#include <list>
#include <memory>
#include <optional>
#include <string>

#include <netinet/in.h>

#include "ogs-app.h" // ogs_error(), ogs_info()
#include "ogs-sbi.h"
#include "Transmitter.h" // LibFlute

#include "common.hh"
#include "ObjectController.hh"
#include "ObjectListController.hh"
#include "ObjectPackager.hh"
#include "ObjectStore.hh"

#include "ObjectListPackager.hh"

using namespace std::literals::chrono_literals;

MBSTF_NAMESPACE_START

// ObjectListPackager::PackageItem

ObjectListPackager::PackageItem::PackageItem(const std::string &object_id, const std::optional<time_type> &deadline)
    :m_objectId(object_id)
    ,m_deadline(deadline)
{
}

ObjectListPackager::PackageItem::PackageItem(const PackageItem &other)
    :m_objectId(other.m_objectId)
    ,m_deadline(other.m_deadline)
{
}

ObjectListPackager::PackageItem::PackageItem(PackageItem &&other)
    :m_objectId(std::move(other.m_objectId))
    ,m_deadline(std::move(other.m_deadline))
{
}

// ObjectListPackager

ObjectListPackager::ObjectListPackager(ObjectStore &object_store, ObjectController &controller,
                                       const std::list<PackageItem> &object_to_package,
                                       const std::optional<std::string> &address,
                                       uint32_t rateLimit, unsigned short mtu, in_port_t port, const std::optional<std::string> &tunnel_address, in_port_t tunnel_port)
    :ObjectPackager(object_store, controller, address, rateLimit, mtu, port, tunnel_address, tunnel_port)
    ,m_packageItems(object_to_package)
    ,m_tunnelEndpoint()
    ,m_packageItemsMutex (new std::recursive_mutex)
{
    sortListByPolicy();
    if (tunnel_address) {
        m_tunnelEndpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::address::from_string(tunnel_address.value()), tunnel_port);
    }
    startWorker();
}

ObjectListPackager::ObjectListPackager(ObjectStore &object_store, ObjectController &controller,
                                       std::list<PackageItem> &&object_to_package, const std::optional<std::string> &address,
                                       uint32_t rateLimit, unsigned short mtu, in_port_t port, const std::optional<std::string> &tunnel_address, in_port_t tunnel_port)
    :ObjectPackager(object_store, controller, address, rateLimit, mtu, port, tunnel_address, tunnel_port)
    ,m_packageItems(std::move(object_to_package))
    ,m_tunnelEndpoint()
    ,m_packageItemsMutex (new std::recursive_mutex)
{
    sortListByPolicy();
    if (tunnel_address) {
        m_tunnelEndpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::address::from_string(tunnel_address.value()), tunnel_port);
    }
    startWorker();
}

ObjectListPackager::ObjectListPackager(ObjectStore &object_store, ObjectController &controller,
                                       const std::optional<std::string> &address, uint32_t rateLimit, unsigned short mtu,
                                       in_port_t port, const std::optional<std::string> &tunnel_address, in_port_t tunnel_port)
    :ObjectPackager(object_store, controller, address, rateLimit, mtu, port, tunnel_address, tunnel_port)
    ,m_packageItems()
    ,m_tunnelEndpoint()
    ,m_packageItemsMutex (new std::recursive_mutex)
{
    if (tunnel_address) {
        m_tunnelEndpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::address::from_string(tunnel_address.value()), tunnel_port);
    }
    startWorker();
}

ObjectListPackager::~ObjectListPackager() {
    abort();
    if (m_transmitter) {
        delete m_transmitter;
        m_transmitter = NULL;
    }
}

bool ObjectListPackager::add(const PackageItem &item) {
    ogs_debug("ObjectListPackager::add(): deactivating=%s", m_deactivating?"true":"false");
    if (m_deactivating) return false;
    std::lock_guard<std::recursive_mutex> lock(*m_packageItemsMutex);
    m_packageItems.remove_if([&item](const PackageItem &pkg_item) -> bool { return item.objectId() == pkg_item.objectId(); });
    m_packageItems.push_back(item);
    sortListByPolicy();
    return true;
}

bool ObjectListPackager::add(PackageItem &&item) {
    ogs_debug("ObjectListPackager::add(): deactivating=%s", m_deactivating?"true":"false");
    if (m_deactivating) return false;
    std::lock_guard<std::recursive_mutex> lock(*m_packageItemsMutex);
    m_packageItems.remove_if([&item](const PackageItem &pkg_item) -> bool { return item.objectId() == pkg_item.objectId(); });
    m_packageItems.push_back(std::move(item));
    sortListByPolicy();
    return true;
}

bool ObjectListPackager::updateFluteInfo(const std::string &address, in_port_t port,
                                         uint32_t rateLimit,
                                         const std::optional<std::string> &tunnel_address, in_port_t tunnel_port)
{
    /* Do nothing if we don't have a Transmitter */
    if (!m_transmitter) return false;

    /* set destination endpoint address if it has changed */
    boost::asio::ip::udp::endpoint dest_addr(boost::asio::ip::make_address(address), port);
    if (dest_addr != m_transmitter->endpoint()) {
        m_transmitter->endpoint(dest_addr);
    }

    /* set new MBR if it has changed */
    if (rateLimit != m_transmitter->rate_limit()) {
        m_transmitter->rate_limit(rateLimit);
    }

    /* set new tunnel address if it has changed */
    auto curr_tun_addr = m_transmitter->udp_tunnel_address();
    if (tunnel_address) {
        m_tunnelEndpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::make_address(tunnel_address.value()), tunnel_port);
    } else {
        m_tunnelEndpoint = std::nullopt;
    }
    if (curr_tun_addr != m_tunnelEndpoint) {
        m_transmitter->udp_tunnel_address(m_tunnelEndpoint);
    }

    return true;
}

void ObjectListPackager::doObjectPackage() {
    std::optional<std::string> destAddr = destIpAddr();

    if (!destAddr) return;

    if (!m_transmitter) {
        m_transmitter = new LibFlute::Transmitter(
                destAddr.value(),
                static_cast<short>(port()),
                0,
                mtu(),
                rateLimit(),
                m_io,
                m_tunnelEndpoint,
                LibFlute::FileDeliveryTable::FDT_NS_DRAFT_2005);
        m_transmitter->register_completion_callback(
                [this](uint32_t toi) {
                    ogs_debug("FLUTE Transmitter has %zu files left", m_transmitter->number_of_files());
                    bool queue_empty = (m_transmitter->number_of_files() == 0);
                    if (m_queuedToi == toi) {
                        m_queued = false;
                        objectSendCompletion(m_queuedObjectId, queue_empty);
                        ogs_info("Transmitted: Object with TOI: %d", toi);
                    } else {
                        ogs_error("Unscheduled completion of Object with TOI: %d", toi);
                    }
                    std::lock_guard<std::recursive_mutex> guard(m_deactivateMutex);
                    if (m_deactivating && queue_empty) {
                        ogs_debug("Deactivating FLUTE stream on last file");
                        m_transmitter->deactivate();
                        abort();
                        m_deactivating = false;
                    }
                });

        // emitFluteSessionStartedEvent();
    }

    {
        std::lock_guard<std::recursive_mutex> lock(*m_packageItemsMutex);

        if (!m_packageItems.empty() && !m_queued) {
            auto &item = m_packageItems.front();
            m_packageItemsMutex->unlock();
            std::string location;
            m_queuedObjectId = item.objectId();
            std::vector<unsigned char> &objData = objectStore().getObjectData(item.objectId());
            ObjectStore::Metadata &metadata = objectStore().getMetadata(item.objectId());
            std::string obj_ingest_base_url = metadata.objIngestBaseUrl().value_or(std::string());
            std::string obj_distribution_base_url = metadata.objDistributionBaseUrl().value_or(std::string());

            // If we need to substitute objIngestBaseUrl for objDistributionBaseUrl then do so
            if (!obj_ingest_base_url.empty() && !obj_distribution_base_url.empty() &&
                metadata.getFetchedUrl().starts_with(obj_ingest_base_url)) {
                location = obj_distribution_base_url + metadata.getFetchedUrl().substr(obj_ingest_base_url.size());
            } else {
                // Just use the fetched URL
                location = metadata.getFetchedUrl();
            }
            std::shared_ptr<LibFlute::Transmitter::FileDescription> file_desc(metadata.fluteFileDescription());
            if (!file_desc) {
                ogs_debug("New FileDescription(%s, ...)", location.c_str());
                file_desc.reset(new LibFlute::Transmitter::FileDescription(location, objData));
                metadata.fluteFileDescription(file_desc);
            } else {
                ogs_debug("Existing FileDescription(%s, ...)", file_desc->file_entry().content_location.c_str());
                file_desc->set_content_location(location);
                ogs_debug("Set FileDescription location to %s", location.c_str());
                file_desc->set_content(objData);
            }

            m_queued = true;
            LibFlute::Transmitter::FileDescription::date_time_type expires_at;
            const auto &cache_expires = metadata.cacheExpires();
            if (cache_expires) {
                expires_at = cache_expires.value();
            } else {
                expires_at = LibFlute::Transmitter::FileDescription::date_time_type::clock::now() + 60s;
            }
            file_desc->set_expiry_time(expires_at);

            file_desc->set_content_type(metadata.mediaType());

            const auto &entity_tag = metadata.entityTag();
            if (entity_tag) {
                file_desc->set_etag(entity_tag.value());
            }

            m_queuedToi = m_transmitter->send(file_desc);

            m_packageItemsMutex->lock();
            m_packageItems.pop_front();
        }
    }

    m_io.run_one();
}

void ObjectListPackager::sortListByPolicy() {
    m_packageItems.sort([](const PackageItem &a, const PackageItem &b) {
        if (a.deadline().has_value() && b.deadline().has_value()) {
            return a.deadline() < b.deadline();
        }
        return a.deadline().has_value();
    });
}

void ObjectListPackager::objectSendCompletion(std::string &object_id, bool queue_empty)
{
    std::shared_ptr<Event> event(new ObjectListPackager::ObjectSendCompleted(object_id, queue_empty));
    sendEventAsynchronous(event);
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
