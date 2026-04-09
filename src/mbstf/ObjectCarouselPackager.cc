/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: ObjectCarouselPackager class
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
#include <cmath>
#include <chrono>
#include <exception>
#include <iostream>
#include <list>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <netinet/in.h>

#include "ogs-app.h" // ogs_error(), ogs_info()
#include "ogs-sbi.h"
#include "Transmitter.h" // LibFlute

#include "common.hh"
#include "DistributionSession.hh"
#include "ObjectController.hh"
#include "ObjectCarouselController.hh"
#include "ObjectManifestHandler.hh"
#include "ObjectPackager.hh"
#include "ObjectStore.hh"
#include "openapi/model/Object.h"

#include "ObjectCarouselPackager.hh"

using namespace std::literals::chrono_literals;
using ApiObject = reftools::mbstf::Object;

MBSTF_NAMESPACE_START

// ObjectCarouselPackager::PackageItem

ObjectCarouselPackager::PackageItem::PackageItem(const std::shared_ptr<ObjectStore::Object> &object,
                                                 const std::shared_ptr<const ObjectManifestHandler> &manifest_handler)
    :m_object(object)
    ,m_repetitionInterval(manifest_handler->getRepetitionIntervalForUrl(object->second.getOriginalUrl()))
    ,m_nextTransmissionStart(ObjectCarouselPackager::time_type::clock::now())
{
}

ObjectCarouselPackager::PackageItem::PackageItem(const std::shared_ptr<ObjectStore::Object> &object,
                                                 const ObjectCarouselPackager::duration_type &repetition_interval)
    :m_object(object)
    ,m_repetitionInterval(repetition_interval)
    ,m_nextTransmissionStart(time_type::clock::now())
{
}

ObjectCarouselPackager::PackageItem::PackageItem(const PackageItem &other)
    :m_object(other.m_object)
    ,m_repetitionInterval(other.m_repetitionInterval)
    ,m_nextTransmissionStart(other.m_nextTransmissionStart)
{
}

ObjectCarouselPackager::PackageItem::PackageItem(PackageItem &&other)
    :m_object(std::move(other.m_object))
    ,m_repetitionInterval(std::move(other.m_repetitionInterval))
    ,m_nextTransmissionStart(std::move(other.m_nextTransmissionStart))
{
}

bool ObjectCarouselPackager::PackageItem::operator==(const std::shared_ptr<ApiObject> &obj) const
{
    if (!obj && !m_object) return true;
    if (!obj || !m_object) return false;
    const auto &locator = obj->getLocator();
    return locator == m_object->second.getFetchedUrl() ||
           locator == m_object->second.getOriginalUrl() ||
           locator == m_object->second.acquisitionId();
}

std::pair<ObjectCarouselPackager::time_type, ObjectCarouselPackager::time_type> ObjectCarouselPackager::PackageItem::nextTransmitStartWindow(double available_bit_rate) const
{
    auto obj_bit_size = m_object->first.size() * sizeof(ObjectStore::ObjectData::value_type) * 8;
    auto window_start = m_nextTransmissionStart;
    auto window_end = window_start;
    if (!std::isnan(m_repetitionInterval.count())) {
        window_end += std::chrono::duration_cast<time_type::duration>(m_repetitionInterval - duration_type(obj_bit_size/available_bit_rate));
    }
    return std::make_pair(window_start, window_end);
}

void ObjectCarouselPackager::PackageItem::startedTransmission(const ObjectCarouselPackager::duration_type &repetition_interval)
{
    auto now = time_type::clock::now();
    /* skip the transmission window start forward by m_repeatIntervals until we find the next start after now */
    while (m_nextTransmissionStart < now) {
        m_nextTransmissionStart += std::chrono::duration_cast<time_type::duration>(repetition_interval);
    }
}

// ObjectCarouselPackager

ObjectCarouselPackager::ObjectCarouselPackager(ObjectStore &object_store, ObjectController &controller,
                                       const std::list<ObjectCarouselPackager::PackageItem> &objects_to_package,
                                       const std::optional<std::string> &address,
                                       uint32_t rate_limit, unsigned short mtu, in_port_t port, const std::optional<std::string> &tunnel_address, in_port_t tunnel_port)
    :ObjectPackager(object_store, controller, address, rate_limit, mtu, port, tunnel_address, tunnel_port)
    ,m_packageItemsMutex(new decltype(m_packageItemsMutex)::element_type)
    ,m_packageItems(objects_to_package)
    ,m_packagingUpdateCondVar()
    ,m_tunnelEndpoint()
    ,m_streamsMutex(new decltype(m_streamsMutex)::element_type)
    ,m_streams()
    ,m_schedulingThread()
    ,m_schedulingRunning(false)
    ,m_schedulingCancel(false)
    ,m_maxStreams(0)
{
    if (tunnel_address) {
        m_tunnelEndpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::address::from_string(tunnel_address.value()), tunnel_port);
    }
    startWorker();
    startScheduler();
}

ObjectCarouselPackager::ObjectCarouselPackager(ObjectStore &object_store, ObjectController &controller,
                                       std::list<PackageItem> &&objects_to_package, const std::optional<std::string> &address,
                                       uint32_t rate_limit, unsigned short mtu, in_port_t port, const std::optional<std::string> &tunnel_address, in_port_t tunnel_port)
    :ObjectPackager(object_store, controller, address, rate_limit, mtu, port, tunnel_address, tunnel_port)
    ,m_packageItemsMutex(new decltype(m_packageItemsMutex)::element_type)
    ,m_packageItems(std::move(objects_to_package))
    ,m_packagingUpdateCondVar()
    ,m_tunnelEndpoint()
    ,m_streamsMutex(new decltype(m_streamsMutex)::element_type)
    ,m_streams()
    ,m_schedulingThread()
    ,m_schedulingRunning(false)
    ,m_schedulingCancel(false)
    ,m_maxStreams(0)
{
    if (tunnel_address) {
        m_tunnelEndpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::address::from_string(tunnel_address.value()), tunnel_port);
    }
    startWorker();
    startScheduler();
}

ObjectCarouselPackager::ObjectCarouselPackager(ObjectStore &object_store, ObjectController &controller,
                                       const std::optional<std::string> &address, uint32_t rate_limit, unsigned short mtu,
                                       in_port_t port, const std::optional<std::string> &tunnel_address, in_port_t tunnel_port)
    :ObjectPackager(object_store, controller, address, rate_limit, mtu, port, tunnel_address, tunnel_port)
    ,m_packageItemsMutex(new decltype(m_packageItemsMutex)::element_type)
    ,m_packageItems()
    ,m_packagingUpdateCondVar()
    ,m_tunnelEndpoint()
    ,m_streamsMutex(new decltype(m_streamsMutex)::element_type)
    ,m_streams()
    ,m_schedulingThread()
    ,m_schedulingRunning(false)
    ,m_schedulingCancel(false)
    ,m_maxStreams(0)
{
    if (tunnel_address) {
        m_tunnelEndpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::address::from_string(tunnel_address.value()), tunnel_port);
    }
    startWorker();
    startScheduler();
}

ObjectCarouselPackager::~ObjectCarouselPackager() {
    abort();
    abortScheduler();
}

bool ObjectCarouselPackager::add(const PackageItem &item) {
    ogs_debug("ObjectCarouselPackager::add(): deactivating=%s", m_deactivating?"true":"false");
    if (m_deactivating) return false;
    std::lock_guard<decltype(m_packageItemsMutex)::element_type> lock(*m_packageItemsMutex);
    m_packageItems.remove_if([&item](const PackageItem &pkg_item) -> bool { return item.object()->second.objectId() == pkg_item.object()->second.objectId(); });
    m_packageItems.push_back(item);
    m_packagingUpdateCondVar.notify_all();
    return true;
}

bool ObjectCarouselPackager::add(PackageItem &&item) {
    ogs_debug("ObjectCarouselPackager::add(): deactivating=%s", m_deactivating?"true":"false");
    if (m_deactivating) return false;
    std::lock_guard<decltype(m_packageItemsMutex)::element_type> lock(*m_packageItemsMutex);
    m_packageItems.remove_if([&item](const PackageItem &pkg_item) -> bool { return item.object()->second.objectId() == pkg_item.object()->second.objectId(); });
    m_packageItems.push_back(std::move(item));
    m_packagingUpdateCondVar.notify_all();
    return true;
}

bool ObjectCarouselPackager::remove(const PackageItem &item) {
    std::lock_guard<decltype(m_packageItemsMutex)::element_type> lock(*m_packageItemsMutex);
    m_packageItems.remove_if([&item](const PackageItem &pkg_item) -> bool { return item.object()->second.objectId() == pkg_item.object()->second.objectId(); });
    m_packagingUpdateCondVar.notify_all();
    return true;
}

bool ObjectCarouselPackager::updateFluteInfo(const std::string &address, in_port_t port,
                                             uint32_t rate_limit,
                                             const std::optional<std::string> &tunnel_address, in_port_t tunnel_port)
{
    std::lock_guard<decltype(m_transmitterMutex)::element_type> lock(*m_transmitterMutex);

    /* Do nothing if we don't have a Transmitter */
    if (!m_transmitter) return false;

    /* set destination endpoint address if it has changed */
    boost::asio::ip::udp::endpoint dest_addr(boost::asio::ip::make_address(address), port);
    if (dest_addr != m_transmitter->endpoint()) {
        m_transmitter->endpoint(dest_addr);
    }

    /* set new MBR if it has changed */
    if (rate_limit != m_transmitter->rate_limit()) {
        m_transmitter->rate_limit(rate_limit);
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

void ObjectCarouselPackager::doObjectPackage() {
    ensureTransmitter();
    m_io.run_one();
}

void ObjectCarouselPackager::ensureTransmitter()
{
    std::lock_guard<decltype(m_transmitterMutex)::element_type> lock(*m_transmitterMutex);
    if (!m_transmitter) {
        std::optional<std::string> destAddr = destIpAddr();
        if (!destAddr) return;
        m_transmitter.reset(new LibFlute::Transmitter(destAddr.value(), static_cast<short>(port()), 0, mtu(), rateLimit(), m_io,
                                                  m_tunnelEndpoint, LibFlute::FileDeliveryTable::FDT_NS_DRAFT_2005));
        m_transmitter->register_completion_callback(
            [this](uint32_t toi) {
                ogs_debug("Object with TOI %d completed", toi);
                try {
                    /* find stream containing current object with toi */
                    streamsRemoveToi(toi);
                } catch (std::out_of_range &ex) {
                    errorInCarousel(ex.what(), ObjectPackager::PackagingFailedEvent::RESOURCE_NOT_AVAILABLE);
                }
            }
        );
    }
}

void ObjectCarouselPackager::flushQueue()
{
    std::lock_guard<std::recursive_mutex> lock(*m_packageItemsMutex);
    m_packageItems.clear();
}

bool ObjectCarouselPackager::deactivate()
{
    m_deactivating = true;
    bool queue_empty;
    {
        std::lock_guard<decltype(m_transmitterMutex)::element_type> lock(*m_transmitterMutex);
        if (!m_transmitter) {
            queue_empty = (m_packageItems.size() == 0);
        } else {
            queue_empty = (m_transmitter->number_of_files() + m_packageItems.size() == 0);
        }
    }
    if (queue_empty) {
        ogs_debug("Deactivating FLUTE stream, no files to purge");
        abort();
        {
            std::lock_guard<decltype(m_transmitterMutex)::element_type> lock(*m_transmitterMutex);
            if (m_transmitter) m_transmitter->deactivate();
        }
        m_deactivating = false;
        return true;
    }
    return false;
}

bool ObjectCarouselPackager::streamsAllocateToi(const std::function<std::pair<uint32_t, std::shared_ptr<ObjectStore::Object> >()> &get_toi_fn)
{
    std::lock_guard<decltype(m_streamsMutex)::element_type> lock(*m_streamsMutex);
    if (m_streams.size() < m_maxStreams) {
        try {
            m_streams.insert(get_toi_fn());
        } catch (std::runtime_error &ex) {
            ogs_error("Unable to schedule carousel stream: %s", ex.what());
        }
        return true;
    }
    return false;
}

void ObjectCarouselPackager::streamsRemoveToi(uint32_t toi)
{
    std::lock_guard<decltype(m_streamsMutex)::element_type> lock(*m_streamsMutex);
    auto it = m_streams.find(toi);
    if (it != m_streams.end()) {
        m_streams.erase(it);
        m_packagingUpdateCondVar.notify_all();
    }
}

void ObjectCarouselPackager::scheduleCarousel()
{
    /* copy list of package items */
    std::lock_guard<decltype(m_packageItemsMutex)::element_type> pkg_lock(*m_packageItemsMutex);
    if (m_packageItems.empty()) {
        ogs_debug("Empty schedule, wait for change");
        m_packagingUpdateCondVar.wait(*m_packageItemsMutex);
        return;
    }

    /* copy the package items list to filter for items to schedule */
    std::list<PackageItem> package_items(m_packageItems);

    /* fix repetition rates where unknown by allocating unknown items to the remaining bit rate */
    double known_bit_rate = 0.0;
    size_t unknown_rate_bits = 0;
    for (const auto &pkg_item : package_items) {
        double rep_interval = pkg_item.repetitionInterval().count();
        size_t obj_bit_size = pkg_item.object()->first.size()*sizeof(*pkg_item.object()->first.data())*8;
        if (!std::isnan(rep_interval)) {
            known_bit_rate += obj_bit_size / rep_interval;
        } else {
            unknown_rate_bits += obj_bit_size;
        }
    }
    double unknown_rep_interval = 0.0;
    double mbr = rateLimit()*1000.0;
    if (unknown_rate_bits) {
        unknown_rep_interval = unknown_rate_bits / (mbr - known_bit_rate);
    }
    for (auto &pkg_item : package_items) {
        double rep_interval = pkg_item.repetitionInterval().count();
        if (std::isnan(rep_interval)) {
            pkg_item.repetitionInterval(duration_type(unknown_rep_interval));
        }
    }

    /* find largest bitrate item and check total bit rate requirement */
    double max_obj_bit_rate = 0.0;
    double total_bit_rate = 0.0;
    for (const auto &pkg_item : package_items) {
        const auto &object = pkg_item.object();
        size_t obj_bit_size = object->first.size()*sizeof(*object->first.data())*8;
        double obj_bit_rate = obj_bit_size / pkg_item.repetitionInterval().count();
        //ogs_debug("%s", std::format("Object {} of {} bits repeats every {}s: bitrate = {}", object.second.getFetchedUrl(), obj_bit_size, pkg_item.repetitionInterval().count(), obj_bit_rate).c_str());
        if (obj_bit_rate > max_obj_bit_rate) max_obj_bit_rate = obj_bit_rate;
        total_bit_rate += obj_bit_rate;
    }
    if (total_bit_rate > mbr) {
        errorInCarousel(std::format("Carousel maximum bit rate exceeded: allocated {} bps, requires {} bps", mbr, total_bit_rate), ObjectPackager::PackagingFailedEvent::BIT_RATE_OVERFLOW);
        return;
    }

    /* calculate the maximum number of concurrently transmitted objects the maximim bit rate object will allow */
    m_maxStreams = static_cast<size_t>(mbr / max_obj_bit_rate);
    double avail_bitrate = mbr / m_maxStreams;

    //ogs_debug("%s", std::format("Highest Object bit rate = {}, Max concurrent objects = {}, Available bitrate per concurrent stream = {}", max_obj_bit_rate, m_maxStreams, avail_bitrate).c_str());

    /* remove any items currently being transmitted or not due for send until after now */
    auto now = time_type::clock::now();
    std::optional<time_type> next_start;
    std::erase_if(package_items, [this, &now, &next_start, avail_bitrate](const auto &item) -> bool {
            auto [start_min, start_deadline] = item.nextTransmitStartWindow(avail_bitrate);
            //ogs_debug("%s", std::format("Item {} to start transmission between {} and {}", item.object()->second.getFetchedUrl(), start_min, start_deadline).c_str());
            {
                std::lock_guard<decltype(m_streamsMutex)::element_type> lock(*m_streamsMutex);
                if (m_streams.find(item.toi()) != m_streams.end()) {
                    //ogs_debug("Item already being sent");
                    return true;
                }
            }
            if (start_min > now) {
                //ogs_debug("Item not due for transmission yet");
                if (!next_start || start_min < next_start.value()) {
                    next_start = start_min;
                }
                return true;
            }
            return false;
        });

    //ogs_debug("%s", std::format("There remains {} items awaiting scheduling", package_items.size()).c_str());

    /* If there are no items in the remaining list end scheduling now */
    if (package_items.empty()) {
        if (next_start) {
            //ogs_debug("%s", std::format("Nothing to schedule, sleeping until {} or scheduling change", next_start.value()).c_str());
            m_packagingUpdateCondVar.wait_until(*m_packageItemsMutex, next_start.value());
        } else {
            //ogs_debug("Nothing to schedule, waiting for scheduling change");
            m_packagingUpdateCondVar.wait(*m_packageItemsMutex);
        }
        return;
    }

    /* sort list of package items into order from earliest deadline to latest */
    package_items.sort([avail_bitrate](const auto &a, const auto &b) -> bool {
                     return a.nextTransmitStartWindow(avail_bitrate).second < b.nextTransmitStartWindow(avail_bitrate).second;
              });

    /* iterate through list allocating package items to streams until no streams left or no package items left */
    for (auto &pkg_item : package_items) {
        //ogs_debug("%s", std::format("Attempting to schedule {}", pkg_item.object()->second.getFetchedUrl()).c_str());
        if (streamsAllocateToi([this,&pkg_item]() -> std::pair<uint32_t, std::shared_ptr<ObjectStore::Object> > {
                std::lock_guard<decltype(m_transmitterMutex)::element_type> lock(*m_transmitterMutex);
                ensureTransmitter();
                auto &metadata = pkg_item.object()->second;
                auto &file_desc = metadata.fluteFileDescription();
                std::string location;
                std::string obj_ingest_base_url = metadata.objIngestBaseUrl().value_or(std::string());
                std::string obj_distribution_base_url = metadata.objDistributionBaseUrl().value_or(std::string());
                if (!obj_ingest_base_url.empty() && !obj_distribution_base_url.empty() &&
                    metadata.getFetchedUrl().starts_with(obj_ingest_base_url)) {
                    location = obj_distribution_base_url + metadata.getFetchedUrl().substr(obj_ingest_base_url.size());
                } else {
                    // Just use the fetched URL
                    location = metadata.getFetchedUrl();
                }
                if (!file_desc) {
                    pkg_item.object()->second.fluteFileDescription(new LibFlute::Transmitter::FileDescription(location, pkg_item.object()->first));
                } else {
                    /* reset file description information if it's changed */
                    if (file_desc->file_entry().content_location != location) {
                        file_desc->set_content_location(location);
                    }
                    if (file_desc->data() != reinterpret_cast<const char*>(pkg_item.object()->first.data())) {
                        file_desc->set_content(pkg_item.object()->first);
                    }
                }
                /* update Cache expiry time */
                LibFlute::Transmitter::FileDescription::date_time_type default_expiry(LibFlute::Transmitter::FileDescription::date_time_type::clock::now() + 60s);
                file_desc->set_expiry_time(pkg_item.object()->second.cacheExpires().value_or(std::move(default_expiry)));

                /* update Content-Type */
                file_desc->set_content_type(pkg_item.object()->second.mediaType());

                /* update ETag */
                file_desc->set_etag(pkg_item.object()->second.entityTag().value_or(std::string{}));

                /* add PackageItem to the FLUTE Transmitter as a current file */
                m_transmitter->send(file_desc);

                /* Return TOI to set in stream */
                return std::make_pair(pkg_item.toi(), pkg_item.object());
            })) {
            /* mark as transmission started to shift to next repeat window */
            ogs_debug("%s", std::format("Item {} scheduled at {} to be repeated after {}s", pkg_item.object()->second.getFetchedUrl(), time_type::clock::now(), pkg_item.repetitionInterval().count()).c_str());
            for (auto &item : m_packageItems) {
                if (item.object()->second.objectId() == pkg_item.object()->second.objectId()) {
                    item.startedTransmission(pkg_item.repetitionInterval());
                    break;
                }
            }
        } else {
            /* no more free streams, stop scheduling */
            //ogs_debug("No more streams available, waiting for scheduling change");
            m_packagingUpdateCondVar.wait(*m_packageItemsMutex);
            break;
        }
    }
}

void ObjectCarouselPackager::errorInCarousel(const std::string &reason, ObjectPackager::PackagingFailedEvent::FailureType fail_type)
{
    /* log error */
    ogs_error("Error in Carousel: (%i) %s", fail_type, reason.c_str());

    ObjectPackager::PackagingFailedEvent packaging_failed(reason, fail_type);
    sendEventSynchronous(packaging_failed);
}

void ObjectCarouselPackager::startScheduler()
{
    if (!!m_schedulingRunning) return;
    if (!!m_schedulingCancel) return;
    if (m_schedulingThread.joinable()) m_schedulingThread.detach();
    m_schedulingThread = std::thread([this](void *dummy) -> void {
            m_schedulingRunning = true;
            ensureTransmitter();
            while (!m_schedulingCancel) {
                try {
                    scheduleCarousel();
                } catch (std::overflow_error &ex) {
                    errorInCarousel(ex.what(), ObjectPackager::PackagingFailedEvent::BIT_RATE_OVERFLOW);
                }
            }
            m_schedulingRunning = false;
        }, nullptr);
}

void ObjectCarouselPackager::abortScheduler()
{
    m_schedulingCancel = true;
    m_packagingUpdateCondVar.notify_all();
    if (m_schedulingThread.get_id() != std::this_thread::get_id() && m_schedulingThread.joinable()) {
        m_schedulingThread.join();
    }
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
