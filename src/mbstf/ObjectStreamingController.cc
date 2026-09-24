/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: ObjectStreamingController class
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

#include <exception>
#include <iostream>
#include <list>
#include <memory>
#include <optional>
#include <string>

#include <netinet/in.h>

#include <uuid/uuid.h>

#include "ogs-app.h"
#include "ogs-sbi.h" // include before "common.hh" to ensure correct logging domain

#include "common.hh"
#include "ControllerFactory.hh"
#include "DistributionSession.hh"
#include "Event.hh"
#include "ManifestHandlerFactory.hh"
#include "ObjectController.hh"
#include "ObjectListPackager.hh"
#include "ObjectStore.hh"
#include "PullObjectIngester.hh"
#include "PushObjectIngester.hh"
#include "SsmPort.hh"
#include "SubscriptionService.hh"
#include "utilities.hh"
#include "openapi/model/DistSessionState.h"
#include "openapi/model/ProblemCause.hh"

#include "ObjectStreamingController.hh"

using reftools::mbstf::DistSessionState;
using fiveg_mag_reftools::ModelException;
using fiveg_mag_reftools::ProblemCause;

MBSTF_NAMESPACE_START

static void validate_distribution_session(DistributionSession &distributionSession);

ObjectStreamingController::ObjectStreamingController(DistributionSession &distributionSession)
    :ObjectManifestController(distributionSession)
{
    validate_distribution_session(distributionSession);
    subscribeToService(*objectStore());
    //setObjectListPackager();
    //startWorker();
}

ObjectStreamingController::~ObjectStreamingController()
{
    /* Dropped before anything else: this object is still subscribed to the object store, and an
       event delivered once the derived part is gone reaches ObjectManifestController::processEvent
       through a vtable that no longer has sendToPackager(), which ends the process with "pure
       virtual method called". ~Subscriber() unsubscribes too, but it runs after every derived
       destructor, which is exactly too late. */
    /* Stopped before anything else: the ingest workers this controller owns are held by its
       ObjectController base, so destruction alone stops them last, after every derived destructor
       has run. abort() below joins a scheduled pull that can take tens of seconds, and the workers
       keep ingesting throughout, using objects the teardown is already dismantling. */
    abortIngest();
    unsubscribeFromAll();
    abort();
}

void ObjectStreamingController::setObjectPackager()
{
    auto ssm_port = distributionSession().getSsmPort();
    const std::optional<std::string> &tunnel_addr = distributionSession().getTunnelAddr();
    uint32_t rate_limit = distributionSession().getRateLimit();
    in_port_t tunnel_port = distributionSession().getTunnelPortNumber();
    bool mtu_via_loopback = false;
    /* Sequenced, not nested: the order arguments are evaluated in is unspecified, so reading
       mtu_via_loopback in the same call that fills it would read it before it is set. */
    const int discovered_mtu = get_tunnelled_path_mtu(ssm_port, tunnel_addr, tunnel_port,
                                                     GET_MTU_ETHERNET_PAYLOAD, &mtu_via_loopback);
    unsigned short mtu = flute_path_mtu(discovered_mtu, mtu_via_loopback) - GTP_HEADER_SIZE;
    packager(new ObjectListPackager(objectStore(), *this, ssm_port, rate_limit, mtu, tunnel_addr, tunnel_port,
                                    distributionSession().getFecInformation()));
    auto pkgr = getObjectListPackager();
    subscribeToService(*pkgr);
    startWorker();
    auto object_store = objectStore();
    if (object_store) {
        const auto &obj_list = object_store->getObjects();
        for (const auto &[obj_id, object] : obj_list) {
            sendToPackager(object);
        }
    }
}

void ObjectStreamingController::activateObjectPackager() {
    packager()->activate();
    startWorker();
}

void ObjectStreamingController::deactivateObjectPackager() {
    if (packager()->deactivate()) {
        distributionSession().haveEmptyQueue();
    }
}

std::shared_ptr<ObjectListPackager> ObjectStreamingController::getObjectListPackager() const
{
    return std::dynamic_pointer_cast<ObjectListPackager>(packager());
}

void ObjectStreamingController::sendToPackager(const std::shared_ptr<ObjectStore::Object> &object)
{
    auto packager = getObjectListPackager();
    if (packager) {
        // TS 26.517 V18.6.0 clause 6.2.3.5: "The MBSTF shall transmit each object in the object list
        // such that the last packet of the delivered FLUTE transmission object (including any FEC
        // recovery packets, when configured) is available at the MBSTF Client no later than its
        // availability start time." The packaging queue is ordered by each item's deadline for that
        // purpose, so for this operating mode the deadline is that availability start time. Passing
        // no deadline leaves every item undated, and the ordering predicate then has nothing to
        // order by.
        ObjectListPackager::PackageItem item(object, object->second.availabilityStartTime());
        packager->add(item);
    }
}

const std::optional<std::string> &ObjectStreamingController::getObjectDistributionBaseUrl() const {
    return distributionSession().objectDistributionBaseUrl();
}

void ObjectStreamingController::reconfigureObjectPackager()
{
    if (distributionSession().getState() == DistSessionState::VAL_ACTIVE) {
        auto packager = getObjectListPackager();
        if (packager) {
            auto ssm_port = distributionSession().getSsmPort();
            const std::optional<std::string> &tunnel_addr = distributionSession().getTunnelAddr();
            uint32_t rate_limit = distributionSession().getRateLimit();
            in_port_t tunnel_port = distributionSession().getTunnelPortNumber();

            if (ssm_port) {
                packager->updateFluteInfo(ssm_port, rate_limit, tunnel_addr, tunnel_port);
            }
        }
    }
}

namespace {
static const struct init {
    init() {
        ControllerFactory::registerController(new ControllerConstructor<ObjectStreamingController>);
    };
} g_init;
}

static void validate_distribution_session(DistributionSession &distribution_session)
{
    if (distribution_session.getObjectDistributionOperatingMode() != "STREAMING") {
        throw std::logic_error("Expected objDistributionOperatingMode to be set to STREAMING.");
    }
    ObjectController::validateDistributionSession(distribution_session);
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
