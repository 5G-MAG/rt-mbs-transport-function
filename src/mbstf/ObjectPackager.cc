/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Object packager base class
 ******************************************************************************
 * Copyright: (C)2024-2026 British Broadcasting Corporation
 * Author(s): Dev Audsin <dev.audsin@bbc.co.uk>
 *            David Waring <david.waring2@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */
// Open5GS includes
#include "ogs-sbi.h" // include before "common.hh" to get correct logging domain

// STL includes
#include <sstream>
#include <string>

// spdlog includes
#include "spdlog/spdlog.h"

// rt-libflute includes
#include "Transmitter.h"

// local includes
#include "common.hh"
#include "ObjectController.hh"
#include "DistributionSession.hh"

// this class include
#include "ObjectPackager.hh"

MBSTF_NAMESPACE_START

std::string ObjectPackager::PackagingFailedEvent::reprString() const
{
    std::ostringstream oss;
    oss << "ObjectPackager::" << event_name << "(reason=\"" << m_reason << "\", type=" << m_failureType << ")";
    return oss.str();
}

// Prevent spdlog default logger being deleted too early on exit.
auto spdlog_logger = spdlog::default_logger();

ObjectPackager::~ObjectPackager()
{
    abort();
    std::lock_guard<decltype(m_transmitterMutex)::element_type> lock(*m_transmitterMutex);
    m_transmitter.reset();
}

void ObjectPackager::workerLoop(ObjectPackager *packager)
{
    packager->m_workerRunning = true;
    while(!packager->m_workerCancel){
       packager->doObjectPackage();
    }
    packager->m_workerRunning = false;
}

ObjectPackager& ObjectPackager::setSsmPort(const SsmPort &ssm_port) {
    m_ssmPort = ssm_port;
    return *this;
}

ObjectPackager& ObjectPackager::setMtu(unsigned short mtu) {
    m_mtu = mtu;
    return *this;
}

ObjectPackager& ObjectPackager::setRateLimit(uint32_t rateLimit) {
    m_rateLimit = rateLimit;
    return *this;
}

void ObjectPackager::activate()
{
    if (m_transmitter) {
        ogs_debug("Activating FLUTE stream");
        m_transmitter->activate();
    }
    m_workerCancel = false;
    startWorker();
}

bool ObjectPackager::deactivate()
{
    m_deactivating = true;
    std::lock_guard<decltype(m_transmitterMutex)::element_type> lock(*m_transmitterMutex);
    ogs_debug("FLUTE Transmitter has %zu files left", m_transmitter?m_transmitter->number_of_files():0);
    if (m_transmitter && m_transmitter->number_of_files() == 0) {
        ogs_debug("Deactivating FLUTE stream, no files to purge");
        m_workerCancel = true;
        m_transmitter->deactivate();
        m_deactivating = false;
        return true;
    }
    return false;
}

uint64_t ObjectPackager::tsi() const
{
    return m_controller.distributionSession().getTSI();
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
