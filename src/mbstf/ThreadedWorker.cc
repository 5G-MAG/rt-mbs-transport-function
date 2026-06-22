/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Threaded Worker class
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
#include <exception>
#include <format>
#include <functional>
#include <string>
#include <thread>

#include "ogs-core.h"
#include "ogs-sbi.h"

#include "common.hh"

#include "ThreadedWorker.hh"

using namespace std::literals::chrono_literals;

MBSTF_NAMESPACE_START

ThreadedWorker::ThreadedWorker()
    :m_threadState()
{
    //ogs_debug("Empty threaded worker %p", this);
}

ThreadedWorker::ThreadedWorker(ThreadedWorker &&other)
    :m_threadState(std::move(other.m_threadState))
{
    //ogs_debug("Move construct threaded worker %p (%p) to %p", &other, m_threadState.get(), this);
}

ThreadedWorker::~ThreadedWorker()
{
    //ogs_debug("Destroy threaded worker %p (%p)", this, m_threadState.get());
}

ThreadedWorker &ThreadedWorker::operator=(ThreadedWorker &&other)
{
    //ogs_debug("Move threaded worker %p (%p) to %p (%p)", &other, other.m_threadState.get(), this, m_threadState.get());
    m_threadState = std::move(other.m_threadState);
    return *this;
}

ThreadedWorker &ThreadedWorker::cancel()
{
    if (m_threadState) {
        //ogs_debug("Cancelling threaded worker %p (%p) [%s]", this, m_threadState.get(), m_threadState->m_name.c_str());
        m_threadState->m_isCancelled.store(true);
    }
    return *this;
}

ThreadedWorker &ThreadedWorker::join()
{
    if (m_threadState) {
        if (m_threadState->m_thread.joinable()) {
            if (m_threadState->m_thread.get_id() != std::this_thread::get_id()) {
                //ogs_debug("Join threaded worker %p (%p) [%s]", this, m_threadState.get(), m_threadState->m_name.c_str());
                m_threadState->m_thread.join();
            } else {
                // if we are trying to join this thread from itself, just detach
                //ogs_debug("Detach threaded worker %p (%p) [%s]", this, m_threadState.get(), m_threadState->m_name.c_str());
                m_threadState->m_thread.detach();
            }
        } else {
            //ogs_debug("Threaded worker %p (%p) [%s] not joinable", this, m_threadState.get(), m_threadState->m_name.c_str());
        }
    } else {
        //ogs_debug("Threaded worker %p has no state, not joinable", this);
    }
    return *this;
}

ThreadedWorker &ThreadedWorker::startWorker(const std::string &name, std::function<void(std::function<void()>)> workload)
{
    if (!m_threadState) m_threadState.reset(new ThreadedWorkerState);
    //ogs_debug("Attempt thread start for worker %p (%p) [%s]", this, m_threadState.get(), name.c_str());
    if (!m_threadState->m_isRunning.load()) {
        m_threadState->m_isRunning.store(true);
        m_threadState->m_isCancelled.store(false);
        //ogs_debug("Threaded worker %p (%p) [%s] not running, starting...", this, m_threadState.get(), name.c_str());
        m_threadState->m_name = name;
        if (m_threadState->m_thread.joinable()) m_threadState->m_thread.detach();
        auto state = m_threadState.get();
        m_threadState->m_thread = std::thread([state, workload]() {
                state->m_hasCompleted.store(false);
                try {
                    workload([state]() -> void { state->checkCancelled(); });
                } catch (ThreadedWorkerCancelled &ex) {
                    // cancelled is ok
                } catch (std::exception &ex) {
                    ogs_error("%s", std::format("The {} thread failed: {}", state->m_name, ex.what()).c_str());
                    state->m_hasFailed.store(true);
                }
                state->m_hasCompleted.store(true);
                state->m_isRunning.store(false);
        });
        //ogs_debug("Threaded worker %p (%p) [%s] started", this, m_threadState.get(), name.c_str());
    }
    return *this;
}

ThreadedWorker::ThreadedWorkerState::~ThreadedWorkerState()
{
    if (m_isRunning) {
        //{
        //    std::ostringstream oss;
        //    oss << "Stopping running thread " << m_thread.get_id() << " for worker state " << this;
        //    ogs_debug("%s", oss.str().c_str());
        //}
        m_isCancelled.store(true);
        if (m_thread.joinable()) {
            if (m_thread.get_id() != std::this_thread::get_id()) {
                m_thread.join();
            } else {
                // if we are trying to join this thread from itself, just detach
                m_thread.detach();
            }
        }
    }
}

void ThreadedWorker::ThreadedWorkerState::checkCancelled() const
{
    //ogs_debug("Checking for cancelled thread on state %p", this);
    if (m_isCancelled.load()) {
        //ogs_debug("Thread cancelled on state %p", this);
        throw ThreadedWorker::ThreadedWorkerCancelled();
    }
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
