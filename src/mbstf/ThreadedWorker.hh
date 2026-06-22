#ifndef _MBS_TF_THREADED_WORKER_HH_
#define _MBS_TF_THREADED_WORKER_HH_
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

#include <exception>
#include <format>
#include <functional>
#include <string>
#include <thread>

#include <ogs-core.h>
#include <ogs-sbi.h>

#include "common.hh"

MBSTF_NAMESPACE_START

class ThreadedWorker {
public:
    class ThreadedWorkerCancelled : public std::exception {
    public:
        using std::exception::exception;
    };

    ThreadedWorker();
    ThreadedWorker(const std::string &name, std::function<void(std::function<void()>)> workload)
        :m_threadState(new ThreadedWorkerState)
    {
        startWorker(name, workload);
    }
    template<class... Args>
    ThreadedWorker(const std::string &name, std::function<void(std::function<void()>, Args&&...)> workload, Args&&... args)
        :m_threadState(new ThreadedWorkerState)
    {
        startWorker(name, workload, std::forward<Args>(args)...);
    };
    ThreadedWorker(const ThreadedWorker&) = delete;
    ThreadedWorker(ThreadedWorker &&other);

    virtual ~ThreadedWorker();

    ThreadedWorker &operator=(const ThreadedWorker &) = delete;
    ThreadedWorker &operator=(ThreadedWorker &&);

    operator bool() const { return isRunning(); };

    bool isRunning() const { return m_threadState?m_threadState->m_isRunning.load():false; };
    bool isCancelled() const { return m_threadState?m_threadState->m_isCancelled.load():false; };
    bool hasCompleted() const { return m_threadState?m_threadState->m_hasCompleted.load():false; };

    ThreadedWorker &cancel();
    ThreadedWorker &join();

    void checkCancelled() const { if (m_threadState) m_threadState->checkCancelled(); };

    ThreadedWorker &startWorker(const std::string &name, std::function<void(std::function<void()>)> workload);

private:
    struct ThreadedWorkerState {
        ~ThreadedWorkerState();

        std::thread m_thread;
        std::atomic<bool> m_isRunning;
        std::atomic<bool> m_isCancelled;
        std::atomic<bool> m_hasCompleted;
        std::atomic<bool> m_hasFailed;
        std::string m_name;

        void checkCancelled() const;
    };
    std::unique_ptr<ThreadedWorkerState> m_threadState;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_THREADED_WORKER_HH_ */
