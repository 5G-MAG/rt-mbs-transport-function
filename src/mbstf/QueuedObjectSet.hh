#ifndef MBSTF_QUEUED_OBJECT_SET_HH
#define MBSTF_QUEUED_OBJECT_SET_HH
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: objects already handed to a packager
 ******************************************************************************
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include <mutex>
#include <set>
#include <string>

#include "common.hh"

MBSTF_NAMESPACE_START

/** The identifiers of the objects a controller has handed to its current packager.
 *
 * COLLECTION distributes a set once. Replaying the manifest's listing to the packager (on a manifest
 * update, or when a packager is made) therefore skips what is recorded here. An object whose content
 * changed arrives as its own event and is sent regardless. Safe to use from several threads.
 */
class QueuedObjectSet {
public:
    bool contains(const std::string &object_id) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_ids.contains(object_id);
    };
    void insert(const std::string &object_id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_ids.insert(object_id);
    };
    void clear() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_ids.clear();
    };

private:
    mutable std::mutex m_mutex;
    std::set<std::string> m_ids;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* MBSTF_QUEUED_OBJECT_SET_HH */
