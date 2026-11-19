#ifndef MBSTF_REPAIR_REGISTRY_HH
#define MBSTF_REPAIR_REGISTRY_HH
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: the repair objects of every Distribution Session
 ******************************************************************************
 * License: 5G-MAG Public License v1
 *
 * Licensed under the License terms and conditions for use, reproduction, and
 * distribution of 5G-MAG software (the "License").  You may not use this file
 * except in compliance with the License.  You may obtain a copy of the License at
 * https://www.5g-mag.com/reference-tools.  Unless required by applicable law or
 * agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied.
 *
 * See the License for the specific language governing permissions and limitations
 * under the License.
 */

#include <chrono>
#include <cstddef>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "common.hh"
#include "RepairObjectStore.hh"

MBSTF_NAMESPACE_START

/** One RepairObjectStore per Distribution Session, found by the identifier of the session.
 *
 * TS 26.517 V19.2.0 clause 10.2.3: "An MBS AS instance is assigned to an MBS User Service Session and hosts all objects at a location
 * as specified in clause 6.2.4.4." The AS of the MBSTF serves every session from one address, so the repair base URL given to the
 * client carries the identifier of the session and the AS finds the session's objects by it.
 *
 * The registry outlives the Distribution Sessions it holds objects for: a client repairs after the session has ended (clause 10.2.2.1,
 * the back-off after the end of the download delivery session), so the objects of a deleted session stay until their retention ends.
 * The octet limit applies to each session separately, which makes the most the registry holds that limit times the number of
 * sessions with objects.
 */
class RepairRegistry {
public:
    using Object = RepairObjectStore::Object;
    using time_type = RepairObjectStore::time_type;

    RepairRegistry(std::chrono::seconds retention, std::size_t max_octets_per_session)
        :m_retention(retention), m_maxOctets(max_octets_per_session) {}

    RepairRegistry(const RepairRegistry &) = delete;
    RepairRegistry &operator=(const RepairRegistry &) = delete;

    /** Keep an object of a session under a path, making the session's store if it has none. \return false when nothing was kept. */
    bool put(const std::string &session_id, const std::string &path, Object &&object, time_type now)
    {
        std::shared_ptr<RepairObjectStore> store;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto &slot = m_stores[session_id];
            if (!slot) slot = std::make_shared<RepairObjectStore>(m_retention, m_maxOctets);
            store = slot;
        }
        return store->put(path, std::move(object), now);
    }

    /** The object of a session under a path, or nothing when the session or the object is not held or has expired. */
    std::shared_ptr<const Object> get(const std::string &session_id, const std::string &path, time_type now)
    {
        std::shared_ptr<RepairObjectStore> store;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            const auto it = m_stores.find(session_id);
            if (it == m_stores.end()) return nullptr;
            store = it->second;
        }
        return store->get(path, now);
    }

    /** Drop the objects whose retention has run out, and the stores that are then empty. \return the number of objects dropped. */
    std::size_t purgeExpired(time_type now)
    {
        std::size_t dropped = 0;
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto it = m_stores.begin(); it != m_stores.end();) {
            dropped += it->second->purgeExpired(now);
            if (it->second->objectCount() == 0) it = m_stores.erase(it);
            else ++it;
        }
        return dropped;
    }

    std::size_t sessionCount() const { std::lock_guard<std::mutex> lock(m_mutex); return m_stores.size(); }
    std::chrono::seconds retention() const { return m_retention; }
    std::size_t maxOctetsPerSession() const { return m_maxOctets; }

private:
    mutable std::mutex m_mutex;
    const std::chrono::seconds m_retention;
    const std::size_t m_maxOctets;
    std::map<std::string, std::shared_ptr<RepairObjectStore>> m_stores;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* MBSTF_REPAIR_REGISTRY_HH */
