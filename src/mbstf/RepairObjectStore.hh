#ifndef MBSTF_REPAIR_OBJECT_STORE_HH
#define MBSTF_REPAIR_OBJECT_STORE_HH
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: objects kept for unicast Object Repair
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
#include <iterator>
#include <cstddef>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "common.hh"

MBSTF_NAMESPACE_START

/** The objects of one MBS Distribution Session that the co-located MBS AS hosts for unicast Object Repair.
 *
 * TS 26.517 V19.2.0 clause 10.2.3: "An MBS AS instance is assigned to an MBS User Service Session and hosts all objects at a
 * location as specified in clause 6.2.4.4." The ObjectStore of the MBSTF drops an object a few seconds after it has been sent, which
 * is too soon for a client that repairs after the session ends: the client waits its offset time and a random time before it asks
 * (clause 10.2.2.1). This store keeps what the AS has to serve, for as long as the operator allows.
 *
 * Two limits, both set by the operator, bound it so that a long session cannot use all memory: how long an object is kept after it
 * was stored, and how many octets are kept in all. The object that was stored first is dropped first when the octet limit is
 * reached. An object dropped for either reason is no longer served, and a client asking for it is answered as for an object the
 * AS never had.
 *
 * Objects are looked up by the path of their repair location: the File@Content-Location of the object with the distribution base
 * URL taken off (clause 6.2.4.4), which is what the client appends to the repair base URL.
 *
 * All members may be called from any thread. The clock is passed in, so that expiry is tested without waiting.
 */
class RepairObjectStore {
public:
    using clock_type = std::chrono::steady_clock;
    using time_type = clock_type::time_point;
    using Data = std::vector<unsigned char>;

    /** What the AS needs to answer for one object. The octets are shared, never copied, with whoever else holds them. */
    struct Object {
        std::shared_ptr<const Data> data;
        std::string entityTag;                              //!< as in File@File-ETag when the FDT has one, else made by the AS
        std::string mediaType;                              //!< empty when unknown
        std::chrono::system_clock::time_point lastModified;
    };

    /**
     * \param retention  how long an object is kept after it was stored; zero keeps nothing.
     * \param max_octets the most octets kept in all; zero keeps nothing. An object longer than this is not kept at all.
     */
    RepairObjectStore(std::chrono::seconds retention, std::size_t max_octets)
        :m_retention(retention), m_maxOctets(max_octets) {}

    RepairObjectStore(const RepairObjectStore &) = delete;
    RepairObjectStore &operator=(const RepairObjectStore &) = delete;

    /** Keep an object under a path. A later object for the same path replaces it and starts its retention again.
     *
     * \return false when nothing was kept: no octets to keep, no retention, or the object is longer than the octet limit.
     */
    bool put(const std::string &path, Object &&object, time_type now)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        removeLocked(path);
        if (m_retention.count() <= 0 || !object.data) return false;
        const std::size_t size = object.data->size();
        if (size > m_maxOctets) return false;
        dropExpiredLocked(now);
        while (m_octets + size > m_maxOctets && !m_order.empty()) dropOldestLocked();
        m_order.push_back(path);
        m_entries[path] = Entry{std::make_shared<const Object>(std::move(object)), now + m_retention, std::prev(m_order.end())};
        m_octets += size;
        return true;
    }

    /** The object kept under a path, or nothing when there is none or its retention has run out. */
    std::shared_ptr<const Object> get(const std::string &path, time_type now)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_entries.find(path);
        if (it == m_entries.end()) return nullptr;
        if (it->second.expires <= now) {
            removeLocked(path);
            return nullptr;
        }
        return it->second.object;
    }

    /** Drop every object whose retention has run out. \return how many were dropped. */
    std::size_t purgeExpired(time_type now)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return dropExpiredLocked(now);
    }

    /** Drop every object. */
    void clear()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_entries.clear();
        m_order.clear();
        m_octets = 0;
    }

    std::size_t objectCount() const { std::lock_guard<std::mutex> lock(m_mutex); return m_entries.size(); }
    std::size_t octetCount() const { std::lock_guard<std::mutex> lock(m_mutex); return m_octets; }
    std::chrono::seconds retention() const { return m_retention; }
    std::size_t maxOctets() const { return m_maxOctets; }

private:
    struct Entry {
        std::shared_ptr<const Object> object;
        time_type expires;
        std::list<std::string>::iterator position;  //!< in m_order, which runs from the object stored first to the one stored last
    };

    void removeLocked(const std::string &path)
    {
        auto it = m_entries.find(path);
        if (it == m_entries.end()) return;
        m_octets -= it->second.object->data ? it->second.object->data->size() : 0;
        m_order.erase(it->second.position);
        m_entries.erase(it);
    }

    std::size_t dropExpiredLocked(time_type now)
    {
        std::size_t dropped = 0;
        // The retention is the same for every object, so the object stored first is the first to expire.
        while (!m_order.empty()) {
            const auto it = m_entries.find(m_order.front());
            if (it != m_entries.end() && it->second.expires > now) break;
            dropOldestLocked();
            dropped++;
        }
        return dropped;
    }

    /** Drop the object stored first. The order list and the map are kept in step by every other member; an order node with no object
     * (which no member leaves behind) is dropped too, so that a loop that drops from the front always makes progress. */
    void dropOldestLocked()
    {
        const std::string path = m_order.front();
        if (m_entries.find(path) != m_entries.end()) removeLocked(path);
        else m_order.pop_front();
    }

    mutable std::mutex m_mutex;
    const std::chrono::seconds m_retention;
    const std::size_t m_maxOctets;
    std::map<std::string, Entry> m_entries;
    std::list<std::string> m_order;
    std::size_t m_octets = 0;
};

/** The path under which an object is hosted, from its File@Content-Location and the distribution base URL.
 *
 * TS 26.517 V19.2.0 clause 6.2.4.4: "If both the repair base URL and the distribution base URL are both present, then the network
 * location of the repair object is the value of File@Content-Location with the Base URI according to RFC 3986 [34] being the
 * distribution base URL replaced with the repair base URL." and "If the repair base URL is present, but not the distribution base
 * URL, then the network location of the repair object is the value of File@Content-Location with the Retrieval URI according to
 * RFC 3986 [34] replaced with the repair base URL."
 *
 * What remains after the distribution base URL is the path the client appends to the repair base URL. With no distribution base
 * URL, or one that the location does not start with, the Retrieval URI is the scheme and authority and what remains is the path
 * and query of the location. A location with no path gives "/".
 */
inline std::string repairPathOf(const std::string &content_location, const std::optional<std::string> &distribution_base_url)
{
    std::string rest;
    if (distribution_base_url && !distribution_base_url->empty() && content_location.starts_with(*distribution_base_url)) {
        rest = content_location.substr(distribution_base_url->size());
    } else {
        const auto scheme_end = content_location.find("://");
        if (scheme_end == std::string::npos) {
            rest = content_location;
        } else {
            const auto path_start = content_location.find('/', scheme_end + 3);
            rest = path_start == std::string::npos ? std::string() : content_location.substr(path_start);
        }
    }
    if (rest.empty() || rest.front() != '/') rest.insert(rest.begin(), '/');
    return rest;
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* MBSTF_REPAIR_OBJECT_STORE_HH */
