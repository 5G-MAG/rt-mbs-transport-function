#ifndef MBSTF_MBS_AS_RESPONSE_HH
#define MBSTF_MBS_AS_RESPONSE_HH
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: the answer of the co-located MBS AS to a GET
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
#include <cstdint>
#include <ctime>
#include <format>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "common.hh"
#include "EntityTag.hh"
#include "RangeRequest.hh"
#include "RepairObjectStore.hh"

MBSTF_NAMESPACE_START

/** What the co-located MBS AS answers to a request for an object it hosts.
 *
 * TS 26.517 V19.2.0 clause 10.2.3: "An MBS AS shall be an HTTP server that complies with the general provisions in clause 8.2 and
 * 8.3 of the present document and shall respond to all requests as specified in clause 10.2.2.4." The requests of clause 10.2.2.4
 * are a GET for the whole object, a partial GET with a Range header field (several ranges in one request when more are wanted)
 * and, when the client has the entity tag of the object, an If-Match or If-Range header field with it. The preconditions are
 * evaluated in the order of RFC 9110 clause 13.2.2: If-Match, If-None-Match, If-Modified-Since, then Range with If-Range.
 *
 * Nothing here touches a socket: the request header fields come in as values and the answer goes out as a status, header fields and
 * octets, so that every rule is tested without a server.
 */
namespace mbsas {

/** The conditional and range header field values of a request, each absent when the request had no such field. */
struct Conditions {
    std::optional<std::string> ifMatch;
    std::optional<std::string> ifNoneMatch;
    std::optional<std::string> ifModifiedSince;
    std::optional<std::string> ifRange;
    std::optional<std::string> range;
};

struct Reply {
    unsigned status = 200;
    std::vector<std::pair<std::string, std::string>> headers;
    std::vector<unsigned char> body;

    std::optional<std::string> header(const std::string &name) const
    {
        for (const auto &h : headers) if (h.first == name) return h.second;
        return std::nullopt;
    }
};

namespace detail {

inline std::string httpDate(const std::chrono::system_clock::time_point &when)
{
    return std::format("{:%a, %d %b %Y %H:%M:%S GMT}", std::chrono::floor<std::chrono::seconds>(when));
}

/** Read an HTTP-date in any of the three forms RFC 9110 clause 5.6.7 has a recipient accept. */
inline std::optional<std::time_t> parseHttpDate(const std::string &value)
{
    static const char *const formats[] = {"%a, %d %b %Y %H:%M:%S", "%A, %d-%b-%y %H:%M:%S", "%a %b %d %H:%M:%S %Y"};
    for (const char *fmt : formats) {
        std::tm tm{};
        std::istringstream in(value);
        in >> std::get_time(&tm, fmt);
        if (in.fail()) continue;
        return timegm(&tm);
    }
    return std::nullopt;
}

inline std::string_view trimOws(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
    return s;
}

inline bool isWeak(std::string_view tag) { return tag.size() >= 2 && tag.compare(0, 2, "W/") == 0; }

/** Whether a list of entity tags (an If-Match or If-None-Match field value) has a member that matches the tag.
 *
 * RFC 9110 clause 13.1.1: "An origin server MUST use the strong comparison function when comparing entity tags for If-Match". The
 * strong comparison never matches a weak tag. A tag that was written without its quotes is compared on its characters, so that the
 * File@File-ETag value of the FDT matches whether or not it carried them.
 *
 * \param strong  true for If-Match; false for If-None-Match, which compares weakly.
 */
inline bool tagListMatches(std::string_view list, std::string_view etag, bool strong)
{
    if (strong && isWeak(etag)) return false;
    const std::string_view wanted = entityTagOpaque(etag);
    size_t pos = 0;
    while (pos <= list.size()) {
        const auto comma = list.find(',', pos);
        const std::string_view item = trimOws(list.substr(pos, comma == std::string_view::npos ? std::string_view::npos : comma - pos));
        if (item == "*") return true;
        if (!item.empty() && !(strong && isWeak(item)) && entityTagOpaque(item) == wanted) return true;
        if (comma == std::string_view::npos) break;
        pos = comma + 1;
    }
    return false;
}

}  // namespace detail

/** Answer a request for an object.
 *
 * \param method    the request method. GET and HEAD are answered as one: a server that sends the body of a HEAD request is stopped by the
 *                  HTTP library, which keeps the length. Any other method is answered 405 with the Allow header field.
 * \param request   the conditional and range header field values.
 * \param object    the object the request names.
 * \param boundary  the boundary of a multipart/byteranges answer, a string of token characters that does not occur in the object.
 */
inline Reply respond(const std::string &method, const Conditions &request, const RepairObjectStore::Object &object, const std::string &boundary)
{
    using namespace detail;
    Reply reply;
    if (method != "GET" && method != "HEAD") {
        reply.status = 405;
        reply.headers.emplace_back("Allow", "GET, HEAD");
        return reply;
    }

    const uint64_t length = object.data ? object.data->size() : 0;
    const std::string etag = object.entityTag.empty() ? std::string() : entityTagQuoted(object.entityTag);
    const std::string last_modified = httpDate(object.lastModified);

    auto validators = [&](Reply &r) {
        if (!etag.empty()) r.headers.emplace_back("ETag", etag);
        r.headers.emplace_back("Last-Modified", last_modified);
        r.headers.emplace_back("Accept-Ranges", "bytes");
    };

    // 1. If-Match: a failed condition is a 412 and nothing is sent.
    if (request.ifMatch && (etag.empty() ? trimOws(*request.ifMatch) != "*" : !tagListMatches(*request.ifMatch, etag, true))) {
        reply.status = 412;
        return reply;
    }
    // 3. If-None-Match, and 4. If-Modified-Since when there is no If-None-Match: a match, or no change, is a 304.
    bool not_modified = false;
    if (request.ifNoneMatch) {
        not_modified = !etag.empty() ? tagListMatches(*request.ifNoneMatch, etag, false) : trimOws(*request.ifNoneMatch) == "*";
    } else if (request.ifModifiedSince) {
        const auto since = parseHttpDate(*request.ifModifiedSince);
        const auto modified = parseHttpDate(last_modified);
        not_modified = since && modified && *modified <= *since;
    }
    if (not_modified) {
        reply.status = 304;
        validators(reply);
        return reply;
    }

    // 5. Range, unless an If-Range condition is false.
    rangereq::Evaluation evaluation{rangereq::Outcome::Whole, {}};
    if (request.range) {
        bool apply = true;
        if (request.ifRange) {
            const std::string_view cond = trimOws(*request.ifRange);
            if (cond.find('"') != std::string_view::npos && cond.find('"') < 3) {
                // An entity tag: the strong comparison, so a weak tag on either side never matches.
                apply = !etag.empty() && !isWeak(cond) && !isWeak(etag) && entityTagOpaque(cond) == entityTagOpaque(etag);
            } else {
                // An HTTP-date: it has to be exactly the Last-Modified value.
                apply = cond == last_modified;
            }
        }
        if (apply) evaluation = rangereq::evaluate(*request.range, length);
    }

    const auto media_type = object.mediaType.empty() ? std::optional<std::string>() : std::optional<std::string>(object.mediaType);
    const unsigned char *data = object.data ? object.data->data() : nullptr;

    if (evaluation.outcome == rangereq::Outcome::NotSatisfiable) {
        reply.status = 416;
        reply.headers.emplace_back("Content-Range", std::format("bytes */{}", length));
        validators(reply);
        return reply;
    }
    if (evaluation.outcome == rangereq::Outcome::Partial && evaluation.ranges.size() == 1) {
        const auto &r = evaluation.ranges.front();
        reply.status = 206;
        validators(reply);
        if (media_type) reply.headers.emplace_back("Content-Type", *media_type);
        reply.headers.emplace_back("Content-Range", std::format("bytes {}-{}/{}", r.first, r.last, length));
        reply.body.assign(data + r.first, data + r.last + 1);
        return reply;
    }
    if (evaluation.outcome == rangereq::Outcome::Partial) {
        // RFC 9110 clause 15.3.7.2: a multipart/byteranges body, a Content-Range in each part and none in the header section.
        reply.status = 206;
        validators(reply);
        reply.headers.emplace_back("Content-Type", std::format("multipart/byteranges; boundary={}", boundary));
        auto append = [&](const std::string &text) { reply.body.insert(reply.body.end(), text.begin(), text.end()); };
        for (const auto &r : evaluation.ranges) {
            append(std::format("--{}\r\n", boundary));
            if (media_type) append(std::format("Content-Type: {}\r\n", *media_type));
            append(std::format("Content-Range: bytes {}-{}/{}\r\n\r\n", r.first, r.last, length));
            reply.body.insert(reply.body.end(), data + r.first, data + r.last + 1);
            append("\r\n");
        }
        append(std::format("--{}--\r\n", boundary));
        return reply;
    }

    reply.status = 200;
    validators(reply);
    if (media_type) reply.headers.emplace_back("Content-Type", *media_type);
    if (data) reply.body.assign(data, data + length);
    return reply;
}

}  // namespace mbsas

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* MBSTF_MBS_AS_RESPONSE_HH */
