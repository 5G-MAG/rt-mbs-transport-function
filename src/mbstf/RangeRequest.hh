#ifndef MBSTF_RANGE_REQUEST_HH
#define MBSTF_RANGE_REQUEST_HH
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: HTTP byte range evaluation
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

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "common.hh"

MBSTF_NAMESPACE_START

/** Evaluation of a "Range" request header field for the MBS AS that is co-located with the MBSTF.
 *
 * TS 26.517 V19.2.0 clause 10.2.3: "An MBS AS shall be an HTTP server that complies with the general provisions in clause 8.2
 * and 8.3 of the present document and shall respond to all requests as specified in clause 10.2.2.4." Clause 10.2.2.4 has the
 * client send a whole object with GET, or "a HTTP partial GET request" with "multiple byte range requests within a single partial
 * GET request" when a subset is wanted. The rules for answering are those of RFC 9110 clauses 14.1.2, 14.2 and 15.3.7.2.
 */
namespace rangereq {

/** One byte range of a representation, both ends inclusive and counted from zero. */
struct ByteRange {
    uint64_t first;
    uint64_t last;
    bool operator==(const ByteRange &other) const { return first == other.first && last == other.last; }
};

/** What the server does with the request. */
enum class Outcome {
    Whole,          //!< answer 200 with the whole representation: there is no usable Range
    Partial,        //!< answer 206 with `ranges`
    NotSatisfiable  //!< answer 416 with "Content-Range: bytes * /length"
};

struct Evaluation {
    Outcome outcome;
    std::vector<ByteRange> ranges;  //!< in the order of the request, overlapping and adjacent ranges joined; empty unless Partial
};

namespace detail {

inline bool isOws(char c) { return c == ' ' || c == '\t'; }

inline std::string_view trim(std::string_view s)
{
    while (!s.empty() && isOws(s.front())) s.remove_prefix(1);
    while (!s.empty() && isOws(s.back())) s.remove_suffix(1);
    return s;
}

/** Read a string of digits as a number, refusing an empty string, a non-digit and a value that does not fit.
 *
 * RFC 9110 clause 14.1.2: "recipients MUST anticipate potentially large decimal numerals and prevent parsing errors due to integer
 * conversion overflows." A value too large for 64 bits is returned as the largest 64-bit value, which no real object length
 * reaches, so that a first-pos beyond the length is unsatisfiable and a last-pos beyond it is cut to the length.
 */
inline std::optional<uint64_t> number(std::string_view s)
{
    if (s.empty()) return std::nullopt;
    uint64_t value = 0;
    bool saturated = false;
    for (char c : s) {
        if (c < '0' || c > '9') return std::nullopt;
        const unsigned digit = static_cast<unsigned>(c - '0');
        if (saturated) continue;  // every remaining character is still checked to be a digit
        if (value > (UINT64_MAX - digit) / 10) { saturated = true; continue; }
        value = value * 10 + digit;
    }
    return saturated ? UINT64_MAX : value;
}

inline bool equalsIgnoreCase(std::string_view a, std::string_view b)
{
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x = static_cast<char>(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z') y = static_cast<char>(y - 'A' + 'a');
        if (x != y) return false;
    }
    return true;
}

/** A range-spec as the request wrote it, before it is held against a length. */
struct Spec {
    bool suffix;        //!< "-N": the last N bytes
    uint64_t first;     //!< first-pos, or N for a suffix
    std::optional<uint64_t> last;  //!< last-pos, when given
};

}  // namespace detail

/** Evaluate a Range header field value against the length of the representation.
 *
 * - A unit other than "bytes" is ignored: RFC 9110 clause 14.2 "An origin server MUST ignore a Range header field that contains a
 *   range unit it does not understand."
 * - A ranges-specifier that does not parse, or a range-spec whose last-pos is less than its first-pos, is ignored (the whole
 *   representation is sent): the clause lets a server "ignore or reject" it.
 * - A representation of zero length is sent whole: the clause lets a server ignore Range then.
 * - If no range-spec is satisfiable the answer is 416: "the ranges-specifier is unsatisfiable with respect to the selected
 *   representation, the server SHOULD send a 416 (Range Not Satisfiable) response."
 * - A last-pos at or beyond the length is cut to the last byte, and a suffix longer than the representation is the whole of it
 *   (clause 14.1.2).
 * - Overlapping and adjacent ranges are joined, which clause 15.3.7.2 allows ("a server MAY coalesce any of the ranges that
 *   overlap"), so that the answer is never larger than the representation however many ranges the request lists. The order of
 *   the request is kept for the ranges that remain.
 *
 * \param range_value  the field value of the Range header field, without the field name.
 * \param length       the length in octets of the representation (of the coded bytes where a content coding applies).
 */
inline Evaluation evaluate(std::string_view range_value, uint64_t length)
{
    using namespace detail;
    const Evaluation whole{Outcome::Whole, {}};

    range_value = trim(range_value);
    const auto eq = range_value.find('=');
    if (eq == std::string_view::npos) return whole;
    if (!equalsIgnoreCase(trim(range_value.substr(0, eq)), "bytes")) return whole;

    std::vector<Spec> specs;
    std::string_view rest = range_value.substr(eq + 1);
    while (true) {
        const auto comma = rest.find(',');
        std::string_view item = trim(rest.substr(0, comma));
        if (!item.empty()) {  // an empty list element is allowed by the list syntax and carries no range
            const auto dash = item.find('-');
            if (dash == std::string_view::npos) return whole;
            const std::string_view a = trim(item.substr(0, dash));
            const std::string_view b = trim(item.substr(dash + 1));
            if (a.empty()) {
                const auto n = number(b);
                if (!n) return whole;
                specs.push_back({true, *n, std::nullopt});
            } else {
                const auto first = number(a);
                if (!first) return whole;
                if (b.empty()) {
                    specs.push_back({false, *first, std::nullopt});
                } else {
                    const auto last = number(b);
                    if (!last || *last < *first) return whole;
                    specs.push_back({false, *first, *last});
                }
            }
        }
        if (comma == std::string_view::npos) break;
        rest.remove_prefix(comma + 1);
    }
    if (specs.empty()) return whole;
    if (length == 0) return whole;

    std::vector<ByteRange> satisfiable;
    for (const Spec &s : specs) {
        if (s.suffix) {
            if (s.first == 0) continue;  // a suffix-length of zero is not satisfiable
            satisfiable.push_back({s.first >= length ? 0 : length - s.first, length - 1});
        } else {
            if (s.first >= length) continue;
            const uint64_t last = (!s.last || *s.last >= length) ? length - 1 : *s.last;
            satisfiable.push_back({s.first, last});
        }
    }
    if (satisfiable.empty()) return {Outcome::NotSatisfiable, {}};

    // Join ranges that overlap or touch. A joined range keeps the place of the earliest request range it absorbed.
    struct Held { ByteRange range; size_t order; };
    std::vector<Held> held;
    for (size_t n = 0; n < satisfiable.size(); n++) {
        Held current{satisfiable[n], n};
        bool merged = true;
        while (merged) {
            merged = false;
            for (size_t i = 0; i < held.size(); i++) {
                const ByteRange &j = held[i].range;
                const bool apart = (current.range.first > j.last && current.range.first - j.last > 1) ||
                                   (j.first > current.range.last && j.first - current.range.last > 1);
                if (!apart) {
                    current.range.first = current.range.first < j.first ? current.range.first : j.first;
                    current.range.last = current.range.last > j.last ? current.range.last : j.last;
                    current.order = current.order < held[i].order ? current.order : held[i].order;
                    held.erase(held.begin() + static_cast<std::ptrdiff_t>(i));
                    merged = true;
                    break;
                }
            }
        }
        held.push_back(current);
    }
    std::vector<ByteRange> joined;
    for (size_t order = 0; order < satisfiable.size(); order++) {
        for (const Held &h : held) if (h.order == order) joined.push_back(h.range);
    }
    return {Outcome::Partial, joined};
}

}  // namespace rangereq

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* MBSTF_RANGE_REQUEST_HH */
