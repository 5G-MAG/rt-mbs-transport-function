#ifndef MBSTF_ENTITY_TAG_HH
#define MBSTF_ENTITY_TAG_HH
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: HTTP entity-tag formatting
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

#include <string>
#include <string_view>

#include "common.hh"

MBSTF_NAMESPACE_START

/** Strip the weak indicator and the surrounding DQUOTEs from an entity-tag.
 *
 * Returns the opaque-tag characters alone, which is the part that comparison
 * operates on.
 */
inline std::string_view entityTagOpaque(std::string_view tag)
{
    if (tag.size() >= 2 && tag.compare(0, 2, "W/") == 0) tag.remove_prefix(2);
    if (tag.size() >= 2 && tag.front() == '"' && tag.back() == '"') {
        tag.remove_prefix(1);
        tag.remove_suffix(1);
    }
    return tag;
}

/** Render an entity-tag in the form an ETag header field value must take.
 *
 * RFC 9110 section 8.8.3 gives the grammar as "opaque-tag = DQUOTE *etagc DQUOTE",
 * so the quotes are part of the field value and not display punctuation. A caller
 * holding a bare digest would otherwise emit it unquoted, which no conditional
 * request can then match. A value already carrying its quotes, weak or strong, is
 * returned unchanged rather than quoted twice.
 */
inline std::string entityTagQuoted(std::string_view tag)
{
    if (tag.size() >= 2 && tag.compare(0, 2, "W/") == 0) {
        auto opaque = tag.substr(2);
        if (opaque.size() >= 2 && opaque.front() == '"' && opaque.back() == '"') return std::string(tag);
        return std::string("W/\"") + std::string(opaque) + "\"";
    }
    if (tag.size() >= 2 && tag.front() == '"' && tag.back() == '"') return std::string(tag);
    return std::string("\"") + std::string(tag) + "\"";
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* MBSTF_ENTITY_TAG_HH */
