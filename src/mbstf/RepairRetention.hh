#ifndef MBSTF_REPAIR_RETENTION_HH
#define MBSTF_REPAIR_RETENTION_HH
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: what the MBS AS hosts of a sent object
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

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <Transmitter.h>

#include "common.hh"
#include "ObjectStore.hh"
#include "RepairObjectStore.hh"

MBSTF_NAMESPACE_START

/** An object ready to be kept by the MBS AS: the path it is hosted under and the object itself. */
struct RetainedObject {
    std::string path;
    RepairObjectStore::Object object;
};

/** What the co-located MBS AS has to host for an object the MBSTF has sent, and where.
 *
 * TS 26.517 V19.2.0 clause 6.2.4.4 gives the location of the repair object from the File@Content-Location of the FDT Instance and the
 * distribution base URL (see repairPathOf()). The values come from the FDT entry that was sent, so that the entity tag and the location are those the
 * client holds. The query part of a location is not part of the path the AS looks up. The octets of an object are shared with the object store, not copied.
 *
 * Clause 6.2.4.4 also says that for an object whose FDT entry has File@Content-Encoding "gzip" the ".gz" copy of the object is hosted. The MBSTF does
 * not send such objects: rt-libflute refuses a content encoding under the 3GPP profiles (5G-MAG/Standards#212), so there is none to host, and an object
 * whose FDT entry has any content encoding is left out here rather than hosted under a path or with octets nobody specified. When the sender can carry
 * a compressed object, the ".gz" copy is to be added, from the octets that were sent.
 *
 * Nothing is hosted for an object that has no file description, which is one that was never packaged.
 */
inline std::optional<RetainedObject> repairObjectOf(const std::shared_ptr<ObjectStore::Object> &stored)
{
    if (!stored) return std::nullopt;
    const ObjectStore::Metadata &metadata = stored->second;
    const auto description = metadata.fluteFileDescription();
    if (!description) return std::nullopt;
    const auto &entry = description->file_entry();
    if (!entry.content_encoding.empty()) return std::nullopt;

    std::string path = repairPathOf(entry.content_location, metadata.objDistributionBaseUrl());
    if (const auto query = path.find('?'); query != std::string::npos) path.erase(query);

    RepairObjectStore::Object object;
    object.data = std::shared_ptr<const RepairObjectStore::Data>(stored, &stored->first);
    object.entityTag = !entry.etag.empty() ? entry.etag : metadata.entityTag().value_or(std::string());
    object.mediaType = !metadata.mediaType().empty() ? metadata.mediaType() : entry.content_type;
    object.lastModified = metadata.modified();
    return RetainedObject{std::move(path), std::move(object)};
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* MBSTF_REPAIR_RETENTION_HH */
