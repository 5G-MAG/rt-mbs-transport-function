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

/** What the co-located MBS AS has to host for an object of the MBSTF, and where.
 *
 * TS 26.517 V19.2.0 clause 6.2.4.4 gives the location of the repair object from the File@Content-Location of the FDT Instance and the
 * distribution base URL (see repairPathOf()). The location is the one the packager gives the object: the fetched URL with the ingest base URL replaced
 * by the distribution base URL when both are set, which is also what the file description holds once the object has been queued for sending. The
 * object is hosted from the moment it is in the object store, not from the moment it has been sent: a client that has lost part of an object needs the
 * whole of it, and an object in flight when the session ends is the one most likely to need repair. The File-ETag is the entity tag of the metadata,
 * which is what the file description carries. The query part of a location is not part of the path the AS looks up. The octets of an object are shared
 * with the object store, not copied.
 *
 * Clause 6.2.4.4 also says that for an object whose FDT entry has File@Content-Encoding "gzip" the ".gz" copy of the object is hosted. The MBSTF does
 * not send such objects: rt-libflute refuses a content encoding under the 3GPP profiles (5G-MAG/Standards#212), so there is none to host, and an object
 * that has an encoding, or is marked to be sent compressed, is left out here rather than hosted under a path or with octets nobody specified. When the
 * sender can carry a compressed object, the ".gz" copy is to be added, from the octets that were sent.
 */
inline std::optional<RetainedObject> repairObjectOf(const std::shared_ptr<ObjectStore::Object> &stored)
{
    if (!stored) return std::nullopt;
    const ObjectStore::Metadata &metadata = stored->second;
    const auto description = metadata.fluteFileDescription();

    std::string location;
    std::string etag = metadata.entityTag().value_or(std::string());
    if (description) {
        const auto &entry = description->file_entry();
        if (!entry.content_encoding.empty()) return std::nullopt;
        location = entry.content_location;
        if (!entry.etag.empty()) etag = entry.etag;
    } else {
        if (metadata.compressedSend()) return std::nullopt;
        const std::string ingest_base = metadata.objIngestBaseUrl().value_or(std::string());
        const std::string distribution_base = metadata.objDistributionBaseUrl().value_or(std::string());
        const std::string fetched = metadata.getFetchedUrl();
        location = (!ingest_base.empty() && !distribution_base.empty() && fetched.starts_with(ingest_base))
                       ? distribution_base + fetched.substr(ingest_base.size())
                       : fetched;
    }
    if (location.empty()) return std::nullopt;

    std::string path = repairPathOf(location, metadata.objDistributionBaseUrl());
    if (const auto query = path.find('?'); query != std::string::npos) path.erase(query);

    RepairObjectStore::Object object;
    object.data = std::shared_ptr<const RepairObjectStore::Data>(stored, &stored->first);
    object.entityTag = etag;
    object.mediaType = metadata.mediaType();
    if (object.mediaType.empty() && description) object.mediaType = description->file_entry().content_type;
    object.lastModified = metadata.modified();
    return RetainedObject{std::move(path), std::move(object)};
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* MBSTF_REPAIR_RETENTION_HH */
