/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: FEC OTI helper
 ******************************************************************************
 * Copyright: (C)2025-2026 British Broadcasting Corporation
 * Author(s): Dev Audsin <dev.audsin@bbc.co.uk>
 *            David Waring <david.waring2@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "Transmitter.h" // LibFlute

#include "openapi/model/FECConfig.h"

#include "FecOtiHelper.hh"

MBSTF_NAMESPACE_START

namespace {

/* fecScheme is a URN naming an IANA "RMT FEC Encoding ID" (RFC 5052). TS 29.580 V18.8.0 clause
   6.2.6.2.14, table 6.2.6.2.14-1, row fecScheme: "It shall be identified using a term from the
   IANA: "Reliable Multicast Transport (RMT) FEC Encoding IDs and FEC Instance IDs" [20] expressed
   as a URN, e.g.: urn:ietf:rmt:fec:encoding:0". RFC 5053 clause 7 (IANA Considerations): "This
   document assigns the Fully-Specified FEC Encoding ID 1 under the ietf:rmt:fec:encoding
   name-space to "Raptor Code"." rt-libflute's own FecScheme enum (include/flute_types.h) fixes the
   same numeric values on the wire (FEC-OTI-FEC-Encoding-ID): CompactNoCode=0, Raptor=1, RaptorQ=6. */
const char * const kFecSchemeCompactNoCode = "urn:ietf:rmt:fec:encoding:0";
const char * const kFecSchemeRaptor        = "urn:ietf:rmt:fec:encoding:1";
const char * const kFecSchemeRaptorQ       = "urn:ietf:rmt:fec:encoding:6";

} // anonymous namespace

std::pair<std::optional<LibFlute::FecOti>, uint32_t> fecOtiFromFecConfig(
        const std::optional<std::shared_ptr<reftools::mbstf::FECConfig>> &fec_information)
{
    if (!fec_information || !fec_information.value()) {
        return {std::nullopt, LibFlute::kDefaultFecRedundancyLevel};
    }

    const reftools::mbstf::FECConfig &fec_config = *fec_information.value();
    const std::string &fec_scheme = fec_config.getFecScheme();
    int32_t fec_overhead = fec_config.getFecOverHead();

    if (fec_overhead < 0) {
        throw std::runtime_error("fecOverHead must not be negative: " + std::to_string(fec_overhead));
    }

    if (fec_scheme == kFecSchemeCompactNoCode) {
        return {std::nullopt, LibFlute::kDefaultFecRedundancyLevel};
    }
    if (fec_scheme == kFecSchemeRaptor) {
        LibFlute::FecOti oti{};
        oti.encoding_id = LibFlute::FecScheme::Raptor;
        /* max_source_block_length and encoding_symbol_length are left at their defaults (0):
           rt-libflute's own Transmitter derives encoding_symbol_length from the session's path MTU
           and, under the 3GPP profiles, caps max_source_block_length at the TS 26.346 clause 7.2.3
           256 KB sub-block ceiling itself when it is left 0. No MBSTF-side bound is invented here. */
        return {oti, static_cast<uint32_t>(fec_overhead)};
    }
    if (fec_scheme == kFecSchemeRaptorQ) {
        throw std::runtime_error(
            "fecScheme " + fec_scheme + " (RaptorQ) is not one of the FEC schemes the MBMS Download "
            "Profile admits (TS 26.346 V18.2.0 clause L.4.7); this MBSTF cannot honour it");
    }
    throw std::runtime_error("fecScheme " + fec_scheme + " is not implemented by this MBSTF");
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
