#ifndef _MBSTF_FEC_OTI_HELPER_HH_
#define _MBSTF_FEC_OTI_HELPER_HH_
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
#include <memory>
#include <optional>
#include <utility>

#include "Transmitter.h" // LibFlute

#include "common.hh"
#include "openapi/model/FECConfig.h"

MBSTF_NAMESPACE_START

/* Only Raptor (RFC 5053) is wired here. TS 26.517 V18.6.0 clause 6.2.1 binds every FLUTE object
   distribution session this component runs to the MBMS Download Profile ("the MBS Distribution
   Session shall conform to the MBMS Download Profile as defined in clause L.4 of TS 26.346"), and
   TS 26.346 V18.2.0 clause L.4.7 admits exactly two AL-FEC schemes into that profile: "the Compact
   No-Code FEC scheme as specified in RFC 3695 [13], and the Raptor FEC scheme as specified in RFC
   5053 [91] are optional to implement by the BM-SC and mandatory to support by the UE." RaptorQ is
   RFC 6330, referenced by neither TS 26.346 nor TS 26.517, and rt-libflute's own Transmitter now
   refuses it under this profile at construction (Transmitter.cpp, citing the same L.4.7 sentence)
   rather than send a session no conformant receiver has any obligation to decode. Requesting it
   here is therefore reported as a packaging failure rather than passed through to a constructor
   that would throw.

   Returns the Transmitter-level FEC OTI to apply (unset for no FEC or Compact No-Code, which
   carries no repair symbols of its own and so has the same observable effect) and the FEC
   redundancy level (TS 26.346 V18.2.0 clause 7.3.2.11) to apply when one is requested. Throws
   std::runtime_error for a scheme this MBSTF does not wire or a malformed overhead value.

   Shared by every ObjectPackager subclass that constructs its own LibFlute::Transmitter
   (originally ObjectListPackager-local; extracted so ObjectCarouselPackager can apply the same
   Distribution-Session-requested FEC configuration instead of always sending unprotected FLUTE). */
std::pair<std::optional<LibFlute::FecOti>, uint32_t> fecOtiFromFecConfig(
        const std::optional<std::shared_ptr<reftools::mbstf::FECConfig>> &fec_information);

MBSTF_NAMESPACE_STOP

#endif /* _MBSTF_FEC_OTI_HELPER_HH_ */

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
