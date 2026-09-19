#ifndef _MBS_TF_MEDIA_TYPE_INFERENCE_HH_
#define _MBS_TF_MEDIA_TYPE_INFERENCE_HH_
/*
 * License: 5G-MAG Public License (v1.0)
 */

#include <optional>
#include <string>

#include "common.hh"

MBSTF_NAMESPACE_START

/** Infer an object's media type from its URL when the origin sent no Content-Type.
 *
 * TS 26.517 V18.6.0 clause 6.2.1 binds the MBSTF to the MBMS Download Profile, whose
 * TS 26.346 V18.2.0 clause L.4.2 requires Content-Type in the FDT, so an object with no media
 * type cannot be described conformantly and must not be sent.
 *
 * Inference is by filename extension, taken from the system's own /etc/mime.types where that
 * file exists and from a small built-in table otherwise. The media type is not guessed from the
 * object's content: that is what RFC 9110 clause 8.3 calls examining the data, and the same
 * clause records that implementations doing so disagree, which would make the type an MBSTF
 * chose rather than one the service defined.
 *
 * Returns no value when the extension is unknown. The caller fails the ingest in that case
 * rather than inventing a type.
 */
std::optional<std::string> inferMediaTypeFromUrl(const std::string &url);

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_MEDIA_TYPE_INFERENCE_HH_ */
