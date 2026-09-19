/*
 * License: 5G-MAG Public License (v1.0)
 */

#include <algorithm>
#include <cctype>
#include <fstream>
#include <map>
#include <optional>
#include <sstream>
#include <string>

#include "MediaTypeInference.hh"

MBSTF_NAMESPACE_START

namespace {

/* Enough to describe what an MBS service actually carries when the origin says nothing: DASH and
   HLS manifests, ISOBMFF and MPEG-2 TS segments, WebVTT and TTML subtitles, and the still images a
   service announcement refers to. This table is consulted first, ahead of /etc/mime.types; see
   inferMediaTypeFromUrl() below for why that order matters. */
const std::map<std::string, std::string> &builtinTypes()
{
    static const std::map<std::string, std::string> types{
        {"mpd", "application/dash+xml"},
        {"m3u8", "application/vnd.apple.mpegurl"},
        {"m4s", "video/iso.segment"},
        {"mp4", "video/mp4"},
        {"m4a", "audio/mp4"},
        {"m4v", "video/mp4"},
        {"cmfv", "video/mp4"},
        {"cmfa", "audio/mp4"},
        {"cmft", "application/mp4"},
        {"ts", "video/mp2t"},
        {"aac", "audio/aac"},
        {"vtt", "text/vtt"},
        {"ttml", "application/ttml+xml"},
        {"xml", "application/xml"},
        {"json", "application/json"},
        {"txt", "text/plain"},
        {"jpg", "image/jpeg"},
        {"jpeg", "image/jpeg"},
        {"png", "image/png"},
    };
    return types;
}

/* /etc/mime.types is a sequence of "<media-type> <ext> [<ext>...]" lines, with "#" comments. */
const std::map<std::string, std::string> &systemTypes()
{
    static const std::map<std::string, std::string> types = []{
        std::map<std::string, std::string> result;
        std::ifstream in("/etc/mime.types");
        if (!in) return result;
        std::string line;
        while (std::getline(in, line)) {
            const auto hash = line.find('#');
            if (hash != std::string::npos) line.erase(hash);
            std::istringstream fields(line);
            std::string media_type;
            if (!(fields >> media_type)) continue;
            std::string extension;
            while (fields >> extension) result.emplace(extension, media_type);
        }
        return result;
    }();
    return types;
}

std::optional<std::string> extensionOf(const std::string &url)
{
    /* The path only: a query or fragment is not part of the filename. */
    std::string path = url.substr(0, url.find_first_of("?#"));
    const auto slash = path.find_last_of('/');
    const std::string name = (slash == std::string::npos) ? path : path.substr(slash + 1);
    const auto dot = name.find_last_of('.');
    if (dot == std::string::npos || dot + 1 >= name.size()) return std::nullopt;
    std::string extension = name.substr(dot + 1);
    std::transform(extension.begin(), extension.end(), extension.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return extension;
}

}  // namespace

std::optional<std::string> inferMediaTypeFromUrl(const std::string &url)
{
    const auto extension = extensionOf(url);
    if (!extension) return std::nullopt;

    /* The built-in table is consulted first, and deliberately. /etc/mime.types is a general-purpose
       desktop mapping and is wrong for several extensions a media service uses: on a stock Ubuntu it
       maps ".ts" to text/vnd.trolltech.linguist, a Qt translation source, rather than to the MPEG-2
       transport stream an MBS service would be carrying. The system file is still consulted, for
       extensions this service has no opinion about. */
    const auto &builtin = builtinTypes();
    const auto builtin_entry = builtin.find(*extension);
    if (builtin_entry != builtin.end()) return builtin_entry->second;

    const auto &system_types = systemTypes();
    const auto system_entry = system_types.find(*extension);
    if (system_entry != system_types.end()) return system_entry->second;

    return std::nullopt;
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
