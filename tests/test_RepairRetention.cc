/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: what the MBS AS hosts of a sent object, unit test
 ******************************************************************************
 * License: 5G-MAG Public License v1
 ******************************************************************************/

/* Covers repairObjectOf(): the path an object is hosted under and the octets hosted, for an object sent as it is
 * (TS 26.517 V19.2.0 clause 6.2.4.4 and clause 10.2.3). An object with a content encoding is not hosted, as the MBSTF does not send one.
 */

#include <chrono>
#include <cstdio>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <Transmitter.h>

#include "common.hh"
#include "ObjectStore.hh"
#include "RepairRetention.hh"

using namespace com::fiveg_mag::ref_tools::mbstf;
using FD = LibFlute::Transmitter::FileDescription;

static int g_pass = 0;
static int g_fail = 0;

static void check(bool ok, const std::string &what)
{
    if (ok) {
        g_pass++;
        std::printf("INFO: %s passed.\n", what.c_str());
    } else {
        g_fail++;
        std::printf("ERROR: %s failed.\n", what.c_str());
    }
}

static const std::chrono::system_clock::time_point MODIFIED{std::chrono::seconds{1700000000}};

/* A stored object of 2000 compressible octets whose FDT entry has the given location. */
static std::shared_ptr<ObjectStore::Object> stored(const std::string &location, const std::optional<std::string> &dist_base = std::nullopt, bool with_description = true)
{
    ObjectStore::ObjectData data(2000);
    for (size_t i = 0; i < data.size(); i++) data[i] = static_cast<unsigned char>(i % 7);
    ObjectStore::Metadata metadata("1", "video/mp4", location, location, "acq", MODIFIED, std::nullopt, dist_base);
    auto object = std::make_shared<ObjectStore::Object>(std::move(data), std::move(metadata));
    if (with_description) object->second.fluteFileDescription(new FD(location, object->first));
    return object;
}

int main(int argc, char *argv[])
{
    const std::optional<std::string> dist("https://dist.example/live/");

    /* An object sent as it is. */
    {
        auto o = stored("https://dist.example/live/seg/1.m4s", dist);
        o->second.fluteFileDescription()->set_etag("\"tag1\"");
        auto r = repairObjectOf(o);
        check(r && r->path == "/seg/1.m4s", "the distribution base URL is taken off the location");
        check(r && r->object.data.get() == &o->first && r->object.data->size() == 2000, "the octets are those of the object store, shared and not copied");
        check(r && r->object.entityTag == "\"tag1\"" && r->object.mediaType == "video/mp4" && r->object.lastModified == MODIFIED, "with the entity tag of the FDT entry, the media type and the modification time");
        auto q = repairObjectOf(stored("https://dist.example/live/a.mpd?x=1", dist));
        check(q && q->path == "/a.mpd", "the query part of the location is not part of the path");
        auto nobase = repairObjectOf(stored("https://dist.example/live/seg/1.m4s"));
        check(nobase && nobase->path == "/live/seg/1.m4s", "without a distribution base URL the scheme and authority are what is replaced");
    }

    /* The entity tag. */
    {
        auto o = stored("https://dist.example/live/seg/2.m4s", dist, false);
        o->second.entityTag(std::string("\"from-metadata\""));
        o->second.fluteFileDescription(new FD("https://dist.example/live/seg/2.m4s", o->first));  // the entry has no entity tag: the metadata setter ran before it existed
        auto fallback = repairObjectOf(o);
        check(fallback && fallback->object.entityTag == "\"from-metadata\"", "an object whose FDT entry has no entity tag falls back on the metadata's");
        auto none = stored("https://dist.example/live/seg/3.m4s", dist);
        check(repairObjectOf(none) && repairObjectOf(none)->object.entityTag.empty(), "an object with no entity tag anywhere is hosted without one");
    }

    /* Nothing to host. */
    {
        auto g = stored("https://dist.example/live/seg/1.m4s", dist);
        g->second.fluteFileDescription()->set_compression(FD::CompressionAlgorithm::COMPRESSION_GZIP);
        check(!repairObjectOf(g), "an object whose FDT entry has a gzip content encoding is not hosted: nothing specifies the octets of its copy that this sender has");
        auto d = stored("https://dist.example/live/seg/1.m4s", dist);
        d->second.fluteFileDescription()->set_compression(FD::CompressionAlgorithm::COMPRESSION_DEFLATE);
        check(!repairObjectOf(d), "nor one with another encoding");
        check(!repairObjectOf(stored("https://dist.example/live/seg/1.m4s", dist, false)), "an object that was never packaged is not hosted");
        check(!repairObjectOf(nullptr), "no object is nothing to host");
    }

    std::printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
