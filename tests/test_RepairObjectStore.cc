/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: objects kept for unicast Object Repair, unit test
 ******************************************************************************
 * License: 5G-MAG Public License v1
 ******************************************************************************/

/* Covers RepairObjectStore, which keeps the objects the co-located MBS AS hosts for as long as the operator allows (TS 26.517
 * V19.2.0 clause 10.2.3), repairPathOf(), which gives the path an object is hosted under (clause 6.2.4.4), and RepairRegistry, which
 * keeps one store per Distribution Session.
 */

#include <atomic>
#include <chrono>
#include <cstdio>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "common.hh"
#include "RepairObjectStore.hh"
#include "RepairRegistry.hh"

using namespace com::fiveg_mag::ref_tools::mbstf;
using std::chrono::seconds;
using Store = RepairObjectStore;

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

static Store::Object object(size_t size, const std::string &etag = "\"e\"")
{
    return Store::Object{std::make_shared<const Store::Data>(size, static_cast<unsigned char>('x')), etag, "video/mp4", {}};
}

int main(int argc, char *argv[])
{
    const Store::time_type t0 = Store::clock_type::now();

    /* Keeping and finding. */
    {
        Store s(seconds(60), 1000);
        check(s.put("/a", object(100, "\"tag-a\""), t0), "an object is kept");
        auto got = s.get("/a", t0 + seconds(1));
        check(got && got->data->size() == 100 && got->entityTag == "\"tag-a\"" && got->mediaType == "video/mp4", "it is found with its entity tag and media type");
        check(!s.get("/b", t0), "a path that was never stored is not found");
        check(s.objectCount() == 1 && s.octetCount() == 100, "one object of 100 octets is held");
    }

    /* Retention. */
    {
        Store s(seconds(60), 1000);
        s.put("/a", object(100), t0);
        check(s.get("/a", t0 + seconds(59)) != nullptr, "an object is served until its retention has run out");
        check(s.get("/a", t0 + seconds(60)) == nullptr, "an object is not served from the moment its retention has run out");
        check(s.objectCount() == 0 && s.octetCount() == 0, "the expired object is dropped and its octets given back");
    }
    {
        Store s(seconds(60), 1000);
        s.put("/a", object(100), t0);
        s.put("/b", object(100), t0 + seconds(30));
        check(s.purgeExpired(t0 + seconds(59)) == 0, "nothing is purged before the first retention ends");
        check(s.purgeExpired(t0 + seconds(70)) == 1 && s.objectCount() == 1, "only the expired object is purged");
        check(s.get("/b", t0 + seconds(70)) != nullptr, "the object stored later is still served");
    }

    /* A later object for the same path replaces the earlier one and starts its retention again. */
    {
        Store s(seconds(60), 1000);
        s.put("/a", object(100, "\"v1\""), t0);
        s.put("/a", object(300, "\"v2\""), t0 + seconds(50));
        auto got = s.get("/a", t0 + seconds(100));
        check(got && got->entityTag == "\"v2\"" && got->data->size() == 300, "the later object is the one served");
        check(s.objectCount() == 1 && s.octetCount() == 300, "the replaced object's octets are given back");
        check(s.get("/a", t0 + seconds(110)) == nullptr, "the retention of the later object ends 60 seconds after it was stored");
    }

    /* The octet limit drops the object stored first. */
    {
        Store s(seconds(600), 1000);
        s.put("/a", object(400), t0);
        s.put("/b", object(400), t0 + seconds(1));
        s.put("/c", object(400), t0 + seconds(2));
        check(!s.get("/a", t0 + seconds(3)) && s.get("/b", t0 + seconds(3)) && s.get("/c", t0 + seconds(3)), "the object stored first is dropped when the limit is reached");
        check(s.octetCount() == 800, "the octets held stay within the limit");
        s.put("/d", object(900), t0 + seconds(4));
        check(s.objectCount() == 1 && s.get("/d", t0 + seconds(5)) != nullptr && s.octetCount() == 900, "an object that needs the room of several drops them all");
    }
    {
        Store s(seconds(600), 1000);
        s.put("/a", object(100, "\"old\""), t0);
        check(!s.put("/a", object(1001), t0 + seconds(1)), "an object longer than the limit is not kept");
        check(!s.get("/a", t0 + seconds(2)), "the earlier object of that path, now out of date, is no longer served");
        check(s.octetCount() == 0, "no octets are held");
    }

    /* Nothing is kept when retention or the octet limit is zero. */
    {
        Store none(seconds(0), 1000), nobytes(seconds(60), 0);
        check(!none.put("/a", object(10), t0) && none.objectCount() == 0, "a retention of zero keeps nothing");
        check(!nobytes.put("/a", object(10), t0) && nobytes.objectCount() == 0, "an octet limit of zero keeps nothing");
        Store s(seconds(60), 1000);
        check(!s.put("/a", Store::Object{nullptr, "", "", {}}, t0), "an object with no octets is not kept");
    }

    /* The octets are shared, not copied. */
    {
        Store s(seconds(60), 1000);
        auto data = std::make_shared<const Store::Data>(50, static_cast<unsigned char>(1));
        s.put("/a", Store::Object{data, "\"e\"", "", {}}, t0);
        check(s.get("/a", t0)->data.get() == data.get(), "the store holds the caller's octets, not a copy");
        s.clear();
        check(s.objectCount() == 0 && s.octetCount() == 0 && data.use_count() == 1, "clear drops everything and lets the octets go");
    }

    /* An answer being sent stays valid when the object is dropped meanwhile. */
    {
        Store s(seconds(60), 100);
        s.put("/a", object(80), t0);
        auto held = s.get("/a", t0);
        s.put("/b", object(80), t0 + seconds(1));
        check(!s.get("/a", t0 + seconds(1)) && held && held->data->size() == 80, "an object already handed out outlives its removal from the store");
    }

    /* Several threads at once. */
    {
        Store s(seconds(600), 5000);
        std::atomic<bool> broken{false};
        std::vector<std::thread> threads;
        for (int t = 0; t < 4; t++) {
            threads.emplace_back([&, t]() {
                for (int i = 0; i < 2000; i++) {
                    const std::string path = "/t" + std::to_string(t) + "/" + std::to_string(i % 30);
                    s.put(path, object(100 + (i % 7)), t0 + seconds(i % 5));
                    auto got = s.get(path, t0 + seconds(i % 5));
                    if (got && got->data->size() < 100) broken = true;
                    if (s.octetCount() > 5000) broken = true;
                }
            });
        }
        for (auto &th : threads) th.join();
        check(!broken && s.octetCount() <= 5000, "four threads storing and reading at once leave the limit kept");
    }

    /* The path an object is hosted under. */
    const std::optional<std::string> dist("https://dist.example.com/live/");
    check(repairPathOf("https://dist.example.com/live/seg/1.m4s", dist) == "/seg/1.m4s", "the distribution base URL is taken off");
    check(repairPathOf("https://dist.example.com/live/a.mpd?x=1", dist) == "/a.mpd?x=1", "a query stays");
    check(repairPathOf("https://other.example.org/live/seg/1.m4s", dist) == "/live/seg/1.m4s", "a location the base does not start is cut at the scheme and authority");
    check(repairPathOf("https://dist.example.com/live/seg/1.m4s", std::nullopt) == "/live/seg/1.m4s", "with no distribution base URL the scheme and authority are replaced");
    check(repairPathOf("https://dist.example.com/live/seg/1.m4s", std::string()) == "/live/seg/1.m4s", "an empty distribution base URL is no base");
    check(repairPathOf("https://dist.example.com", std::nullopt) == "/", "a location with no path is the root");
    check(repairPathOf("seg/1.m4s", std::nullopt) == "/seg/1.m4s", "a location with no scheme is taken as a path");
    check(repairPathOf("https://dist.example.com/live", dist) == "/live", "a location the base does not reach keeps its own path");
    check(repairPathOf("https://dist.example.com/live/", dist) == "/", "the base itself is the root");

    /* One store per Distribution Session. */
    {
        RepairRegistry r(seconds(60), 250);
        check(r.put("s1", "/a", object(100), t0) && r.put("s2", "/a", object(100, "\"other\""), t0), "two sessions keep an object under the same path");
        check(r.get("s1", "/a", t0)->entityTag == "\"e\"" && r.get("s2", "/a", t0)->entityTag == "\"other\"", "each session's object is its own");
        check(!r.get("s3", "/a", t0) && !r.get("s1", "/b", t0), "a session or path that is not held is not found");
        check(r.sessionCount() == 2, "two sessions are held");
        r.put("s1", "/b", object(100), t0 + seconds(1));
        check(!r.put("s1", "/c", object(300), t0 + seconds(2)), "the octet limit is that of one session");
        r.put("s1", "/c", object(100), t0 + seconds(2));
        check(!r.get("s1", "/a", t0 + seconds(3)) && r.get("s1", "/b", t0 + seconds(3)) && r.get("s1", "/c", t0 + seconds(3)) && r.get("s2", "/a", t0 + seconds(3)), "a session at its limit drops its own oldest object and no other session's");
        check(r.purgeExpired(t0 + seconds(61)) == 2 && r.sessionCount() == 1 && r.get("s1", "/c", t0 + seconds(61)), "a purge drops the objects whose retention has run out, and a store left empty");
        check(r.purgeExpired(t0 + seconds(200)) == 1 && r.sessionCount() == 0, "the last session's last object goes and its store with it");
        check(r.put("s1", "/a", object(10), t0 + seconds(300)) && r.sessionCount() == 1, "a session is made again when an object arrives for it");
    }

    std::printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
