/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: the answer of the co-located MBS AS, unit test
 ******************************************************************************
 * License: 5G-MAG Public License v1
 ******************************************************************************/

/* Covers mbsas::respond(): what the co-located MBS AS answers to the requests of TS 26.517 V19.2.0 clause 10.2.2.4 (a GET for the
 * whole object, a partial GET with one or several byte ranges, with an If-Match or If-Range entity tag), following RFC 9110
 * clauses 13.1.1, 13.1.2, 13.1.3, 13.1.5, 13.2.2, 14.2, 14.4 and 15.3.7.2.
 */

#include <chrono>
#include <cstdio>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "common.hh"
#include "MbsAsResponse.hh"

using namespace com::fiveg_mag::ref_tools::mbstf;
using mbsas::Conditions;
using mbsas::Reply;

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

/* An object of 100 octets, 0 to 99, last modified at a known time. */
static RepairObjectStore::Object object(const std::string &etag = "\"v1\"", const std::string &type = "video/mp4", size_t size = 100)
{
    auto data = std::make_shared<RepairObjectStore::Data>(size);
    for (size_t i = 0; i < size; i++) (*data)[i] = static_cast<unsigned char>(i);
    return RepairObjectStore::Object{data, etag, type, std::chrono::system_clock::time_point{std::chrono::seconds{1700000000}}};
}

static const char *LM = "Tue, 14 Nov 2023 22:13:20 GMT";

static std::string text(const Reply &r) { return std::string(r.body.begin(), r.body.end()); }

static Reply get(const Conditions &c, const RepairObjectStore::Object &o = object(), const std::string &method = "GET")
{
    return mbsas::respond(method, c, o, "B");
}

static Conditions range(const std::string &v) { Conditions c; c.range = v; return c; }

int main(int argc, char *argv[])
{
    /* A plain GET. */
    {
        Reply r = get({});
        check(r.status == 200 && r.body.size() == 100 && r.body[7] == 7, "a GET is answered 200 with the whole object");
        check(r.header("ETag") == std::optional<std::string>("\"v1\"") && r.header("Last-Modified") == std::optional<std::string>(LM), "with its entity tag and modification time");
        check(r.header("Accept-Ranges") == std::optional<std::string>("bytes") && r.header("Content-Type") == std::optional<std::string>("video/mp4"), "and says ranges are accepted, and the media type");
        check(get({}, object("abc")).header("ETag") == std::optional<std::string>("\"abc\""), "an entity tag stored without quotes is sent with them");
        check(!get({}, object("")).header("ETag"), "no entity tag is sent when the object has none");
        check(!get({}, object("\"v1\"", "")).header("Content-Type"), "no media type is sent when the object has none");
        check(get({}, object(), "HEAD").status == 200, "a HEAD request is answered as a GET");
        Reply post = get({}, object(), "POST");
        check(post.status == 405 && post.header("Allow") == std::optional<std::string>("GET, HEAD") && post.body.empty(), "another method is answered 405 with Allow");
    }

    /* One range. */
    {
        Reply r = get(range("bytes=10-19"));
        check(r.status == 206 && r.body.size() == 10 && r.body.front() == 10 && r.body.back() == 19, "one range is answered 206 with those octets");
        check(r.header("Content-Range") == std::optional<std::string>("bytes 10-19/100"), "with the Content-Range of the octets and the length");
        check(r.header("Content-Type") == std::optional<std::string>("video/mp4") && r.header("ETag") == std::optional<std::string>("\"v1\""), "the media type and entity tag are kept");
        check(get(range("bytes=-5")).header("Content-Range") == std::optional<std::string>("bytes 95-99/100"), "a suffix range is answered with the last octets");
        check(get(range("bytes=90-")).body.size() == 10, "an open range runs to the end");
    }

    /* Several ranges. */
    {
        Reply r = get(range("bytes=0-1,98-99"));
        const std::string want = std::string("--B\r\nContent-Type: video/mp4\r\nContent-Range: bytes 0-1/100\r\n\r\n") + std::string("\x00\x01", 2) +
                                 "\r\n--B\r\nContent-Type: video/mp4\r\nContent-Range: bytes 98-99/100\r\n\r\n" + std::string("\x62\x63", 2) + "\r\n--B--\r\n";
        check(r.status == 206 && text(r) == want, "several ranges are answered 206 with a multipart/byteranges body of one part each");
        check(r.header("Content-Type") == std::optional<std::string>("multipart/byteranges; boundary=B"), "its Content-Type names the boundary");
        check(!r.header("Content-Range"), "the header section has no Content-Range, each part has its own");
        Reply joined = get(range("bytes=0-9,5-14"));
        check(joined.status == 206 && joined.header("Content-Range") == std::optional<std::string>("bytes 0-14/100") && joined.body.size() == 15, "ranges that join into one are answered as one range");
        Reply order = get(range("bytes=50-51,0-1"));
        check(text(order).find("bytes 50-51/100") < text(order).find("bytes 0-1/100"), "the parts come in the order of the request");
    }

    /* A range that cannot be answered, or is not applicable. */
    {
        Reply r = get(range("bytes=100-200"));
        check(r.status == 416 && r.header("Content-Range") == std::optional<std::string>("bytes */100") && r.body.empty(), "a range beyond the object is answered 416 with the length");
        check(get(range("items=0-5")).status == 200 && get(range("bytes=9-0")).status == 200, "a range that is not understood is ignored");
        Reply empty = get(range("bytes=0-5"), object("\"v1\"", "text/plain", 0));
        check(empty.status == 200 && empty.body.empty(), "an object of zero length is sent whole");
    }

    /* If-Match. */
    {
        Conditions c;
        c.ifMatch = "\"v1\"";
        check(get(c).status == 200, "an If-Match with the entity tag lets the GET through");
        c.ifMatch = "\"other\"";
        Reply r = get(c);
        check(r.status == 412 && r.body.empty(), "an If-Match without it is answered 412 and nothing is sent");
        c.ifMatch = "\"x\", \"v1\"";
        check(get(c).status == 200, "a list is a match when one member matches");
        c.ifMatch = "*";
        check(get(c).status == 200, "If-Match * matches an object that exists");
        c.ifMatch = "W/\"v1\"";
        check(get(c).status == 412, "a weak tag never matches an If-Match, which compares strongly");
        c.ifMatch = "v1";
        check(get(c).status == 200, "a tag written without quotes matches on its characters");
        c.ifMatch = "\"v1\"";
        c.range = "bytes=0-4";
        check(get(c).status == 206, "an If-Match and a Range give the range");
        Conditions none;
        none.ifMatch = "\"v1\"";
        check(get(none, object("")).status == 412, "an object with no entity tag matches no listed tag");
        none.ifMatch = "*";
        check(get(none, object("")).status == 200, "but it matches *");
    }

    /* If-None-Match and If-Modified-Since. */
    {
        Conditions c;
        c.ifNoneMatch = "\"v1\"";
        Reply r = get(c);
        check(r.status == 304 && r.body.empty() && r.header("ETag") == std::optional<std::string>("\"v1\"") && r.header("Last-Modified") == std::optional<std::string>(LM), "an If-None-Match with the entity tag is answered 304 with the validators");
        c.ifNoneMatch = "\"other\"";
        check(get(c).status == 200, "another tag gets the object");
        c.ifNoneMatch = "*";
        check(get(c).status == 304, "If-None-Match * is answered 304 for an object that exists");
        c.ifNoneMatch = "W/\"v1\"";
        check(get(c).status == 304, "a weak tag matches an If-None-Match, which compares weakly");
        c.ifNoneMatch = "\"v1\"";
        c.range = "bytes=0-4";
        check(get(c).status == 304, "the Range is ignored when the answer is 304");

        Conditions m;
        m.ifModifiedSince = LM;
        check(get(m).status == 304, "an If-Modified-Since the modification time is answered 304");
        m.ifModifiedSince = "Wed, 15 Nov 2023 00:00:00 GMT";
        check(get(m).status == 304, "a later date is answered 304");
        m.ifModifiedSince = "Tue, 14 Nov 2023 22:13:19 GMT";
        check(get(m).status == 200, "an earlier date gets the object");
        m.ifModifiedSince = "not a date";
        check(get(m).status == 200, "a date that cannot be read is no condition");
        m.ifModifiedSince = LM;
        m.ifNoneMatch = "\"other\"";
        check(get(m).status == 200, "If-Modified-Since is not looked at when there is an If-None-Match");
    }

    /* If-Range. */
    {
        Conditions c;
        c.range = "bytes=0-4";
        c.ifRange = "\"v1\"";
        check(get(c).status == 206, "an If-Range with the current entity tag gives the range");
        c.ifRange = "\"other\"";
        Reply r = get(c);
        check(r.status == 200 && r.body.size() == 100, "an If-Range with another tag gives the whole object, not a 412");
        c.ifRange = "W/\"v1\"";
        check(get(c).status == 200, "a weak tag in If-Range never matches");
        c.ifRange = LM;
        check(get(c).status == 206, "an If-Range with exactly the modification time gives the range");
        c.ifRange = "Wed, 15 Nov 2023 00:00:00 GMT";
        check(get(c).status == 200, "an If-Range with another date gives the whole object");
        Conditions no_range;
        no_range.ifRange = "\"v1\"";
        check(get(no_range).status == 200, "an If-Range without a Range is ignored");
        c.ifRange = "\"v1\"";
        check(get(c, object("")).status == 200, "an object with no entity tag cannot satisfy an If-Range tag");
    }

    std::printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
