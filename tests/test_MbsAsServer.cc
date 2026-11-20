/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: the HTTP server of the co-located MBS AS, unit test
 ******************************************************************************
 * License: 5G-MAG Public License v1
 ******************************************************************************/

/* Starts the MBS AS server on a loopback port and asks it for objects over real HTTP with libcurl: whole objects, one range, several
 * ranges, the entity tag conditions, HEAD, another method, objects of another session, an unknown object and one whose retention
 * has run out (TS 26.517 V19.2.0 clauses 10.2.2.4 and 10.2.3).
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <curl/curl.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "common.hh"
#include "MbsAsServer.hh"
#include "RepairRegistry.hh"

using namespace com::fiveg_mag::ref_tools::mbstf;
using std::chrono::seconds;

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

struct Answer {
    long status = 0;
    std::map<std::string, std::string> headers;  // names in lower case
    std::string body;
    bool failed = false;
};

static size_t onBody(char *data, size_t size, size_t n, void *out) { static_cast<std::string *>(out)->append(data, size * n); return size * n; }
static size_t onHeader(char *data, size_t size, size_t n, void *out)
{
    std::string line(data, size * n);
    const auto colon = line.find(':');
    if (colon != std::string::npos) {
        std::string name = line.substr(0, colon);
        for (auto &c : name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        std::string value = line.substr(colon + 1);
        while (!value.empty() && (value.front() == ' ')) value.erase(0, 1);
        while (!value.empty() && (value.back() == '\r' || value.back() == '\n')) value.pop_back();
        (*static_cast<std::map<std::string, std::string> *>(out))[name] = value;
    }
    return size * n;
}

/* \param host  as it is written in a URL: an IPv6 address is in square brackets. */
static Answer askAt(const std::string &host, uint16_t port, const std::string &method, const std::string &path, const std::vector<std::string> &headers = {})
{
    Answer a;
    CURL *curl = curl_easy_init();
    const std::string url = "http://" + host + ":" + std::to_string(port) + path;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.c_str());
    if (method == "HEAD") curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    if (method == "POST") curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, onBody);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &a.body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, onHeader);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &a.headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    struct curl_slist *list = nullptr;
    for (const auto &h : headers) list = curl_slist_append(list, h.c_str());
    if (list) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    a.failed = curl_easy_perform(curl) != CURLE_OK;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &a.status);
    curl_slist_free_all(list);
    curl_easy_cleanup(curl);
    return a;
}

static Answer ask(uint16_t port, const std::string &method, const std::string &path, const std::vector<std::string> &headers = {})
{
    return askAt("127.0.0.1", port, method, path, headers);
}

static RepairObjectStore::Object object(unsigned char fill_base, const std::string &etag)
{
    auto data = std::make_shared<RepairObjectStore::Data>(100);
    for (size_t i = 0; i < 100; i++) (*data)[i] = static_cast<unsigned char>(fill_base + i);
    return RepairObjectStore::Object{data, etag, "video/mp4", std::chrono::system_clock::time_point{seconds{1700000000}}};
}

static struct sockaddr_storage loopback(uint16_t port)
{
    struct sockaddr_storage ss{};
    auto *in = reinterpret_cast<struct sockaddr_in *>(&ss);
    in->sin_family = AF_INET;
    in->sin_port = htons(port);
    in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return ss;
}

static struct sockaddr_storage address6(const struct in6_addr &addr, uint16_t port)
{
    struct sockaddr_storage ss{};
    auto *in6 = reinterpret_cast<struct sockaddr_in6 *>(&ss);
    in6->sin6_family = AF_INET6;
    in6->sin6_port = htons(port);
    in6->sin6_addr = addr;
    return ss;
}

static struct sockaddr_storage wildcard(int family, uint16_t port)
{
    if (family == AF_INET6) return address6(in6addr_any, port);
    struct sockaddr_storage ss{};
    auto *in = reinterpret_cast<struct sockaddr_in *>(&ss);
    in->sin_family = AF_INET;
    in->sin_port = htons(port);
    in->sin_addr.s_addr = htonl(INADDR_ANY);
    return ss;
}

/* Whether this machine can bind an IPv6 loopback socket: a case that needs it is reported as skipped, never as passed. */
static bool hasIpv6Loopback()
{
    const int fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) return false;
    struct sockaddr_storage ss = address6(in6addr_loopback, 0);
    const bool ok = bind(fd, reinterpret_cast<struct sockaddr *>(&ss), sizeof(struct sockaddr_in6)) == 0;
    close(fd);
    return ok;
}

int main(int argc, char *argv[])
{
    curl_global_init(CURL_GLOBAL_DEFAULT);
    const auto now = RepairObjectStore::clock_type::now();

    /* The path of a request. */
    {
        std::string id, path;
        check(MbsAsServer::splitUrl("/s1/a/b.bin", id, path) && id == "s1" && path == "/a/b.bin", "a request path is a session identifier and the path of the object");
        check(MbsAsServer::splitUrl("/s1/x", id, path) && path == "/x", "a one segment object path");
        check(!MbsAsServer::splitUrl("/s1", id, path) && !MbsAsServer::splitUrl("/s1/", id, path) && !MbsAsServer::splitUrl("/", id, path) && !MbsAsServer::splitUrl("", id, path), "no identifier or no path after it is no object");
        check(!MbsAsServer::splitUrl("//a", id, path), "an empty identifier is no object");
    }

    auto registry = std::make_shared<RepairRegistry>(seconds(600), 100000);
    registry->put("s1", "/a/b.bin", object(0, "\"v1\""), now);
    registry->put("s2", "/a/b.bin", object(100, "\"w1\""), now);
    registry->put("s1", "/old.bin", object(0, "\"o\""), now - seconds(1000));
    const std::string server_header = "MBSAS-test.example/19 (test)";
    MbsAsServer server(loopback(0), registry, server_header);
    check(server.running() && server.port() != 0, "the server listens on a port the system chose");
    const uint16_t port = server.port();

    /* Whole objects. */
    {
        Answer a = ask(port, "GET", "/s1/a/b.bin");
        check(a.status == 200 && a.body.size() == 100 && static_cast<unsigned char>(a.body[7]) == 7, "a GET gives the whole object");
        check(a.headers["server"] == server_header && a.headers["etag"] == "\"v1\"" && a.headers["accept-ranges"] == "bytes" && a.headers["content-type"] == "video/mp4", "with the Server header, entity tag, Accept-Ranges and media type");
        Answer b = ask(port, "GET", "/s2/a/b.bin");
        check(b.status == 200 && static_cast<unsigned char>(b.body[0]) == 100 && b.headers["etag"] == "\"w1\"", "the same path of another session is another object");
        Answer h = ask(port, "HEAD", "/s1/a/b.bin");
        check(h.status == 200 && h.body.empty() && h.headers["content-length"] == "100", "a HEAD request gives the headers and the length, no body");
    }

    /* What is not there. */
    {
        check(ask(port, "GET", "/s1/missing").status == 404, "an object that is not held is 404");
        check(ask(port, "GET", "/nosuch/a/b.bin").status == 404, "a session that is not held is 404");
        check(ask(port, "GET", "/").status == 404 && ask(port, "GET", "/s1").status == 404, "a path with no object is 404");
        check(ask(port, "GET", "/s1/old.bin").status == 404, "an object whose retention has run out is 404");
        Answer p = ask(port, "POST", "/s1/a/b.bin");
        check(p.status == 405 && p.headers["allow"] == "GET, HEAD" && p.headers["server"] == server_header, "another method is 405 with Allow");
        check(ask(port, "GET", "/missing").headers["server"] == server_header, "a 404 names the server as well");
        check(ask(port, "POST", "/s1/missing").status == 405, "another method is 405 before the object is looked for");
    }

    /* Ranges. */
    {
        Answer one = ask(port, "GET", "/s1/a/b.bin", {"Range: bytes=10-19"});
        check(one.status == 206 && one.body.size() == 10 && static_cast<unsigned char>(one.body[0]) == 10 && one.headers["content-range"] == "bytes 10-19/100", "one range is 206 with its octets and Content-Range");
        Answer many = ask(port, "GET", "/s1/a/b.bin", {"Range: bytes=0-1,98-99"});
        const std::string ctype = many.headers["content-type"];
        const auto eq = ctype.find("boundary=");
        const std::string boundary = eq == std::string::npos ? std::string() : ctype.substr(eq + 9);
        check(many.status == 206 && ctype.starts_with("multipart/byteranges; boundary=mbsas-") && !boundary.empty() && !many.headers.count("content-range"), "several ranges are 206 multipart/byteranges with no Content-Range in the header section");
        check(many.body.find("--" + boundary + "\r\n") == 0 && many.body.find("Content-Range: bytes 0-1/100") != std::string::npos && many.body.find("Content-Range: bytes 98-99/100") != std::string::npos &&
              many.body.rfind("--" + boundary + "--\r\n") == many.body.size() - (boundary.size() + 6), "its body has a part for each range and the closing boundary");
        check(ask(port, "GET", "/s1/a/b.bin", {"Range: bytes=500-600"}).status == 416, "a range beyond the object is 416");
        check(ask(port, "GET", "/s1/a/b.bin", {"Range: bytes=500-600"}).headers["content-range"] == "bytes */100", "with the length in Content-Range");
    }

    /* Entity tag conditions. */
    {
        check(ask(port, "GET", "/s1/a/b.bin", {"If-Match: \"v1\""}).status == 200, "an If-Match with the entity tag is answered");
        Answer fail = ask(port, "GET", "/s1/a/b.bin", {"If-Match: \"nope\""});
        check(fail.status == 412 && fail.body.empty(), "an If-Match without it is 412");
        check(ask(port, "GET", "/s1/a/b.bin", {"If-Match: \"v1\"", "Range: bytes=0-4"}).status == 206, "an If-Match with a Range gives the range");
        check(ask(port, "GET", "/s1/a/b.bin", {"Range: bytes=0-4", "If-Range: \"nope\""}).status == 200, "an If-Range with another tag gives the whole object");
        check(ask(port, "GET", "/s1/a/b.bin", {"Range: bytes=0-4", "If-Range: \"v1\""}).status == 206, "an If-Range with the tag gives the range");
        check(ask(port, "GET", "/s1/a/b.bin", {"If-None-Match: \"v1\""}).status == 304, "an If-None-Match with the tag is 304");
    }

    /* The port is given up when the server is gone, and a second server cannot take a port in use. */
    {
        MbsAsServer second(loopback(port), registry, server_header);
        check(!second.running() && second.port() == 0, "a server cannot listen on a port that is in use");
    }

    /* Objects whose retention has run out are dropped without any request. */
    {
        auto short_lived = std::make_shared<RepairRegistry>(seconds(1), 100000);
        short_lived->put("s", "/x", object(0, "\"x\""), RepairObjectStore::clock_type::now());
        MbsAsServer housekept(loopback(0), short_lived, server_header, seconds(1));
        check(housekept.running() && short_lived->sessionCount() == 1, "an object is held at first");
        for (int i = 0; i < 50 && short_lived->sessionCount() != 0; i++) std::this_thread::sleep_for(std::chrono::milliseconds(100));
        check(short_lived->sessionCount() == 0, "the housekeeping drops it, and its store, once its retention has run out");
    }

    /* Every form of address the configuration accepts: IPv4 and IPv6 loopback, and the wildcard addresses of both families. */
    {
        if (hasIpv6Loopback()) {
            MbsAsServer v6(address6(in6addr_loopback, 0), registry, server_header);
            check(v6.running() && v6.port() != 0, "a server listens on the IPv6 loopback address");
            if (v6.running()) {
                Answer whole = askAt("[::1]", v6.port(), "GET", "/s1/a/b.bin");
                check(whole.status == 200 && whole.body.size() == 100 && whole.headers["server"] == server_header, "and answers a GET sent over IPv6");
                Answer part = askAt("[::1]", v6.port(), "GET", "/s1/a/b.bin", {"Range: bytes=10-19"});
                check(part.status == 206 && part.body.size() == 10 && part.headers["content-range"] == "bytes 10-19/100", "and a Range request sent over IPv6");
            }
            MbsAsServer any6(wildcard(AF_INET6, 0), registry, server_header);
            check(any6.running() && any6.port() != 0, "a server listens on the IPv6 wildcard address");
            if (any6.running()) check(askAt("[::1]", any6.port(), "GET", "/s1/a/b.bin").status == 200, "and answers over the IPv6 loopback address");
        } else {
            std::printf("SKIPPED: the IPv6 cases (this machine has no IPv6 loopback address).\n");
        }
        MbsAsServer any4(wildcard(AF_INET, 0), registry, server_header);
        check(any4.running() && any4.port() != 0, "a server listens on the IPv4 wildcard address");
        if (any4.running()) check(ask(any4.port(), "GET", "/s1/a/b.bin").status == 200, "and answers over the IPv4 loopback address");
    }

    /* Two Distribution Sessions at once: many clients ask for the same path of two sessions while objects of a third are stored and
     * purged. Every answer has to carry the object of the session that was asked for, whatever else the server is doing. */
    {
        auto busy = std::make_shared<RepairRegistry>(seconds(600), 1000000);
        busy->put("a", "/obj.bin", object(0, "\"a1\""), now);
        busy->put("b", "/obj.bin", object(100, "\"b1\""), now);
        MbsAsServer shared(loopback(0), busy, server_header, seconds(1));
        const uint16_t shared_port = shared.port();
        constexpr int kClients = 8, kRequests = 40;
        std::atomic<int> wrong{0}, failed{0}, answered{0};
        std::atomic<bool> stop{false};
        std::vector<std::thread> clients;
        for (int c = 0; c < kClients; c++) {
            clients.emplace_back([&, c]() {
                for (int i = 0; i < kRequests; i++) {
                    const bool first = ((c + i) % 2) == 0;
                    Answer r = ask(shared_port, "GET", first ? "/a/obj.bin" : "/b/obj.bin", {"Range: bytes=0-9"});
                    if (r.failed) { failed++; continue; }
                    const unsigned char want = first ? 0 : 100;
                    if (r.status != 206 || r.body.size() != 10 || static_cast<unsigned char>(r.body[0]) != want || r.headers["etag"] != (first ? "\"a1\"" : "\"b1\"")) wrong++;
                    answered++;
                }
            });
        }
        std::thread writer([&]() {
            int n = 0;
            while (!stop) {
                /* Stored at a time that puts its retention in the past, so that the purge drops it and leaves sessions "a" and "b" alone. */
                busy->put("c", "/obj" + std::to_string(n++ % 5) + ".bin", object(50, "\"c\""), RepairObjectStore::clock_type::now() - seconds(1000));
                busy->purgeExpired(RepairObjectStore::clock_type::now());
                /* The object of session "a" replaced by an identical one while clients read it, as a new version of an object is. */
                busy->put("a", "/obj.bin", object(0, "\"a1\""), RepairObjectStore::clock_type::now());
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        });
        for (auto &t : clients) t.join();
        stop = true;
        writer.join();
        check(failed == 0 && answered == kClients * kRequests, "320 requests for two sessions sent at once are all answered");
        check(wrong == 0, "and each answer carries the object and entity tag of the session that was asked for");
    }

    std::printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
