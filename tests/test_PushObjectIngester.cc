/*****************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Push ingest path routing test
 *****************************************************************************
 * Copyright: (C)2026 British Broadcasting Corporation
 * License: 5G-MAG Public License v1
 *
 * Licensed under the License terms and conditions for use, reproduction, and
 * distribution of 5G-MAG software (the "License").  You may not use this file
 * except in compliance with the License.  You may obtain a copy of the License
 * at https://www.5g-mag.com/reference-tools.  Unless required by applicable
 * law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Covers PushObjectIngester::splitSharedPath(), which decides, for an object push arriving on the
 * shared port, which ingest session it belongs to and what the object path within that session is.
 *
 * This is the routing that lets one published port serve every ingest session
 * (5G-MAG/rt-mbs-transport-function#27). Getting it wrong sends a push to the wrong session or
 * refuses a valid one, and the discriminator is generated rather than chosen, so the cases below are
 * about the shape of the path and not about any particular identifier.
 */

#include <format>

#include "PushObjectIngester.hh"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace com::fiveg_mag::ref_tools::mbstf;

static int g_pass = 0;
static int g_fail = 0;

static void check(bool ok, const char *what)
{
    if (ok) { g_pass++; printf("INFO: %s passed.\n", what); }
    else    { g_fail++; printf("FAIL: %s\n", what); }
}

/* Convenience: run the split and report all three results together. */
static bool split(const char *url, std::string &seg, std::string &obj)
{
    seg.clear();
    obj.clear();
    return PushObjectIngester::splitSharedPath(url, seg, obj);
}

int main(void)
{
    std::string seg, obj;

    /* The ordinary case: a discriminator then the object being pushed. */
    check(split("/9f8e/segment-1.m4s", seg, obj) && seg == "9f8e" && obj == "/segment-1.m4s",
          "a discriminator and an object name split into the two");

    /* Nested object paths belong to the session whole, so only the first segment is taken. */
    check(split("/9f8e/video/1/init.mp4", seg, obj) && seg == "9f8e" && obj == "/video/1/init.mp4",
          "only the first segment is the discriminator");

    /* A push to the session root: there is no object path, so it is "/" rather than empty, which is
       what the ingester would have seen on a port of its own. */
    check(split("/9f8e", seg, obj) && seg == "9f8e" && obj == "/",
          "a bare discriminator addresses the session root");
    check(split("/9f8e/", seg, obj) && seg == "9f8e" && obj == "/",
          "a trailing slash addresses the session root");

    /* A real UUID, since that is what is generated. */
    check(split("/3f2504e0-4f89-11d3-9a0c-0305e82c3301/a.mp4", seg, obj) &&
          seg == "3f2504e0-4f89-11d3-9a0c-0305e82c3301" && obj == "/a.mp4",
          "a generated UUID discriminator is taken whole");

    /* Nothing to route on. Each of these has to be refused rather than guessed at, because a wrong
       guess would hand the push to whichever session happened to match. */
    check(!split("/", seg, obj), "a bare slash routes to nothing");
    check(!split("//segment.m4s", seg, obj), "an empty discriminator routes to nothing");
    check(!split("", seg, obj), "an empty path routes to nothing");
    check(!split(nullptr, seg, obj), "a null path routes to nothing");
    check(!split("9f8e/segment.m4s", seg, obj), "a path with no leading slash routes to nothing");

    /* Query strings and dots are part of the object path, not of the discriminator. */
    check(split("/9f8e/seg.m4s?x=1", seg, obj) && seg == "9f8e" && obj == "/seg.m4s?x=1",
          "a query string stays with the object path");

    printf("Test: PushObjectIngester Pass: %d Fail: %d\n", g_pass, g_fail);
    return g_fail == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
