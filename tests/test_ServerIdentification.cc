/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Server response header of the co-located MBS AS, unit test
 ******************************************************************************
 * License: 5G-MAG Public License v1
 ******************************************************************************/

/* Covers the Server response header of the co-located MBS AS (TS 26.517 V19.2.0 clauses 8.2.3.3.1 and 8.2.3.3.5): the product identifier
 * names the type and the host name, separated by a single hyphen, with the release number as the product version.
 */

#include <limits.h>
#include <unistd.h>

#include <cstdio>
#include <string>

#include "common.hh"
#include "ServerIdentification.hh"

using namespace com::fiveg_mag::ref_tools::mbstf;

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

int main(int argc, char *argv[])
{
    check(serverident::productIdentifier("MBSAS", "vm10240.mno.net") == "MBSAS-vm10240.mno.net/19", "type, one hyphen, host name and release number");
    check(serverident::productIdentifier("MBSAS", "my-host") == "MBSAS-my-host/19", "a hyphen inside the host name is kept; the first hyphen is the separator because the type has none");
    check(serverident::productIdentifier("MBSAS", "a b/c") == "MBSAS-a-b-c/19", "a space or a slash in the host name is written as a hyphen");
    check(serverident::productIdentifier("MBSAS", "host_1") == "MBSAS-host_1/19", "an underscore is a token character");
    check(serverident::productIdentifier("MBSAS", "") == "MBSAS/19", "no host name is invented when none is known");
    check(serverident::headerValue("MBSAS", "h.example", "5G-MAG-MBSTF/1; microhttpd/2") == "MBSAS-h.example/19 (5G-MAG-MBSTF/1; microhttpd/2)", "the product identifier is followed by the comment element");

    char name[HOST_NAME_MAX + 1] = {0};
    const bool have_name = gethostname(name, sizeof(name) - 1) == 0 && name[0] != '\0';
    const std::string local = serverident::localHostName();
    check(have_name == !local.empty(), "the local host name is read exactly when gethostname() succeeds");
    if (have_name) {
        check(local == std::string(name), "the local host name is the one gethostname() reports");
        const std::string id = serverident::productIdentifier("MBSAS", local);
        check(id.starts_with("MBSAS-") && id.ends_with("/19") && id.find(' ') == std::string::npos, "the identifier built from the local host name is one token ending in the release");
    }

    std::printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
