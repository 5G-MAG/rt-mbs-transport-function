/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: HTTP byte range evaluation unit test
 ******************************************************************************
 * License: 5G-MAG Public License v1
 ******************************************************************************/

/* Covers rangereq::evaluate(): which byte ranges the co-located MBS AS answers for a Range header field. The MBSTF Client sends
 * "a HTTP partial GET request" with several byte ranges when it repairs an object (TS 26.517 V19.2.0 clause 10.2.2.4), and the
 * answer follows RFC 9110 clauses 14.1.2, 14.2 and 15.3.7.2.
 */

#include <cstdio>
#include <string>
#include <vector>

#include "common.hh"
#include "RangeRequest.hh"

using namespace com::fiveg_mag::ref_tools::mbstf;
using rangereq::ByteRange;
using rangereq::Outcome;
using R = std::vector<ByteRange>;

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

static bool partial(const std::string &value, uint64_t length, const R &want)
{
    const auto e = rangereq::evaluate(value, length);
    return e.outcome == Outcome::Partial && e.ranges == want;
}

static bool outcomeIs(const std::string &value, uint64_t length, Outcome want)
{
    const auto e = rangereq::evaluate(value, length);
    return e.outcome == want && e.ranges.empty();
}

int main(int argc, char *argv[])
{
    /* The examples of RFC 9110 clause 14.1.2 for a representation of length 10000. */
    check(partial("bytes=0-499", 10000, {{0, 499}}), "the first 500 bytes");
    check(partial("bytes=500-999", 10000, {{500, 999}}), "the second 500 bytes");
    check(partial("bytes=-500", 10000, {{9500, 9999}}), "the final 500 bytes as a suffix range");
    check(partial("bytes=9500-", 10000, {{9500, 9999}}), "the final 500 bytes as an open range");
    check(partial("bytes=0-0,-1", 10000, {{0, 0}, {9999, 9999}}), "the first and the last byte");
    check(partial("bytes= 0-999, 4500-5499, -1000", 10000, {{0, 999}, {4500, 5499}, {9000, 9999}}), "the first, middle and last 1000 bytes, with spaces");

    /* The ends are cut to the representation. */
    check(partial("bytes=900-5000", 1000, {{900, 999}}), "a last-pos beyond the length is cut to the last byte");
    check(partial("bytes=-5000", 1000, {{0, 999}}), "a suffix longer than the representation is the whole of it");
    check(partial("bytes=0-", 1, {{0, 0}}), "a one byte representation");

    /* Ranges that cannot be answered. */
    check(outcomeIs("bytes=1000-1999", 1000, Outcome::NotSatisfiable), "a first-pos at the length is not satisfiable");
    check(outcomeIs("bytes=-0", 1000, Outcome::NotSatisfiable), "a suffix of zero is not satisfiable");
    check(partial("bytes=1000-1999,0-9", 1000, {{0, 9}}), "an unsatisfiable range is dropped when another can be answered");
    check(outcomeIs("bytes=99999999999999999999999-", 1000, Outcome::NotSatisfiable), "a first-pos too large for 64 bits is not satisfiable, not an error");
    check(partial("bytes=0-99999999999999999999999", 1000, {{0, 999}}), "a last-pos too large for 64 bits is cut to the last byte");

    /* Ranges that are ignored: the whole representation is sent. */
    check(outcomeIs("items=0-5", 1000, Outcome::Whole), "a range unit that is not bytes is ignored");
    check(partial("BYTES=0-9", 1000, {{0, 9}}), "the unit name is not case sensitive");
    check(outcomeIs("bytes=9-0", 1000, Outcome::Whole), "a last-pos below the first-pos is ignored");
    check(outcomeIs("bytes=abc", 1000, Outcome::Whole), "a range that is not numbers is ignored");
    check(outcomeIs("bytes=1-2-3", 1000, Outcome::Whole), "a range with a second hyphen is ignored");
    check(outcomeIs("bytes=0-9x", 1000, Outcome::Whole), "a trailing character is ignored as invalid");
    check(outcomeIs("bytes=", 1000, Outcome::Whole), "no range at all is ignored");
    check(outcomeIs("bytes=,", 1000, Outcome::Whole), "only empty list elements is ignored");
    check(outcomeIs("0-9", 1000, Outcome::Whole), "no unit is ignored");
    check(outcomeIs("bytes=0-9", 0, Outcome::Whole), "a representation of zero length is sent whole");
    check(outcomeIs("bytes=99999999999999999999999x-", 1000, Outcome::Whole), "digits too large for 64 bits followed by a letter are invalid");

    /* Overlapping and adjacent ranges are joined, so the answer is never larger than the representation. */
    check(partial("bytes=500-600,601-999", 10000, {{500, 999}}), "adjacent ranges are joined");
    check(partial("bytes=500-700,601-999", 10000, {{500, 999}}), "overlapping ranges are joined");
    check(partial("bytes=0-9,0-9,0-9,0-9", 100, {{0, 9}}), "the same range repeated is one range");
    check(partial("bytes=0-99,10-20", 100, {{0, 99}}), "a range inside another is absorbed");
    check(partial("bytes=0-9,20-29,10-19", 100, {{0, 29}}), "a range that bridges two others joins all three");
    check(partial("bytes=20-29,0-9,5-24", 100, {{0, 29}}), "a chain of overlaps joins into one range");
    check(partial("bytes=50-59,0-9,55-70", 100, {{50, 70}, {0, 9}}), "the request order is kept, a joined range at the place of its earliest member");
    check(partial("bytes=0-9,12-19", 100, {{0, 9}, {12, 19}}), "ranges with a gap stay separate");

    /* The size of an answer is bounded by the representation whatever the request lists. */
    std::string many = "bytes=";
    for (int i = 0; i < 500; i++) many += "0-999,";
    const auto e = rangereq::evaluate(many, 1000);
    uint64_t total = 0;
    for (const auto &r : e.ranges) total += r.last - r.first + 1;
    check(e.outcome == Outcome::Partial && total == 1000, "five hundred copies of the same range answer the representation once");

    std::printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
