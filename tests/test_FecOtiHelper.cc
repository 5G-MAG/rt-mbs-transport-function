/*****************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: FecOtiHelper tests
 *****************************************************************************
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

#include "FecOtiHelper.hh"
#include "openapi/model/FECConfig.h"

MBSTF_NAMESPACE_USING;

static int pass = 0;
static int fail = 0;

static void check(bool ok, const std::string &name)
{
    if (ok) { pass++; std::cout<<"INFO: "<<name<<" passed."<<std::endl; }
    else    { fail++; std::cout<<"ERROR: "<<name<<" failed."<<std::endl; }
}

static std::optional<std::shared_ptr<reftools::mbstf::FECConfig>> makeConfig(const std::string &scheme, int32_t overhead)
{
    auto cfg = std::make_shared<reftools::mbstf::FECConfig>();
    cfg->setFecScheme(scheme);
    cfg->setFecOverHead(overhead);
    return std::optional<std::shared_ptr<reftools::mbstf::FECConfig>>(cfg);
}

/* A session that asked for no FEC must produce no FEC OTI, so the Transmitter keeps its own
   default behaviour rather than being handed an empty-but-present configuration. */
static void testAbsentConfig()
{
    auto [oti, redundancy] = fecOtiFromFecConfig(std::nullopt);
    check(!oti.has_value() && redundancy == LibFlute::kDefaultFecRedundancyLevel,
          "testAbsentConfig");

    std::optional<std::shared_ptr<reftools::mbstf::FECConfig>> null_ptr_config(nullptr);
    auto [oti2, redundancy2] = fecOtiFromFecConfig(null_ptr_config);
    check(!oti2.has_value() && redundancy2 == LibFlute::kDefaultFecRedundancyLevel,
          "testAbsentConfig null shared_ptr");
}

/* Compact No-Code carries no repair symbols, so it has the same observable effect as no FEC and
   must not be turned into a FEC OTI the Transmitter would act on. */
static void testCompactNoCode()
{
    auto [oti, redundancy] = fecOtiFromFecConfig(makeConfig("urn:ietf:rmt:fec:encoding:0", 20));
    check(!oti.has_value(), "testCompactNoCode yields no FEC OTI");
    (void)redundancy;
}

/* Raptor is the one repair scheme this MBSTF wires. The requested overhead becomes the
   Transmitter's redundancy level; the symbol geometry is left for rt-libflute to derive. */
static void testRaptor()
{
    auto [oti, redundancy] = fecOtiFromFecConfig(makeConfig("urn:ietf:rmt:fec:encoding:1", 25));
    check(oti.has_value() && oti->encoding_id == LibFlute::FecScheme::Raptor,
          "testRaptor yields a Raptor FEC OTI");
    check(redundancy == 25u, "testRaptor carries the requested overhead as the redundancy level");
}

/* TS 26.346 V18.2.0 clause L.4.7 admits only Compact No-Code and Raptor into the MBMS Download
   Profile, which TS 26.517 V18.6.0 clause 6.2.1 requires this session to conform to. RaptorQ
   (RFC 6330) is not admitted, so it must be refused rather than silently downgraded to no FEC:
   a session sent unprotected when it asked for protection is a worse outcome than a failure. */
static void testRaptorQRefused()
{
    bool threw = false;
    try { fecOtiFromFecConfig(makeConfig("urn:ietf:rmt:fec:encoding:6", 20)); }
    catch (const std::runtime_error &) { threw = true; }
    check(threw, "testRaptorQRefused");
}

static void testUnknownSchemeRefused()
{
    bool threw = false;
    try { fecOtiFromFecConfig(makeConfig("urn:example:not-a-fec-scheme", 20)); }
    catch (const std::runtime_error &) { threw = true; }
    check(threw, "testUnknownSchemeRefused");
}

/* A negative overhead cannot be turned into an unsigned redundancy level without wrapping to an
   enormous value, so it is rejected at the boundary rather than converted. */
static void testNegativeOverheadRefused()
{
    bool threw = false;
    try { fecOtiFromFecConfig(makeConfig("urn:ietf:rmt:fec:encoding:1", -1)); }
    catch (const std::runtime_error &) { threw = true; }
    check(threw, "testNegativeOverheadRefused");
}

int main()
{
    std::cout<<"### FecOtiHelper: Test start #### "<<std::endl;
    testAbsentConfig();
    testCompactNoCode();
    testRaptor();
    testRaptorQRefused();
    testUnknownSchemeRefused();
    testNegativeOverheadRefused();
    std::cout<<"Test: FecOtiHelper Pass: "<<pass<<" Fail: "<<fail<<std::endl;
    std::cout<<"### FecOtiHelper: Test finish #### "<<std::endl;
    return fail == 0 ? 0 : 1;
}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
