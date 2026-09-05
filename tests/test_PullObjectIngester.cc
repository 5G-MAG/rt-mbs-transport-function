/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: PullObjectIngester tests
 ******************************************************************************
 * Copyright: (C)2024 British Broadcasting Corporation
 * License: 5G-MAG Public License v1
 * Author(s): Dev Audsin
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

/* Covers what an ingest item carries into the object list.
 *
 * TS 26.517 V18.6.0 clause 6.2.3.5 requires, for each object of an object flow, that the MBSTF
 * maintain in an object list "The URL used by the MBS-Aware Application to request the object,
 * derived from the object ingest URL", "The object's latest availability start time at the MBS
 * Client" and "The object's availability end time from the MBSTF Client".
 *
 * The availability times are distinct from the download deadline, which governs when the object is
 * pulled from its origin rather than when a client may request it. They were previously conflated:
 * the DASH availability end time was passed into the deadline parameter and no availability time was
 * retained at all. These tests hold them apart.
 *
 * Only the carriage of those values is exercised. Fetching needs an origin server and a running
 * event loop, which is not a unit test.
 */

#include <chrono>
#include <iostream>
#include <optional>
#include <string>

#include "common.hh"
#include "ObjectStore.hh"
#include "PullObjectIngester.hh"

MBSTF_NAMESPACE_START
using namespace std::literals;

class ObjectController {};

int pass = 0;
int fail = 0;

static void check(bool condition, const std::string &what)
{
    if (condition) {
        pass++;
        std::cout << "INFO: " << what << " passed." << std::endl;
    } else {
        fail++;
        std::cout << "ERROR: " << what << " failed." << std::endl;
    }
}

using time_type = PullObjectIngester::time_type;

/* The base URLs are what the distribution URL is derived from, per the first item of the object
 * list in clause 6.2.3.5. Both must survive into the ingest item. */
static void testCarriesBothBaseUrls()
{
    PullObjectIngester::IngestItem item("obj1", "http://127.0.0.1/seg1.m4s", "acq1",
                                        std::string("http://127.0.0.1/"),
                                        std::string("http://127.0.0.2/"));

    check(item.objectId() == "obj1", "testCarriesBothBaseUrls objectId");
    check(item.url() == "http://127.0.0.1/seg1.m4s", "testCarriesBothBaseUrls url");
    check(item.acquisitionId() == "acq1", "testCarriesBothBaseUrls acquisitionId");
    check(item.objIngestBaseUrl().has_value() &&
          item.objIngestBaseUrl().value() == "http://127.0.0.1/",
          "testCarriesBothBaseUrls objIngestBaseUrl");
    check(item.objDistributionBaseUrl().has_value() &&
          item.objDistributionBaseUrl().value() == "http://127.0.0.2/",
          "testCarriesBothBaseUrls objDistributionBaseUrl");
}

/* An item with no times stated must report none, rather than defaulting to something a caller would
 * mistake for a real availability window. */
static void testTimesAbsentByDefault()
{
    PullObjectIngester::IngestItem item("obj2", "http://127.0.0.1/seg2.m4s", "acq2");

    check(!item.hasDeadline(), "testTimesAbsentByDefault no deadline");
    check(!item.availabilityStartTime().has_value(), "testTimesAbsentByDefault no availability start");
    check(!item.availabilityEndTime().has_value(), "testTimesAbsentByDefault no availability end");
}

/* The three times are independent. The deadline governs the pull from origin; the availability times
 * govern when a client may request the object. Conflating them is the defect these guard against. */
static void testAvailabilityTimesIndependentOfDeadline()
{
    auto now = std::chrono::system_clock::now();
    time_type deadline(now + 10s);
    time_type avail_start(now + 30s);
    time_type avail_end(now + 300s);

    PullObjectIngester::IngestItem item("obj3", "http://127.0.0.1/seg3.m4s", "acq3",
                                        std::string("http://127.0.0.1/"),
                                        std::string("http://127.0.0.2/"),
                                        deadline, false, false, false, avail_start, avail_end);

    check(item.hasDeadline() && item.deadline().value() == deadline,
          "testAvailabilityTimesIndependentOfDeadline deadline");
    check(item.availabilityStartTime().has_value() && item.availabilityStartTime().value() == avail_start,
          "testAvailabilityTimesIndependentOfDeadline availability start");
    check(item.availabilityEndTime().has_value() && item.availabilityEndTime().value() == avail_end,
          "testAvailabilityTimesIndependentOfDeadline availability end");

    check(item.deadline().value() != item.availabilityStartTime().value() &&
          item.availabilityStartTime().value() != item.availabilityEndTime().value(),
          "testAvailabilityTimesIndependentOfDeadline all three differ");

    /* Availability start no later than availability end, the ordering clause 6.2.3.5 implies by
       deriving one from a distribution offset and the other from a clean-up time. */
    check(item.availabilityStartTime().value() < item.availabilityEndTime().value(),
          "testAvailabilityTimesIndependentOfDeadline start precedes end");
}

/* The setters must be usable after construction, which is how DASHManifestHandler attaches the times
 * to an item built from existing object metadata. */
static void testTimesSettableAfterConstruction()
{
    auto now = std::chrono::system_clock::now();
    time_type avail_start(now + 45s);
    time_type avail_end(now + 450s);

    PullObjectIngester::IngestItem item("obj4", "http://127.0.0.1/seg4.m4s", "acq4");
    item.availabilityStartTime(avail_start).availabilityEndTime(avail_end);

    check(item.availabilityStartTime().has_value() && item.availabilityStartTime().value() == avail_start,
          "testTimesSettableAfterConstruction availability start");
    check(item.availabilityEndTime().has_value() && item.availabilityEndTime().value() == avail_end,
          "testTimesSettableAfterConstruction availability end");
    check(!item.hasDeadline(), "testTimesSettableAfterConstruction deadline untouched");
}

/* Copying must carry every value: items are copied into and out of the ingest list. */
static void testCopyPreservesEverything()
{
    auto now = std::chrono::system_clock::now();
    PullObjectIngester::IngestItem original("obj5", "http://127.0.0.1/seg5.m4s", "acq5",
                                            std::string("http://127.0.0.1/"),
                                            std::string("http://127.0.0.2/"),
                                            time_type(now + 5s), false, false, false,
                                            time_type(now + 25s), time_type(now + 250s));
    PullObjectIngester::IngestItem copied(original);

    check(copied.objectId() == original.objectId() && copied.url() == original.url() &&
          copied.acquisitionId() == original.acquisitionId(),
          "testCopyPreservesEverything identifiers");
    check(copied.objIngestBaseUrl() == original.objIngestBaseUrl() &&
          copied.objDistributionBaseUrl() == original.objDistributionBaseUrl(),
          "testCopyPreservesEverything base URLs");
    check(copied.deadline() == original.deadline() &&
          copied.availabilityStartTime() == original.availabilityStartTime() &&
          copied.availabilityEndTime() == original.availabilityEndTime(),
          "testCopyPreservesEverything times");
}

MBSTF_NAMESPACE_STOP

MBSTF_NAMESPACE_USING;

int main()
{
    std::cout << "### PullObjectIngester: Test start ####" << std::endl;

    testCarriesBothBaseUrls();
    testTimesAbsentByDefault();
    testAvailabilityTimesIndependentOfDeadline();
    testTimesSettableAfterConstruction();
    testCopyPreservesEverything();

    std::cout << "Test: PullObjectIngester Pass: " << pass << " Fail: " << fail << std::endl;
    std::cout << "### PullObjectIngester: Test finish ####" << std::endl;
    return fail ? 1 : 0;
}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
