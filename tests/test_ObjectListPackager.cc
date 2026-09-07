/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: ObjectListPackager tests
 ******************************************************************************
 * Copyright: (C)2024 British Broadcasting Corporation
 * License: 5G-MAG Public License v1
 * Author(s): Dev Audsin
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

/* Covers the transmission ordering the segment streaming operating mode requires.
 *
 * TS 26.517 V18.6.0 clause 6.2.3.5: "The MBSTF shall transmit each object in the object list such
 * that the last packet of the delivered FLUTE transmission object (including any FEC recovery
 * packets, when configured) is available at the MBSTF Client no later than its availability start
 * time."
 *
 * The packaging queue is ordered by each item's deadline, which for OBJECT_STREAMING is that
 * availability start time. Only the ordering is exercised here: constructing an ObjectListPackager
 * brings up a FLUTE transmitter and its sockets, which is not a unit test, so the predicate is
 * tested directly.
 */

#include <chrono>
#include <iostream>
#include <list>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "ObjectStore.hh"
#include "ObjectListPackager.hh"

MBSTF_NAMESPACE_START
using namespace std::literals;

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

using time_type = ObjectListPackager::time_type;

static std::shared_ptr<ObjectStore::Object> makeObject(const std::string &object_id)
{
    ObjectStore::ObjectData data = {0x31, 0x32};
    ObjectStore::Metadata metadata(object_id, "application/octet-stream", "url-" + object_id,
                                   "fetched-" + object_id, "acquisition-" + object_id,
                                   std::chrono::system_clock::now());
    return std::make_shared<ObjectStore::Object>(std::move(data), std::move(metadata));
}

/* An object whose availability start time is earlier must be transmitted first. */
static void testEarlierDeadlineSortsFirst()
{
    auto now = std::chrono::system_clock::now();
    ObjectListPackager::PackageItem early(makeObject("early"), time_type(now + 10s));
    ObjectListPackager::PackageItem late(makeObject("late"), time_type(now + 60s));

    check(ObjectListPackager::PackageItem::earlierDeadlineFirst(early, late),
          "testEarlierDeadlineSortsFirst early before late");
    check(!ObjectListPackager::PackageItem::earlierDeadlineFirst(late, early),
          "testEarlierDeadlineSortsFirst late not before early");
}

/* An object with no known availability start time must not displace one that has a stated time. */
static void testItemWithoutDeadlineSortsLast()
{
    auto now = std::chrono::system_clock::now();
    ObjectListPackager::PackageItem dated(makeObject("dated"), time_type(now + 30s));
    ObjectListPackager::PackageItem undated(makeObject("undated"));

    check(ObjectListPackager::PackageItem::earlierDeadlineFirst(dated, undated),
          "testItemWithoutDeadlineSortsLast dated before undated");
    check(!ObjectListPackager::PackageItem::earlierDeadlineFirst(undated, dated),
          "testItemWithoutDeadlineSortsLast undated not before dated");
    check(!ObjectListPackager::PackageItem::earlierDeadlineFirst(undated, undated),
          "testItemWithoutDeadlineSortsLast undated not before itself");
}

/* The whole queue, sorted, must come out in availability start time order with the undated last.
 * This is the property the clause actually depends on, rather than any single comparison. */
static void testQueueSortsIntoAvailabilityOrder()
{
    auto now = std::chrono::system_clock::now();
    std::list<ObjectListPackager::PackageItem> queue;
    queue.emplace_back(makeObject("third"), time_type(now + 90s));
    queue.emplace_back(makeObject("undated"));
    queue.emplace_back(makeObject("first"), time_type(now + 10s));
    queue.emplace_back(makeObject("second"), time_type(now + 50s));

    queue.sort(ObjectListPackager::PackageItem::earlierDeadlineFirst);

    std::vector<std::string> order;
    for (auto &item : queue) {
        order.push_back(item.object()->second.objectId());
    }

    check(order.size() == 4 && order[0] == "first" && order[1] == "second" &&
          order[2] == "third" && order[3] == "undated",
          "testQueueSortsIntoAvailabilityOrder");
    if (fail) {
        std::cout << "       order was:";
        for (const auto &id : order) std::cout << " " << id;
        std::cout << std::endl;
    }
}

/* An object already past its availability start time must still sort ahead of later ones, so a
 * late arrival is sent next rather than being starved by objects due further out. */
static void testOverdueObjectSortsFirst()
{
    auto now = std::chrono::system_clock::now();
    ObjectListPackager::PackageItem overdue(makeObject("overdue"), time_type(now - 30s));
    ObjectListPackager::PackageItem upcoming(makeObject("upcoming"), time_type(now + 30s));

    check(ObjectListPackager::PackageItem::earlierDeadlineFirst(overdue, upcoming),
          "testOverdueObjectSortsFirst");
}

MBSTF_NAMESPACE_STOP

MBSTF_NAMESPACE_USING;

int main()
{
    std::cout << "### ObjectListPackager: Test start ####" << std::endl;

    testEarlierDeadlineSortsFirst();
    testItemWithoutDeadlineSortsLast();
    testQueueSortsIntoAvailabilityOrder();
    testOverdueObjectSortsFirst();

    std::cout << "Test: ObjectListPackager Pass: " << pass << " Fail: " << fail << std::endl;
    std::cout << "### ObjectListPackager: Test finish ####" << std::endl;
    return fail ? 1 : 0;
}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
