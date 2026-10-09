/*****************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: QueuedObjectSet tests
 *****************************************************************************
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "QueuedObjectSet.hh"

MBSTF_NAMESPACE_USING;

static int pass = 0;
static int fail = 0;

static void check(bool ok, const std::string &name)
{
    if (ok) { pass++; std::cout<<"INFO: "<<name<<" passed."<<std::endl; }
    else    { fail++; std::cout<<"ERROR: "<<name<<" failed."<<std::endl; }
}

/* A manifest listing is replayed only for objects not yet handed to the packager. */
static void testNothingIsQueuedAtFirst()
{
    QueuedObjectSet set;
    check(!set.contains("a"), "testNothingIsQueuedAtFirst");
}

static void testAnInsertedObjectIsFound()
{
    QueuedObjectSet set;
    set.insert("a");
    check(set.contains("a") && !set.contains("b"), "testAnInsertedObjectIsFound");
}

static void testInsertingTwiceKeepsOneEntry()
{
    QueuedObjectSet set;
    set.insert("a");
    set.insert("a");
    set.clear();
    check(!set.contains("a"), "testInsertingTwiceKeepsOneEntry");
}

/* A new packager has been sent nothing, so its catch-up must replay every listed object. */
static void testClearForgetsEveryObject()
{
    QueuedObjectSet set;
    set.insert("a");
    set.insert("b");
    set.clear();
    check(!set.contains("a") && !set.contains("b"), "testClearForgetsEveryObject");
}

/* Controller events and the catch-up run on different threads. */
static void testConcurrentInsertsAreAllKept()
{
    QueuedObjectSet set;
    std::vector<std::thread> threads;
    for (int t = 0; t < 4; t++) {
        threads.emplace_back([&set, t]() {
            for (int i = 0; i < 200; i++) set.insert(std::to_string(t) + "-" + std::to_string(i));
        });
    }
    for (auto &th : threads) th.join();
    bool all = true;
    for (int t = 0; t < 4; t++)
        for (int i = 0; i < 200; i++) all = all && set.contains(std::to_string(t) + "-" + std::to_string(i));
    check(all, "testConcurrentInsertsAreAllKept");
}

int main(int argc, char *argv[])
{
    testNothingIsQueuedAtFirst();
    testAnInsertedObjectIsFound();
    testInsertingTwiceKeepsOneEntry();
    testClearForgetsEveryObject();
    testConcurrentInsertsAreAllKept();
    std::cout<<"Test: QueuedObjectSet Pass: "<<pass<<" Fail: "<<fail<<std::endl;
    std::cout<<"### QueuedObjectSet: Test finish #### "<<std::endl;
    return fail == 0 ? 0 : 1;
}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
