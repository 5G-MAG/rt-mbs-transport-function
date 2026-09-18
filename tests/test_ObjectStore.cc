/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Testing MBSTF Object store
 ******************************************************************************
 * Copyright: (C)2024 British Broadcasting Corporation
 * License: 5G-MAG Public License v1
 * Author(s): Dev Audsin
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

//#include "ogs-app.h"
//#include "ogs-sbi.h"

#include <memory>
#include <stdexcept>
#include <utility>
#include <chrono>
#include <thread>
#include <mutex>
#include <iostream>
#include <string>
#include <vector>
#include <optional>
#include <map>
#include <list>
#include <atomic>
#include <cstring>
#include <cstdlib>

#include "common.hh"
#include "ObjectStore.hh"
#include "Subscriber.hh"
#include "Event.hh"

MBSTF_NAMESPACE_START
using namespace std::literals;

class ObjectController {};

int pass= 0;
int fail = 0;

static void check(bool condition, const std::string &what)
{
    if (condition) {
        std::cout << "INFO: " << what << " passed." << std::endl;
        pass++;
    } else {
        std::cout << "ERROR: " << what << " failed." << std::endl;
        fail++;
    }
}

std::string firstObject = "obj1";
std::string secondObject = "obj2";

void testAddObject(ObjectStore& store) {
	
    ObjectStore::ObjectData firstObjectData = {0x31, 0x32};
    ObjectStore::ObjectData secondObjectData = {0x50, 0x51, 0x52};
    	
    ObjectStore::Metadata firstObjectMetadata(firstObject, "type1", "url1", "fetched_url1", "acquisition1", std::chrono::system_clock::now());
    ObjectStore::Metadata secondObjectMetadata(secondObject,"type2", "url2", "fetched_url2", "acquisition2", std::chrono::system_clock::now() + std::chrono::minutes(1));

    firstObjectMetadata.entityTag("etag1");
    firstObjectMetadata.cacheExpires(std::chrono::system_clock::now() + 5s);

    secondObjectMetadata.entityTag("etag2");
    secondObjectMetadata.cacheExpires(std::chrono::system_clock::now() + 5s);
    store.addObject(firstObject, std::move(firstObjectData), std::move(firstObjectMetadata));
    store.addObject(secondObject, std::move(secondObjectData), std::move(secondObjectMetadata));
    
    if (store.getObjectData(firstObject) == ObjectStore::ObjectData{0x31, 0x32}) {
	    std::cout<<"INFO: testAddObject for firstObject passed."<<std::endl;
	    pass++;
    } else {
	    std::cout<<"ERROR: testAddObject for firstObject failed."<<std::endl;
	    fail++;
    }

    if (store.getObjectData(secondObject) == ObjectStore::ObjectData{0x50, 0x51, 0x52}) {
        std::cout<<"INFO: testAddObject for secondObject passed."<<std::endl;
	pass++;
    } else {
        std::cout<<"ERROR: testAddObject for secondObject failed."<<std::endl;
	fail++;
    }
}

void testGetMetadata(ObjectStore& store) {
    if (store.getMetadata(firstObject).mediaType() == "type1") {
        std::cout<<"INFO: testGetMetadata for firstObject passed."<<std::endl;
	pass++;
    } else {
        std::cout<<"ERROR: testGetMetadata for firstObject failed."<<std::endl;
	fail++;
    }

    if (store.getMetadata(secondObject).mediaType() == "type2") {
        std::cout<<"INFO: testGetMetadata for secondObject passed."<<std::endl;
	pass++;
    } else {
        std::cout<<"ERROR: testGetMetadata for secondObject failed."<<std::endl;
	fail++;
    }
}

void testDeleteFirstObject(ObjectStore& store) {
    store.deleteObject(firstObject);

    try {
        store.getObjectData(firstObject);
        std::cout<<"ERROR: testDeleteObject for firstObject failed."<<std::endl;
	fail++;
    } catch (const std::out_of_range& e) {
        std::cout<<"INFO: testDeleteObject for firstObject passed."<<std::endl;
	pass++;
    }

}

void testDeleteSecondObject(ObjectStore& store) {
    store.deleteObject(secondObject);

    try {
        store.getObjectData(secondObject);
        std::cout<<"ERROR: testDeleteObject for secondObject failed."<<std::endl;
	fail++;
    } catch (const std::out_of_range& e) {
        std::cout<<"INFO: testDeleteObject for secondObject passed."<<std::endl;
	pass++;
    }

}


void testRemoveObjects(ObjectStore& store) {
    std::list<std::string> objectIds = {firstObject, secondObject};
    bool result = store.removeObjects(objectIds);
    if (result) {
        std::cout<<"INFO: testRemoveObjects for both firstObject and secondObject passed."<<std::endl;
	pass++;
    } else {
        std::cout<<"ERROR: testRemoveObjects failed."<<std::endl;
	fail++;
    }
}

void testGetStaleObjects(ObjectStore& store) {
    auto staleObjects = store.getStale();
    if (staleObjects.find(secondObject) != staleObjects.end()) {
        std::cout<<"INFO: testGetStaleObjects passed."<<std::endl;
	pass++;
    } else {
        std::cout<<"ERROR: testGetStaleObjects failed."<<std::endl;
	fail++;
    }
}

MBSTF_NAMESPACE_STOP
MBSTF_NAMESPACE_USING;
/* TS 26.517 V18.6.0 clause 6.2.3.5 requires the object's latest availability start time and its
   availability end time to be maintained per object in the object list, separately from the HTTP
   cache expiry of the ingest fetch. Check they are held, are independent of cacheExpires(), and
   survive copy and assignment. */
void testAvailabilityTimes() {
    auto now = std::chrono::system_clock::now();
    auto start = now + std::chrono::seconds(30);
    auto end = now + std::chrono::seconds(300);
    auto cache = now + std::chrono::seconds(90);

    ObjectStore::Metadata meta("availObj", "type", "url", "fetched_url", "acquisition", now);

    if (!meta.availabilityStartTime().has_value() && !meta.availabilityEndTime().has_value()) {
        pass++;
        std::cout<<"INFO: testAvailabilityTimes default-absent passed."<<std::endl;
    } else {
        fail++;
        std::cout<<"ERROR: testAvailabilityTimes default-absent failed."<<std::endl;
    }

    meta.availabilityStartTime(start).availabilityEndTime(end);
    meta.cacheExpires(cache);

    if (meta.availabilityStartTime().value() == start && meta.availabilityEndTime().value() == end &&
        meta.cacheExpires().value() == cache && meta.availabilityEndTime().value() != cache) {
        pass++;
        std::cout<<"INFO: testAvailabilityTimes independent of cacheExpires passed."<<std::endl;
    } else {
        fail++;
        std::cout<<"ERROR: testAvailabilityTimes independent of cacheExpires failed."<<std::endl;
    }

    ObjectStore::Metadata copied(meta);
    ObjectStore::Metadata assigned;
    assigned = meta;
    if (copied.availabilityStartTime().value() == start && copied.availabilityEndTime().value() == end &&
        assigned.availabilityStartTime().value() == start && assigned.availabilityEndTime().value() == end &&
        copied == meta) {
        pass++;
        std::cout<<"INFO: testAvailabilityTimes copy and assign passed."<<std::endl;
    } else {
        fail++;
        std::cout<<"ERROR: testAvailabilityTimes copy and assign failed."<<std::endl;
    }
}

/* The entity tag is the HTTP ETag of the ingested object. PullObjectIngester.cc:240 passes it to the
   conditional re-fetch (a lost tag turns an If-None-Match into an unconditional GET, re-downloading
   unchanged segments) and ObjectCarouselPackager.cc:481 copies it into the FLUTE file description.
   Metadata is copied and moved on every path out of the store, so all four must carry it.
   code-derived, no spec claim. */
void testEntityTagSurvivesCopyAndMove() {
    auto now = std::chrono::system_clock::now();
    const std::string etag("\"3f8a-61c0d2\"");

    ObjectStore::Metadata meta("etagObj", "type", "url", "fetched_url", "acquisition", now);
    meta.entityTag(etag);

    ObjectStore::Metadata copied(meta);
    ObjectStore::Metadata moved{ObjectStore::Metadata(meta)};
    ObjectStore::Metadata copy_assigned;
    copy_assigned = meta;
    ObjectStore::Metadata move_assigned;
    move_assigned = ObjectStore::Metadata(meta);

    if (copied.entityTag().value_or(std::string{}) == etag &&
        moved.entityTag().value_or(std::string{}) == etag &&
        copy_assigned.entityTag().value_or(std::string{}) == etag &&
        move_assigned.entityTag().value_or(std::string{}) == etag) {
        pass++;
        std::cout<<"INFO: testEntityTagSurvivesCopyAndMove passed."<<std::endl;
    } else {
        fail++;
        std::cout<<"ERROR: testEntityTagSurvivesCopyAndMove failed: copy=["
                 <<copied.entityTag().value_or(std::string{})<<"] move=["
                 <<moved.entityTag().value_or(std::string{})<<"] copy-assign=["
                 <<copy_assigned.entityTag().value_or(std::string{})<<"] move-assign=["
                 <<move_assigned.entityTag().value_or(std::string{})<<"]"<<std::endl;
    }
}

/* findMetadataByURL() hands out a value, not a window onto the live entry.
 *
 * It used to return a raw pointer into the store, taken without the lock held, and callers copied a
 * Metadata through it. ObjectStore::updateMetadata() move-assigns every std::string of the entry a
 * caller may be reading at that moment, which is the race ObjectStore.hh describes on
 * takeMetadataForIngest(). A returned copy cannot be reached by that writer at all; this pins that it
 * really is a copy, by updating the entry afterwards and checking what the caller holds is unchanged.
 */
static void testFindMetadataByUrlReturnsAnIndependentValue(ObjectStore &store) {
    auto found = store.findMetadataByURL("fetched_url1");
    check(found.has_value(), "findMetadataByURL finds an object by its fetched URL");
    if (!found.has_value()) return;
    check(found->objectId() == firstObject, "the value found carries the object it belongs to");

    check(!store.findMetadataByURL("no-such-url").has_value(),
          "findMetadataByURL yields nothing for a URL no object has");

    ObjectStore::Metadata replacement(firstObject, "type1-changed", "url1-changed", "fetched_url1",
                                      "acquisition1", std::chrono::system_clock::now());
    store.updateMetadata(firstObject, std::move(replacement));

    check(found->getOriginalUrl() == "url1",
          "a value taken before an update is unaffected by it, so it was a copy and not a reference");

    auto after = store.findMetadataByURL("fetched_url1");
    check(after.has_value(), "the object is still findable by its fetched URL after an update");
    check(after.has_value() && after->getOriginalUrl() == "url1-changed",
          "a value taken after the update reflects it");
}


/* A reference handed out by getMetadata() is read with no lock held.
 *
 * getMetadata() takes the store lock under a lock_guard scoped to the function, so the lock is
 * released as it returns and every access through the reference is unsynchronised.
 * updateMetadata() holds the lock and move-assigns the whole entry, every std::string member
 * included. This exercises that pair the way the ingest path does: one thread replacing an entry,
 * another copying it through the reference.
 *
 * Under a normal build this is a no-op that reports how many operations it managed. Its purpose is
 * to give ThreadSanitizer something to report, and to give a torn read somewhere to show up: a
 * std::string whose size() and strlen() disagree has been copied out of two different states of the
 * same object.
 */
static void testConcurrentUpdateAndIngestCopy(ObjectStore &store) {
    const std::string id = firstObject;
    std::atomic<bool> stop{false};
    std::atomic<unsigned> reads{0}, writes{0}, torn{0};

    std::thread writer([&]() {
        unsigned n = 0;
        while (!stop.load(std::memory_order_relaxed)) {
            ObjectStore::Metadata replacement(id, "type", "url" + std::to_string(n),
                                              "fetched_url_long_enough_to_live_on_the_heap_" + std::to_string(n),
                                              "acq", std::chrono::system_clock::now());
            try { store.updateMetadata(id, std::move(replacement)); } catch (const std::exception &) {}
            writes++; n++;
        }
    });

    std::thread reader([&]() {
        while (!stop.load(std::memory_order_relaxed)) {
            try {
                /* The accessor the ingest path now uses. A copy taken under the store lock cannot be
                   reached by the writer, so a torn string here would mean the locking had been
                   undone; that is what the check after this loop asserts.

                   Swapping this for store.getMetadata(id), which returns a reference the store has
                   stopped guarding, makes the same loop report thousands of torn strings and makes
                   ThreadSanitizer report a race on every string member. That accessor now has no
                   callers in src/. */
                auto copy = store.tryGetMetadata(id);
                if (copy) {
                    const std::string &u = copy->getFetchedUrl();
                    if (u.size() != std::strlen(u.c_str())) torn++;
                }
            } catch (const std::exception &) {}
            reads++;
        }
    });

    std::this_thread::sleep_for(2s);
    stop.store(true, std::memory_order_relaxed);
    writer.join();
    reader.join();

    std::cout << "INFO: concurrent update/copy: " << writes.load() << " updates, "
              << reads.load() << " copies" << std::endl;
    check(torn.load() == 0, "a metadata copy taken under the store lock is never torn by a concurrent update");
}

/* A subscriber that takes a lock of its own inside processEvent(), the way
   ObjectManifestController::processEvent() does: it calls manifestHandler(), which takes
   m_manifestHandlerMutex. */
class LockTakingSubscriber : public Subscriber {
public:
    LockTakingSubscriber(std::recursive_mutex &other_lock) : m_otherLock(other_lock), m_ran(0) {};
    virtual ~LockTakingSubscriber() {};

    virtual void processEvent(Event &event, SubscriptionService &event_service) {
        std::lock_guard<std::recursive_mutex> lock(m_otherLock);
        m_ran++;
    };

    unsigned long ran() const { return m_ran.load(); };

private:
    std::recursive_mutex &m_otherLock;
    std::atomic_ulong m_ran;
};

void testSynchronousEventDispatchDoesNotHoldTheStoreLock(ObjectStore& store)
{
    /* The lock-order inversion that stalled the broadcast demo after about 45 seconds of
       media, with the service announcement carousel still running so the session looked
       alive. Two lock orders existed at once:

         - a scheduled-pull worker holds ObjectManifestController::m_manifestHandlerMutex
           while it calls the handler, which reads this store: handler lock, then store lock;
         - an ingest thread calls updateMetadata(), which dispatched the ObjectUpdated event
           to that same controller while still holding the store lock, and the controller took
           the handler lock: store lock, then handler lock.

       Each thread then held what the other waited for.

       The interleaving is forced rather than raced for. Letting two threads loop and hoping
       to collide does not reproduce this: both critical sections are a map lookup long, and
       a version of this test that did so passed against the unfixed store. So the two
       threads hand off explicitly: the reader takes the subscriber's lock and holds it, the
       writer then enters the store, and only once the writer is inside does the reader reach
       for the store. Unfixed, that is the deadlock every time; fixed, the writer is out of
       the store before it needs the subscriber's lock, so both finish. */

    std::recursive_mutex subscriber_lock;
    LockTakingSubscriber subscriber(subscriber_lock);
    store.subscribe({ObjectStore::ObjectUpdatedEvent::event_name}, subscriber);

    std::atomic_bool reader_holds(false), writer_entered(false);
    std::atomic_bool reader_done(false), writer_done(false);

    std::thread reader([&]() {
        std::lock_guard<std::recursive_mutex> lock(subscriber_lock);
        reader_holds.store(true);
        while (!writer_entered.load()) std::this_thread::sleep_for(1ms);
        /* Let the writer get as far as it can: into the store, and up to whatever it does
           next. This is a settling delay for the handoff, not a timing assumption about
           correctness; the outcome is the same for any value that lets the writer run. */
        std::this_thread::sleep_for(250ms);
        try { (void)store.findMetadataByURL("url1"); } catch (const std::exception &) {}
        reader_done.store(true);
    });

    std::thread writer([&]() {
        while (!reader_holds.load()) std::this_thread::sleep_for(1ms);
        writer_entered.store(true);
        ObjectStore::Metadata replacement(firstObject, "type1", "url1", "fetched_url1",
                                          "acquisition1", std::chrono::system_clock::now());
        try {
            store.updateMetadata(firstObject, std::move(replacement), true);
        } catch (const std::exception &) {}
        writer_done.store(true);
    });

    /* Neither thread can be joined while deadlocked, so wait with a deadline instead. The
       handoff takes a quarter of a second by construction; ten is far more than it needs,
       and no amount of waiting recovers a deadlock. */
    const auto deadline = std::chrono::steady_clock::now() + 10s;
    while (std::chrono::steady_clock::now() < deadline &&
           !(reader_done.load() && writer_done.load())) {
        std::this_thread::sleep_for(10ms);
    }

    const bool finished = reader_done.load() && writer_done.load();
    check(finished, "a synchronous event dispatch does not hold the store lock, so a subscriber "
                    "taking its own lock cannot deadlock against a store read");

    if (!finished) {
        std::cout << "ERROR: deadlocked: reader " << (reader_done.load() ? "finished" : "stuck")
                  << ", writer " << (writer_done.load() ? "finished" : "stuck")
                  << ", " << subscriber.ran() << " events delivered. Not joining stuck threads."
                  << std::endl;
        std::cout << "Test: ObjectStore " << "Pass: " << pass << " Fail: " << fail << std::endl;
        std::cout.flush();
        /* Leaving the threads blocked would hang the run at exit and report nothing. */
        std::_Exit(1);
    }

    writer.join();
    reader.join();
    store.unsubscribe(subscriber);

    check(subscriber.ran() == 1, "the synchronous event still reached the subscriber");
}

int main() {
    
    ObjectController objectController;
    std::shared_ptr<ObjectStore> store(new ObjectStore(objectController));

    std::cout<<"### ObjectStore: Test start #### "<<std::endl;
    
    testAddObject(*store);
    testGetMetadata(*store);
    testDeleteFirstObject(*store);
    testDeleteSecondObject(*store);
    testAddObject(*store);
    testRemoveObjects(*store);
    testAddObject(*store);
    std::this_thread::sleep_for(10s);
    testGetStaleObjects(*store);
    testAvailabilityTimes();
    testEntityTagSurvivesCopyAndMove();
    testFindMetadataByUrlReturnsAnIndependentValue(*store);
    testConcurrentUpdateAndIngestCopy(*store);
    testSynchronousEventDispatchDoesNotHoldTheStoreLock(*store);
    std::cout<<"Test: ObjectStore "<<"Pass: "<<pass<<" Fail: "<<fail<<std::endl;
    std::cout<<"### ObjectStore: Test finish #### "<<std::endl;
    store.reset();
    return 0;
}


/* vim:ts=8:sts=4:sw=4:expandtab:
 */
