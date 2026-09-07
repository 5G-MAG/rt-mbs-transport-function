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

#include "common.hh"
#include "ObjectStore.hh"

MBSTF_NAMESPACE_START
using namespace std::literals;

class ObjectController {};

int pass= 0;
int fail = 0;

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
    std::cout<<"Test: ObjectStore "<<"Pass: "<<pass<<" Fail: "<<fail<<std::endl;
    std::cout<<"### ObjectStore: Test finish #### "<<std::endl;
    store.reset();
    return 0;
}


/* vim:ts=8:sts=4:sw=4:expandtab:
 */
