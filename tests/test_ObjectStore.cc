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
    std::cout<<"Test: ObjectStore "<<"Pass: "<<pass<<" Fail: "<<fail<<std::endl;
    std::cout<<"### ObjectStore: Test finish #### "<<std::endl;
    store.reset();
    return 0;
}


/* vim:ts=8:sts=4:sw=4:expandtab:
 */
