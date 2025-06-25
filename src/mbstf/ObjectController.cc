/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: ObjectController class
 ******************************************************************************
 * Copyright: (C)2025 British Broadcasting Corporation
 * Author(s): David Waring <david.waring2@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include <memory>
#include <list>

#include "common.hh"
#include "Controller.hh"
#include "DistributionSession.hh"
#include "ObjectStore.hh"
#include "ObjectPackager.hh"
#include "PullObjectIngester.hh"
#include "PushObjectIngester.hh"

#include "ObjectController.hh"

MBSTF_NAMESPACE_START

const std::shared_ptr<PullObjectIngester> &ObjectController::addPullObjectIngester(PullObjectIngester *ingester) {
    // Transfer ownership from unique_ptr to shared_ptr
    m_pullIngesters.emplace_back(ingester);
    return m_pullIngesters.back();
}

bool ObjectController::removePullObjectIngester(std::shared_ptr<PullObjectIngester> &pullIngester) {
    auto it = std::find(m_pullIngesters.begin(), m_pullIngesters.end(), pullIngester);
    if (it != m_pullIngesters.end()) {
        m_pullIngesters.erase(it);
        return true;
    }
    return false;
}

const std::shared_ptr<PushObjectIngester> &ObjectController::setPushIngester(PushObjectIngester *pushIngester) {
    m_pushIngester.reset(pushIngester);
    return m_pushIngester;
}

void ObjectController::processEvent(Event &event, SubscriptionService &event_service) {
    if (event.eventName() == "ObjectSendCompleted") {
	ObjectPackager::ObjectSendCompleted &objSendEvent = dynamic_cast<ObjectPackager::ObjectSendCompleted&>(event);
        std::string object_id = objSendEvent.objectId();
        ogs_info("Object [%s] sent", object_id.c_str());

	const ObjectStore::Metadata &metadata = objectStore().getMetadata(object_id);

	if(!metadata.keepAfterSend()) {

	    objectStore().deleteObject(object_id);
	} else {
            ogs_debug("Keeping object [%s] in object store after sending...", object_id.c_str());
	}
    }

}

std::string ObjectController::nextObjectId()
{
    std::ostringstream oss;
    oss << m_nextId;
    m_nextId++;
    return oss.str();
}

const std::shared_ptr<ObjectPackager> &ObjectController::setPackager(ObjectPackager *packager)
{
    m_packager.reset(packager);
    return m_packager;
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
