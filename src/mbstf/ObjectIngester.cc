/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Object Ingester base class
 ******************************************************************************
 * Copyright: (C)2025 British Broadcasting Corporation
 * Author(s): Dev Audsin <dev.audsin@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include "common.hh"

#include "ObjectIngester.hh"

MBSTF_NAMESPACE_START

void ObjectIngester::workerLoop(ObjectIngester *ingester)
{
    while(!ingester->m_workerCancel){
       ingester->doObjectIngest();
    }

}

void ObjectIngester::emitObjectIngestFailedEvent(const std::string &url, ObjectIngester::IngestFailedEvent::FailureType fail_type)
{
    sendEventAsynchronous(IngestFailedEvent(url, fail_type));
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
