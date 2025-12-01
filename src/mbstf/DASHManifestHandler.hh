#ifndef _MBS_TF_DASH_MANIFEST_HANDLER_HH_
#define _MBS_TF_DASH_MANIFEST_HANDLER_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: DASH Manifest Handler class
 ******************************************************************************
 * Copyright: (C)2025 British Broadcasting Corporation
 * Author(s): Dev Audsin <dev.audsin@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */
#include <list>
#include <string>
#include <thread>
#include <utility>

#include <libmpd++/libmpd++.hh>

#include "common.hh"
#include "ManifestHandler.hh"
#include "ObjectStore.hh"
#include "PullObjectIngester.hh"

MBSTF_NAMESPACE_START

class DASHManifestHandler : public ManifestHandler {
public:
    DASHManifestHandler() = delete;
    DASHManifestHandler(const ObjectStore::Object &object, ObjectController *controller, bool pull_distribution);
    DASHManifestHandler(const DASHManifestHandler &) = delete;
    DASHManifestHandler(DASHManifestHandler &&) = delete;

    virtual ~DASHManifestHandler();

    DASHManifestHandler &operator=(const DASHManifestHandler &) = delete;
    DASHManifestHandler &operator=(DASHManifestHandler &&) = delete;

    virtual std::pair<ManifestHandler::time_type, ManifestHandler::ingest_list> nextIngestItems();
    virtual ManifestHandler::durn_type getDefaultDeadline();
    virtual bool update(const ObjectStore::Object &new_manifest);
    virtual std::string nextObjectId();
    static unsigned int factoryPriority() { return 100; };

private:
  std::string generateUUID();
  void adjustAvailabilityStartTime();
  void addMPDRefreshToExtraPullObjects();
  void removeExtraPullObjectsEntry(const LIBMPDPP_NAMESPACE_CLASS(SegmentAvailability) &segment);

  std::recursive_mutex m_mpdMutex;
  LIBMPDPP_NAMESPACE_CLASS(MPD)  m_mpd;
  const ObjectStore::Object *m_manifest;
  bool m_refreshMpd;
  ManifestHandler::time_type m_mpdReceivedTime;
  std::list<LIBMPDPP_NAMESPACE_CLASS(SegmentAvailability)> m_extraPullObjects;

};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_DASH_MANIFEST_HANDLER_HH_ */
