#ifndef _MBS_TF_DASH_MANIFEST_HANDLER_HH_
#define _MBS_TF_DASH_MANIFEST_HANDLER_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: DASH Manifest Handler class
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
#include "Open5GSYamlIter.hh"
#include "PullObjectIngester.hh"

MBSTF_NAMESPACE_START

class DASHManifestHandler : public ManifestHandler {
public:
    DASHManifestHandler() = delete;
    DASHManifestHandler(const std::shared_ptr<ObjectStore::Object> &object, ObjectController *controller, bool pull_distribution);
    DASHManifestHandler(const DASHManifestHandler &) = delete;
    DASHManifestHandler(DASHManifestHandler &&) = delete;

    virtual ~DASHManifestHandler();

    DASHManifestHandler &operator=(const DASHManifestHandler &) = delete;
    DASHManifestHandler &operator=(DASHManifestHandler &&) = delete;

    virtual std::pair<ManifestHandler::time_type, ManifestHandler::ingest_list> nextIngestItems();
    virtual ManifestHandler::durn_type getDefaultDeadline();
    virtual bool update(const std::shared_ptr<ObjectStore::Object> &new_manifest);
    virtual std::string nextObjectId();
    virtual bool compressManifestOnSend() const;

    static unsigned int factoryPriority() { return 100; };
    static bool parseConfiguration(const std::string &section_name, Open5GSYamlIter &iter);
    static void tidyConfiguration();

private:
    class SegmentEntry : public LIBMPDPP_NAMESPACE_CLASS(SegmentAvailability) {
    public:
        SegmentEntry();
        SegmentEntry(const SegmentEntry &other);
        SegmentEntry(SegmentEntry &&other);
        SegmentEntry(const LIBMPDPP_NAMESPACE_CLASS(SegmentAvailability) &seg_avail, bool force_recache, bool keep_after_send,
                     bool compress_entry);
        SegmentEntry(LIBMPDPP_NAMESPACE_CLASS(SegmentAvailability) &&seg_avail, bool force_recache, bool keep_after_send,
                     bool compress_entry);
        SegmentEntry(const LIBMPDPP_NAMESPACE_CLASS(SegmentAvailability::time_type) &availability_start,
                     const LIBMPDPP_NAMESPACE_CLASS(SegmentAvailability::duration_type) &segment_length,
                     const LIBMPDPP_NAMESPACE_CLASS(URI) &segment_url,
                     const std::optional<LIBMPDPP_NAMESPACE_CLASS(SegmentAvailability::time_type)> &availability_end = std::nullopt,
                     bool force_recache = false, bool keep_after_send = false, bool compress_entry = false);

        virtual ~SegmentEntry() {};

        SegmentEntry &operator=(const SegmentEntry &other);
        SegmentEntry &operator=(SegmentEntry &&other);

        bool forceRecache() const { return m_forceRecache; };
        SegmentEntry &forceRecache(bool force_recache) { m_forceRecache = force_recache; return *this; };

        bool keepAfterSend() const { return m_keepAfterSend; };
        SegmentEntry &keepAfterSend(bool keep_after_send) { m_keepAfterSend = keep_after_send; return *this; };

        bool compressEntry() const { return m_compressFile; };
        SegmentEntry &compressEntry(bool compress_file) { m_compressFile = compress_file; return *this; };

    private:
        bool m_forceRecache;
        bool m_keepAfterSend;
        bool m_compressFile;
    };

    std::string generateUUID();
    void addMPDRefreshToExtraPullObjects();
    void removeExtraPullObjectsEntry(const SegmentEntry &segment);
    std::list<SegmentEntry> augmentSegmentAvailabilityList(std::list<LIBMPDPP_NAMESPACE_CLASS(SegmentAvailability)> &&segments, bool force_recache = false, bool keep_after_send = false, bool compress_entry = false);

    std::recursive_mutex m_mpdMutex;
    LIBMPDPP_NAMESPACE_CLASS(MPD)  m_mpd;
    std::shared_ptr<ObjectStore::Object> m_manifest;
    bool m_refreshMpd;
    ManifestHandler::time_type m_mpdReceivedTime;
    std::list<SegmentEntry> m_extraPullObjects;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_DASH_MANIFEST_HANDLER_HH_ */
