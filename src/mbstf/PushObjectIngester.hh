#ifndef _MBS_TF_PUSH_OBJECT_INGESTER_HH_
#define _MBS_TF_PUSH_OBJECT_INGESTER_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Push Object Ingester class
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
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <microhttpd.h>

#include "common.hh"
#include "ObjectIngester.hh"
#include "SubscriptionService.hh"

MBSTF_NAMESPACE_START

class ObjectStore;
class ObjectController;

class PushObjectIngester : public ObjectIngester {
public:

    class Request {
    public:
        using data_type = std::vector<unsigned char>;
        using data_size_type = data_type::size_type;
        using time_type = std::chrono::system_clock::time_point;

        Request() = delete;
        Request(const Request&) = delete;
        Request(Request&&) = delete;
        Request(struct MHD_Connection *mhd_connection, PushObjectIngester &poi);

        virtual ~Request() {};

        Request &operator=(const Request&) = delete;
        Request &operator=(Request&&) = delete;

        const std::string &method() const { return m_method; };

        Request &method(const std::string &method) { m_method = method; return *this; };
        Request &method(std::string &&method) { m_method = std::move(method); return *this; };

        const std::string &urlPath() const { return m_urlPath; };
        Request &urlPath(const std::string &url_path) { m_urlPath = url_path; return *this; };
        Request &urlPath(std::string &&url_path) { m_urlPath = std::move(url_path); return *this; };

        const std::string &protocolVersion() const { return m_protocolVersion; };
        Request &protocolVersion(const std::string &proto_ver) { m_protocolVersion = proto_ver; return *this; };

        Request &protocolVersion(std::string &&proto_ver) { m_protocolVersion = std::move(proto_ver); return *this;};

        const std::optional<std::string> &etag() const { return m_etag; };
        Request &etag(std::nullopt_t) { m_etag.reset(); return *this; };
        Request &etag(const std::string &tag) { m_etag = tag; return *this; };
        Request &etag(const std::optional<std::string> &tag) { m_etag = tag; return *this; };

        const std::optional<std::string> &contentType() const { return m_contentType; };
        Request &contentType(std::nullopt_t) { m_contentType.reset(); return *this; };
        Request &contentType(const std::string &content_type) { m_contentType = content_type; return *this; };
        Request &contentType(const std::optional<std::string> &content_type) { m_contentType = content_type; return *this; };

        const std::optional<time_type> &expiryTime() const { return m_expires; };
        Request &expiryTime(std::nullopt_t) { m_expires.reset(); return *this; };
        Request &expiryTime(const time_type &expires) { m_expires = expires; return *this; };
        Request &expiryTime(const std::optional<time_type> &expires) { m_expires = expires; return *this; };

        const std::optional<time_type> &lastModified() const { return m_lastModified; };
        Request &lastModified(std::nullopt_t) { m_lastModified.reset(); return *this; };
        Request &lastModified(const time_type &last_modified) { m_lastModified = last_modified; return *this; };
        Request &lastModified(const std::optional<time_type> &last_modified) { m_lastModified = last_modified; return *this; };

        std::optional<std::string> getHeader(const std::string &field) const;
        data_size_type bodySize() const { return m_totalBodySize; };

        bool addBodyBlock(const data_type &body_block);
        bool setError(unsigned int status_code = 0, const std::string &reason = std::string());
        void completed(struct MHD_Connection *connection, enum MHD_RequestTerminationCode term_code);
        virtual void waitClose() {};
        void requestHandler(struct MHD_Connection *connection);
        typedef bool (*HeaderProcessingCallback)(const std::string &key, const std::string &value, void *data);
        void processRequestHeader(HeaderProcessingCallback callback, void *data) const;

        virtual std::string reprString() const;

    protected:
        //Request(const std::string &url, const std::string &method, const std::string &version);
        virtual void processRequest();

        struct MHD_Connection *m_mhdConnection;
        struct MHD_Response *m_mhdResponse;

    private:
        PushObjectIngester &m_pushObjectIngester;
        std::string m_objectId;
        std::string m_method;
        std::string m_urlPath;
        std::string m_protocolVersion;
        //MHD_connection *m_mhdConnection;
        std::optional<std::string> m_etag;
        std::optional<std::string> m_contentType;
        std::optional<time_type> m_expires;
        std::optional<time_type> m_lastModified;

        std::list<data_type> m_bodyBlocks;
        data_size_type m_totalBodySize;

        unsigned int m_statusCode;
        std::string m_errorReason;
        bool m_noMoreBodyData;

        std::unique_ptr<std::recursive_mutex> m_mutex;
        std::condition_variable_any m_condVar; /**< CondVar for new response content/eof */
    };

    class ObjectPushEvent : public Event {
    public:
        constexpr static const char *start_event_name = "ObjectPushStart";
        constexpr static const char *block_received_event_name = "ObjectPushBlockReceived";
        constexpr static const char *trailers_received_event_name = "ObjectPushTrailersReceived";
        enum ObjectPushEventType {
            ObjectPushStart,
            ObjectPushBlockReceived,
            ObjectPushTrailersReceived
        };

        ObjectPushEvent() = delete;
        static ObjectPushEvent *makeStartEvent(const std::shared_ptr<Request> &request);
        static ObjectPushEvent *makeBlockReceivedEvent(const std::shared_ptr<Request> &request);
        static ObjectPushEvent *makeTrailersReceivedEvent(const std::shared_ptr<Request> &request);
        ObjectPushEvent(const ObjectPushEvent &other) :Event(other), m_request(other.m_request) {};
        ObjectPushEvent(ObjectPushEvent &&other) :Event(std::move(other)), m_request(std::move(other.m_request)) {};

        virtual ~ObjectPushEvent();

        ObjectPushEvent &operator=(const ObjectPushEvent &other) {
            Event::operator=(other);
            m_request = other.m_request;
            return *this;
        };
        ObjectPushEvent &operator=(ObjectPushEvent &&other) {
            Event::operator=(std::move(other));
            m_request = std::move(other.m_request);
            return *this;
        };

        const Request &request() const { return *m_request; };

        virtual Event clone() const { return ObjectPushEvent(*this); };
        virtual Event *newClone() const { return new ObjectPushEvent(*this); };

        virtual std::string reprString() const { return std::format("ObjectPushEvent(\"{}\", {})", eventName(), m_request->reprString()); };

    private:
        ObjectPushEvent(const std::string &typ, const std::shared_ptr<Request> &request);

        std::shared_ptr<Request> m_request;
    };

    /** Split a shared-daemon request path into its leading discriminator and the object path.
     *
     * Separated from the lookup so it can be tested without a registered ingester, which needs an
     * ObjectStore and an ObjectController to exist.
     *
     * \param url         the request path, as libmicrohttpd gives it, beginning with '/'.
     * \param segment     set to the leading path segment, the ingest session's discriminator.
     * \param object_path set to what follows it, keeping a leading '/' so a child sees the same
     *                    path it would have seen on a port of its own.
     * \return false when there is no leading segment to route on, in which case neither output is
     *         meaningful.
     */
    static bool splitSharedPath(const char *url, std::string &segment, std::string &object_path);

    /** Find the ingester a request path belongs to, and the object path within it.
     *
     * Static because the shared daemon's handler has no ingester of its own to be called on.
     * \param url        the request path, beginning with '/'.
     * \param object_path set to the path with the UUID segment removed.
     * \return the ingester registered under the leading segment, or nullptr if none is.
     */
    static PushObjectIngester *routeSharedRequest(const char *url, std::string &object_path);

    PushObjectIngester(const std::shared_ptr<ObjectStore> &object_store, ObjectController &controller)
        :ObjectIngester(object_store, controller)
        ,m_mhdDaemon(nullptr)
        ,m_sockaddr()
        ,m_activeRequests()
        ,m_IPAddress()
        ,m_domain()
        ,m_urlPrefix()
        ,m_port(0)
        ,m_mtx()
    {
        startWorker();
    };

    bool start();
    bool stop();
    bool addRequest(const std::shared_ptr<Request> &request);
    void removeRequest(const std::shared_ptr<Request> &request);

    //void addConnection(Request *request);
    //void removeConnection(Request *request);
    const std::string &getIngestServerPrefix();

    virtual ~PushObjectIngester();

    //static int client_notify_cb(int status, ogs_sbi_response_t *response, void *data);
    // Notifications from microhttpd handlers
    void addedBodyBlock(const std::shared_ptr<Request> &, std::vector<unsigned char>::size_type block_size,
                        std::vector<unsigned char>::size_type body_size);

protected:
    virtual void doObjectIngest();

private:
    std::string generateUUID();

    /* Shared-port mode, for 5G-MAG/rt-mbs-transport-function#27.
     *
     * Without mbstf.httpPushIngest configured each ingester keeps its own daemon on an ephemeral
     * port, which is what a container cannot publish because the number is not known when it starts.
     * With it configured, one daemon is bound to that address and port for the whole process and
     * every ingester is reached through it, told apart by a UUID path segment its ingest prefix
     * carries. No clause governs any of this: it is a deployment concern, and the port is the
     * operator's to set (RULES.md rule 12).
     */
    static bool sharedPortConfigured();
    /** The port from a sockaddr_storage, or 0 if it carries none. Takes void* so the header need not
     *  pull in the socket headers. */
    static uint16_t sockaddrPort(const void *addr);
    /** Bind the shared daemon if it is not already bound, and register this ingester under a fresh
     *  UUID. Returns the UUID, or an empty string if the shared daemon could not be bound. */
    std::string joinSharedDaemon();
    /** Remove this ingester from the shared daemon, stopping it once the last one leaves. */
    void leaveSharedDaemon();


    static std::recursive_mutex s_sharedMtx;         //!< guards the three members below
    static struct MHD_Daemon *s_sharedDaemon;        //!< the one daemon, when in shared-port mode
    static std::map<std::string, PushObjectIngester*> s_sharedIngesters; //!< UUID -> ingester
    static struct sockaddr_storage s_sharedSockaddr; //!< what the shared daemon is bound to

    std::string m_sharedPathSegment;  //!< this ingester's UUID segment, empty when not shared

    struct MHD_Daemon *m_mhdDaemon;
    struct sockaddr_storage m_sockaddr;
    std::list<std::shared_ptr<Request> > m_activeRequests;
    //std::vector<Request*>  m_connections;
    std::string m_IPAddress;
    std::string m_domain;
    std::string m_urlPrefix;
    int m_port;
    std::recursive_mutex m_mtx;
    std::condition_variable_any m_condVar; /**< CondVar for new response content/eof */
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_PUSH_OBJECT_INGESTER_HH_ */
