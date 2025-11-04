#ifndef _MBS_TF_PUSH_OBJECT_INGESTER_HH_
#define _MBS_TF_PUSH_OBJECT_INGESTER_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Push Object Ingester class
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

	const std::string &method() const { return m_urlPath; };

	Request &method(const std::string &method) { m_method = method; return *this; };
        Request &method(std::string &&method) { m_method = std::move(method); return *this; };

        const std::string &urlPath() const { return m_urlPath; };
        Request &urlPath(const std::string &url_path) { m_urlPath = url_path; return *this; };
        Request &urlPath(std::string &&url_path) { m_urlPath = std::move(url_path); return *this; };

        const std::string &protocolVersion() const { return m_urlPath; };
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
        enum ObjectPushEventType {
            ObjectPushStart,
            ObjectPushBlockReceived,
            ObjectPushTrailersReceived
        };

        ObjectPushEvent() = delete;
        static ObjectPushEvent *makeStartEvent(const std::shared_ptr<Request> &request);
        static ObjectPushEvent *makeBlockReceivedEvent(const std::shared_ptr<Request> &request);
        static ObjectPushEvent *makeTrailersReceivedEvent(const std::shared_ptr<Request> &request);
        ObjectPushEvent(const ObjectPushEvent&) = delete;
        ObjectPushEvent(ObjectPushEvent&&) = delete;

        virtual ~ObjectPushEvent();

        ObjectPushEvent &operator=(const ObjectPushEvent &) = delete;
        ObjectPushEvent &operator=(ObjectPushEvent &&) = delete;

        const Request &request() const { return *m_request; };

    private:
        ObjectPushEvent(const std::string &typ, const std::shared_ptr<Request> &request);

        std::shared_ptr<Request> m_request;
    };

    PushObjectIngester(ObjectStore& object_store, ObjectController &controller)
      :ObjectIngester(object_store, controller)
      ,m_mhdDaemon(nullptr)
      ,m_sockaddr()
      ,m_activeRequests()
      ,m_IPAddress()
      ,m_domain()
      ,m_urlPrefix()
      ,m_port(0)
      ,m_mtx()
    { startWorker(); };

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
