/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: cURL requests
 ******************************************************************************
 * Copyright: (C)2025 British Broadcasting Corporation
 * Author(s): Dev Audsin <dev.audsin@bbc.co.uk>
 *            David Waring <david.waring2@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include <iostream>

#include "ogs-app.h"

#include "common.hh"
#include "mbstf-version.h"

#include "Curl.hh"

MBSTF_NAMESPACE_START

class CurlGlobalCleanup {
public:
    CurlGlobalCleanup() {};
    ~CurlGlobalCleanup() {
        curl_global_cleanup();
    };
};

// Ensure cURL clean up called on program exit
static CurlGlobalCleanup g_curl_global_cleanup;

enum HeaderProcessingState {
    HEADER_START,
    HEADER_HEADERS,
    HEADER_BODY,
    HEADER_TRAILING
};

Curl::Curl()
    :m_hdrState(HEADER_START)
    ,m_receivedData()
    ,m_etag()
    ,m_contentType()
    ,m_effectiveUrl()
    ,m_userAgent()
    ,m_protocol()
    ,m_statusCode(0)
    ,m_permanentRedirectUrl()
{
    // Ensure curl_global_init is called only once
    static std::once_flag init_flag;
    std::call_once(init_flag, []() {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    });

    // Initialize the CURL handle
    m_curl = curl_easy_init();
}

Curl::~Curl() {
    if (m_curl) {
        curl_easy_cleanup(m_curl);
    }
}

long Curl::get(const std::string& url, std::chrono::milliseconds timeout) {
    m_etag.clear(); // Clear the ETag before making a new request
    m_receivedData.clear(); // Clear the received data before making a new request

    if (m_curl) {
        curl_easy_setopt(m_curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(m_curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2);
	curl_easy_setopt(m_curl, CURLOPT_CONNECTTIMEOUT_MS, 500l);
        curl_easy_setopt(m_curl, CURLOPT_TIMEOUT_MS, timeout.count());
        curl_easy_setopt(m_curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(m_curl, CURLOPT_HEADERDATA, this);
        curl_easy_setopt(m_curl, CURLOPT_HEADERFUNCTION, headerCallback);
        curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, &m_receivedData);
        curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, writeCallback);
        if (m_userAgent.empty()) {
            curl_easy_setopt(m_curl, CURLOPT_USERAGENT, MBSTF_TYPE "/" MBSTF_VERSION);
        } else {
            curl_easy_setopt(m_curl, CURLOPT_USERAGENT, m_userAgent.c_str());
        }

        // reset values collected during redirects
        m_hdrState = HEADER_START;
        m_statusCode = 0;
        m_protocol.clear();
        m_permanentRedirectUrl.clear();

        CURLcode res = curl_easy_perform(m_curl);
        if (res == CURLE_OK) {
	    struct curl_header *type;
            CURLHcode h;
            h = curl_easy_header(m_curl, "ETag", 0, CURLH_HEADER, -1, &type);
            if (h == CURLHE_OK && type) {
                m_etag = std::string(type->value);
		ogs_info("ETag: %s", m_etag.c_str());
            } else {
		ogs_info("ETag header not found.");
            }

            // Get the Content-Type header
	    char *ct = NULL;
	    res = curl_easy_getinfo(m_curl, CURLINFO_CONTENT_TYPE, &ct);
	    if (!res && ct) {
	        m_contentType = std::string(ct);
	    }

            char *redir_url = NULL;
            res = curl_easy_getinfo(m_curl, CURLINFO_EFFECTIVE_URL, &redir_url);
            if (!res && redir_url) {
                m_effectiveUrl = redir_url;
            }

            return m_receivedData.size(); // Return the number of bytes received
        } else if (res == CURLE_OPERATION_TIMEDOUT) {
            return -1; // Indicate timeout
        } else {
            //std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
            return -2; // Indicate other error
        }
    }
    return -2; // Indicate error if m_curl is not initialized
}

std::vector<unsigned char>& Curl::getData()
{
    return m_receivedData;
}

const std::vector<unsigned char>& Curl::getData() const
{
    return m_receivedData;
}

const std::string& Curl::getEtag() const
{
    return m_etag;
}

const std::string& Curl::getContentType() const
{
    return m_contentType;
}

const std::string &Curl::getEffectiveUrl() const
{
    return m_effectiveUrl;
}

const std::string &Curl::getPermanentRedirectUrl() const
{
    return m_permanentRedirectUrl;
}

bool Curl::extractProtocolAndStatusCode(std::string_view &header_line)
{
    header_line.remove_prefix(5); // Skip "HTTP/"
    // Find first space character marking the end of the protocol version
    auto end_of_protocol = header_line.find_first_of(' ');
    if (end_of_protocol == std::string_view::npos) return false;
    m_protocol = header_line.substr(0, end_of_protocol);

    // Skip to start of status code
    header_line.remove_prefix(end_of_protocol);
    auto start_of_statuscode = header_line.find_first_not_of(' ');
    if (start_of_statuscode == std::string_view::npos) return false;
    header_line.remove_prefix(start_of_statuscode);

    // Find the end of the status code, clip and convert the status code into an integer
    auto end_of_statuscode = header_line.find_first_of(' ');
    if (end_of_statuscode == std::string_view::npos) {
        m_statusCode = std::stoi(std::string(header_line));
    } else {
        m_statusCode = std::stoi(std::string(header_line.substr(0,end_of_statuscode)));
    }
    return true;
}

void Curl::processHeaderLine(std::string_view &header_line)
{
    // Strip trailing CR LF
    if (header_line.ends_with("\r\n")) header_line.remove_suffix(2);

    switch (m_hdrState) {
    case HEADER_START: // haven't had any headers yet, so waiting for status line
        //ogs_debug("Status line: %s", std::string(header_line).c_str());
        if (!header_line.starts_with("HTTP/")) break;
        if (!extractProtocolAndStatusCode(header_line)) break;
        m_hdrState = HEADER_HEADERS;
        break;
    case HEADER_HEADERS: // had status line, now processing headers until we see an empty line
        //ogs_debug("Header: %s", std::string(header_line).c_str());
        if (header_line.empty()) {
            m_hdrState = HEADER_BODY;
        } else if ((m_statusCode == 301 || m_statusCode == 308) &&
                   (header_line.starts_with("Location:") || header_line.starts_with("location:"))) {
            header_line.remove_prefix(9);
            while (header_line.front() == ' ') header_line.remove_prefix(1);
            m_permanentRedirectUrl = header_line;
            ogs_debug("Got new redirect URL: %s", m_permanentRedirectUrl.c_str());
        }
        break;
    case HEADER_BODY: // We're in the response body, so this is either a trailing header or a new status line after redirect
        //ogs_debug("Trailer/New status: %s", std::string(header_line).c_str());
        if (header_line.starts_with("HTTP/") && extractProtocolAndStatusCode(header_line)) {
            m_hdrState = HEADER_HEADERS;
        } else {
            m_hdrState = HEADER_TRAILING;
        }
        break;
    case HEADER_TRAILING: // We're in trailing headers, but if we see a status line we're starting a new redirected fetch
        if (header_line.starts_with("HTTP/") && extractProtocolAndStatusCode(header_line)) {
            m_hdrState = HEADER_HEADERS;
        }
        break;
    default:
        break;
    }
}

size_t Curl::headerCallback(char* buffer, size_t size, size_t nitems, void* userdata)
{
    size_t totalSize = size * nitems;
    Curl* self = reinterpret_cast<Curl*>(userdata);

    std::string_view header_line(buffer, totalSize);
    self->processHeaderLine(header_line);

    return totalSize;
}

size_t Curl::writeCallback(void* contents, size_t memberSize, size_t numberOfMembers, void* userData)
{
    size_t totalSize = memberSize * numberOfMembers;
    std::vector<unsigned char>* receivedData = static_cast<std::vector<unsigned char>*>(userData);
    unsigned char* data = static_cast<unsigned char*>(contents);
    receivedData->insert(receivedData->end(), data, data + totalSize);
    return totalSize;
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */

