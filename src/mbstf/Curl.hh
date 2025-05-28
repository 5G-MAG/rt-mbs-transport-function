#ifndef _MBS_TF_CURL_HH_
#define _MBS_TF_CURL_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: cURL client
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

#pragma once

#include <curl/curl.h>
#include <iostream>
#include <string>
#include <mutex>
#include <chrono>
#include <functional>
#include <vector>
#include "common.hh"

MBSTF_NAMESPACE_START

class Curl {
public:
    Curl();
    ~Curl();

    long get(const std::string& url, std::chrono::milliseconds timeout);
    std::vector<unsigned char> &getData();
    const std::vector<unsigned char> &getData() const;
    const std::string &getEtag() const;
    const std::string &getContentType() const;
    const std::string &getEffectiveUrl() const;
    const std::string &getPermanentRedirectUrl() const;
    const unsigned long getCacheControlMaxAge() const;


    Curl &setUserAgent(const std::string &user_agent);

private:
    bool extractProtocolAndStatusCode(std::string_view &status_line);
    void processHeaderLine(std::string_view &header_line);
    static size_t headerCallback(char* buffer, size_t size, size_t numberOfItems, void* userData);
    static size_t writeCallback(void* contents, size_t memberSize, size_t numberOfMembers, void* userData);

    CURL* m_curl;
    int m_hdrState;
    std::vector<unsigned char> m_receivedData;
    std::string m_etag;
    std::string m_contentType;
    std::string m_effectiveUrl;
    std::string m_userAgent;
    std::string m_protocol;
    int m_statusCode;
    std::string m_permanentRedirectUrl;
    unsigned long m_cacheControlMaxAge;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_CURL_HH_ */

