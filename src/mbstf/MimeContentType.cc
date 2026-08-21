/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: MIME Content Type
 ******************************************************************************
 * Copyright: (C)2025 British Broadcasting Corporation
 * Author: David Waring <david.waring2@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * Licensed under the License terms and conditions for use, reproduction, and
 * distribution of 5G-MAG software (the “License”).  You may not use this file
 * except in compliance with the License.  You may obtain a copy of the License at
 * https://www.5g-mag.com/reference-tools.  Unless required by applicable law or
 * agreed to in writing, software distributed under the License is distributed on
 * an “AS IS” BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied.
 *
 * See the License for the specific language governing permissions and limitations
 * under the License.
 */

#include "ogs-sbi.h"

#include <compare>
#include <map>
#include <string>

#include "common.hh"
#include "CaseInsensitiveTraits.hh"

#include "MimeContentType.hh"

MBSTF_NAMESPACE_START

static std::string _quote(const std::string &str);

MimeContentType::MimeContentType()
    :m_mimeType()
    ,m_mimeTypeLower()
    ,m_typeParams()
{
}

MimeContentType::MimeContentType(const std::string &content_type)
    :m_mimeType()
    ,m_mimeTypeLower()
    ,m_typeParams()
{
    *this = content_type;
}

MimeContentType::MimeContentType(const MimeContentType &other)
    :m_mimeType(other.m_mimeType)
    ,m_mimeTypeLower(other.m_mimeTypeLower)
    ,m_typeParams(other.m_typeParams)
{
}

MimeContentType::MimeContentType(MimeContentType &&other)
    :m_mimeType(std::move(other.m_mimeType))
    ,m_mimeTypeLower(std::move(other.m_mimeTypeLower))
    ,m_typeParams(std::move(other.m_typeParams))
{
}

MimeContentType &MimeContentType::operator=(const std::string &content_type)
{
    // Parse media-type according to rfc9110
    int state = 0;
    m_mimeType.clear();
    m_mimeTypeLower.clear();
    m_typeParams.clear();
    std::string key;
    std::string value;
    static const std::string unquoted_token_chars{"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-.^_`|~"};
    for (auto c : content_type) {
retry_ct_char:
        switch (state) {
        case 0:
            // preamble whitespace
            if (!std::isspace(c)) {
                state = 1;
                goto retry_ct_char;
            }
            break;
        case 1:
            // Start of media-type - must be a token char
            if (unquoted_token_chars.find_first_of(c) != std::string::npos) {
                m_mimeType += c;
                m_mimeTypeLower += std::tolower(c);
                state = 2;
            } else {
                throw std::out_of_range("Bad Content-Type value");
            }
            break;
        case 2:
            // Continue media-type - token char or /
            if (unquoted_token_chars.find_first_of(c) != std::string::npos) {
                m_mimeType += c;
                m_mimeTypeLower += std::tolower(c);
                state = 2;
            } else if (c == '/') {
                m_mimeType += c;
                m_mimeTypeLower += c;
                state = 3;
            } else {
                throw std::out_of_range("Bad Content-Type value");
            }
            break;
        case 3:
            // Start of media-type subtype - must be a token char
            if (unquoted_token_chars.find_first_of(c) != std::string::npos) {
                m_mimeType += c;
                m_mimeTypeLower += std::tolower(c);
                state = 4;
            } else {
                throw std::out_of_range("Bad Content-Type value");
            }
            break;
        case 4:
            // Continue media-type subtype - token char, space or ;
            if (unquoted_token_chars.find_first_of(c) != std::string::npos) {
                m_mimeType += c;
                m_mimeTypeLower += std::tolower(c);
            } else if (c == ';') {
                state = 6;
            } else if (std::isspace(c)) {
                state = 5;
            } else {
                throw std::out_of_range("Bad Content-Type value");
            }
            break;
        case 5:
            // Optional parameters - *(OWS ";" OWS [parameter])
            if (c == ';') {
                state = 6;
            } else if (!std::isspace(c)) {
                throw std::out_of_range("Bad Content-Type value");
            }
            break;
        case 6:
            // Found ";" in parameters - OWS [parameter] *(OWS ";" OWS [parameter])
            if (unquoted_token_chars.find_first_of(c) != std::string::npos) {
                key += c;
                state = 7;
            } else if (c != ';' && !std::isspace(c)) {
                throw std::out_of_range("Bad Content-Type value");
            }
            break;
        case 7:
            // Found parameter (key already started) - token "=" (token | quoted-string)
            if (unquoted_token_chars.find_first_of(c) != std::string::npos) {
                key += c;
            } else if (c == '=') {
                state = 8;
            } else {
                throw std::out_of_range("Bad Content-Type value");
            }
            break;
        case 8:
            // parameter-value - (token | quoted-string)
            if (c == '"') {
                state = 10;
            } else if (unquoted_token_chars.find_first_of(c) != std::string::npos) {
                state = 9;
                value += c;
            } else {
                throw std::out_of_range("Bad Content-Type value");
            }
            break;
        case 9:
            // parameter-value token (continued) - token *(OWS ";" OWS [parameter])
            if (unquoted_token_chars.find_first_of(c) != std::string::npos) {
                value += c;
            } else if (c == ';') {
                m_typeParams[key] = value;
                key.clear();
                value.clear();
                state = 6;
            } else if (std::isspace(c)) {
                m_typeParams[key] = value;
                key.clear();
                value.clear();
                state = 5;
            }
            break;
        case 10:
            // quoted-string parameter value
            if (c == '"') {
                m_typeParams[key] = value;
                key.clear();
                value.clear();
                state = 5;
            } else if (c == '\\') {
                state = 11;
            } else {
                value += c;
            }
            break;
        case 11:
            // quoted-string parameter value, quoted-pair
            value += c;
            state = 10;
            break;
        default:
            throw std::runtime_error("Bad parser state for Content-Type");
        }
    }
    // Complete the paraeter-value token and 
    if (state == 9) {
        m_typeParams[key] = value;
        state = 5;
    }

    // If we are not in a valid finishing state, then parse error
    if (state != 4 && state != 5 && state != 6) {
        throw std::out_of_range("Bad Content-Type value");
    }

    return *this;
}

MimeContentType &MimeContentType::operator=(const MimeContentType &other)
{
    m_mimeType = other.m_mimeType;
    m_mimeTypeLower = other.m_mimeTypeLower;
    m_typeParams = other.m_typeParams;
    return *this;
}

MimeContentType &MimeContentType::operator=(MimeContentType &&other)
{
    m_mimeType = std::move(other.m_mimeType);
    m_mimeTypeLower = std::move(other.m_mimeTypeLower);
    m_typeParams = std::move(other.m_typeParams);
    return *this;
}

std::weak_ordering MimeContentType::operator<=>(const MimeContentType &other) const
{
    auto result = (m_mimeType <=> other.m_mimeType);
    if (result < 0) return std::weak_ordering::less;
    if (result > 0) return std::weak_ordering::greater;

    for (const auto &[key, value] : m_typeParams) {
        if (other.hasParameter(key)) {
            auto result = (value <=> other.parameter(key));
            if (result < 0) return std::weak_ordering::less;
            if (result > 0) return std::weak_ordering::greater;
        } else {
            return std::weak_ordering::greater;
        }
    }

    return std::weak_ordering::equivalent;
}

bool MimeContentType::hasParameter(const std::string &param_key) const
{
    return m_typeParams.find(param_key) != m_typeParams.end();
}

const std::string &MimeContentType::parameter(const std::string &param_key) const
{
    auto it = m_typeParams.find(param_key);
    if (it != m_typeParams.end()) return it->second;
    throw std::out_of_range(std::format("Parameter {} not found in Content-Type parameters", param_key));
}

MimeContentType &MimeContentType::parameter(const std::string &param_key, const std::string &param_value)
{
    m_typeParams[param_key] = param_value;
    return *this;
}

std::size_t MimeContentType::hash() const
{
    std::hash<std::string> sh;
    return sh(m_mimeTypeLower);
}

MimeContentType::operator std::string() const
{
    std::string result(std::string_view(m_mimeType.data(), m_mimeType.size()));
    for (const auto &[key,value] : m_typeParams) {
        result += std::format("; {}={}", key, _quote(value));
    }
    return result;
}

static std::string _quote(const std::string &str)
{
    std::string result;
    static const char unquoted_token_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-.^_`{|}~";
    if (str.find_first_not_of(unquoted_token_chars) != std::string::npos) {
        result += '"';
        for (char c : str) {
            if (c == '\\' || c == '"') {
                result += '\\';
            }
            result += c;
        }
        result += '"';
    } else {
        result = str;
    }
    return result;
}

MBSTF_NAMESPACE_STOP

namespace std {

std::size_t hash<MBSTF_NAMESPACE_NAME(MimeContentType)>::operator()(const MBSTF_NAMESPACE_NAME(MimeContentType) &val) const
{
    return val.hash();
}

}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
