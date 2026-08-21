#ifndef _MBS_TF_MIME_CONTENT_TYPE_HH_
#define _MBS_TF_MIME_CONTENT_TYPE_HH_
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
#include <format>
#include <map>
#include <string>

#include "common.hh"
#include "CaseInsensitiveTraits.hh"

MBSTF_NAMESPACE_START

class MimeContentType
{
public:
    using cistring = std::basic_string<char, CaseInsensitiveTraits<char>>;
    MimeContentType();
    MimeContentType(const std::string &content_type);
    MimeContentType(const MimeContentType &other);
    MimeContentType(MimeContentType &&other);

    virtual ~MimeContentType() {};

    MimeContentType &operator=(const std::string &content_type);
    MimeContentType &operator=(const MimeContentType &other);
    MimeContentType &operator=(MimeContentType &&other);

    std::weak_ordering operator<=>(const MimeContentType &other) const;
    bool operator==(const MimeContentType &other) const { return (*this <=> other) == 0; };
    bool operator!=(const MimeContentType &other) const { return (*this <=> other) != 0; };
    bool operator<(const MimeContentType &other) const { return (*this <=> other) < 0; };
    bool operator<=(const MimeContentType &other) const { return (*this <=> other) <= 0; };
    bool operator>(const MimeContentType &other) const { return (*this <=> other) > 0; };
    bool operator>=(const MimeContentType &other) const { return (*this <=> other) >= 0; };

    const cistring &mimeType() const { return m_mimeType; };
    MimeContentType &mimeType(const cistring &mime_type) { m_mimeType = mime_type; return *this; };

    bool hasParameter(const std::string &param_key) const;
    const std::string &parameter(const std::string &param_key) const;
    MimeContentType &parameter(const std::string &param_key, const std::string &param_value);

    std::size_t hash() const;

    bool empty() const { return m_mimeType.empty() && m_typeParams.empty(); };
    MimeContentType &clear() { m_mimeType.clear(); m_typeParams.clear(); return *this; };

    operator std::string() const;

private:
    cistring m_mimeType;
    std::string m_mimeTypeLower;
    std::map<std::string, std::string> m_typeParams;
};

MBSTF_NAMESPACE_STOP

namespace std {
    template<>
    struct formatter<MBSTF_NAMESPACE_NAME(MimeContentType), char> {
        template <class ParseContext>
        constexpr ParseContext::iterator parse(ParseContext& ctx) {
            return ctx.begin();
        };
        template <class FmtContext>
        FmtContext::iterator format(MBSTF_NAMESPACE_NAME(MimeContentType) content_type, FmtContext& ctx) const {
            return std::format_to(ctx.out(), "{}", static_cast<std::string>(content_type));
        };
    };

    template<>
    struct hash<MBSTF_NAMESPACE_NAME(MimeContentType)> {
        std::size_t operator()(const MBSTF_NAMESPACE_NAME(MimeContentType) &val) const;
    };
}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif
