/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Common utility functions
 ******************************************************************************
 * Copyright: (C)2025 British Broadcasting Corporation
 * Author(s): David Waring <david.waring2@bbc.co.uk>
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
#include <chrono>
#include <format>
#include <string>

#include "common.hh"

#include "utilities.hh"

MBSTF_NAMESPACE_START

std::string trim_slashes(const std::string &path)
{
    size_t start = path.starts_with('/') ? 1 : 0;
    size_t end = path.ends_with('/') ? path.size() - 1 : path.size();

    return path.substr(start, end - start);
}

std::string time_point_to_http_datetime_str(const std::chrono::system_clock::time_point &datetime)
{
    return std::format("%b, %d %b %Y %T GMT", datetime);
}

std::string time_point_to_iso8601_utc_str(const std::chrono::system_clock::time_point &datetime)
{
    std::ostringstream oss;
    auto datetime_us = std::chrono::time_point_cast<std::chrono::microseconds>(datetime);
    oss.imbue(std::locale("C"));
    oss << std::format("{0:%F}T{0:%T}Z", datetime_us);
    return oss.str();
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
