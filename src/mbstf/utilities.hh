#ifndef _MBS_TF_UTILITIES_HH_
#define _MBS_TF_UTILITIES_HH_
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
#include <string>

#include "common.hh"

MBSTF_NAMESPACE_START

std::string trim_slashes(const std::string &path);

std::string time_point_to_http_datetime_str(const std::chrono::system_clock::time_point &datetime);
std::string time_point_to_iso8601_utc_str(const std::chrono::system_clock::time_point &datetime);

int get_path_mtu(const ogs_sockaddr_t &sock_addr);
int get_tunnelled_path_mtu(const std::optional<std::string> &dest_ip, in_port_t dest_port,
                            const std::optional<std::string> &tunnel_ip, in_port_t tunnel_port);

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_UTILITIES_HH_ */
