#ifndef _MBS_TF_UTILITIES_HH_
#define _MBS_TF_UTILITIES_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Common utility functions
 ******************************************************************************
 * Copyright: (C)2025-2026 British Broadcasting Corporation
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
#include <netinet/in.h>
#include <sys/socket.h>

#include <chrono>
#include <memory>
#include <optional>
#include <string>

#include "common.hh"

MBSTF_NAMESPACE_START

class SsmPort;

std::string trim_slashes(const std::string &path);

std::string time_point_to_http_datetime_str(const std::chrono::system_clock::time_point &datetime);
std::string time_point_to_iso8601_utc_str(const std::chrono::system_clock::time_point &datetime);
std::chrono::system_clock::time_point iso8601_utc_str_to_time_point(const std::string &iso8601_str);
std::chrono::system_clock::time_point http_datetime_str_to_time_point(const std::string &rfc9110_str);

enum GetMTULevels {
    GET_MTU_ETHERNET_PAYLOAD = 0,
    GET_MTU_IP_PAYLOAD = 1
};

int get_path_mtu(const ogs_sockaddr_t &sock_addr, int minus_level_hdrs = GET_MTU_ETHERNET_PAYLOAD);
int get_tunnelled_path_mtu(const SsmPort &ssm_port, const std::optional<std::string> &tunnel_ip, in_port_t tunnel_port, int minus_level_hdrs = GET_MTU_ETHERNET_PAYLOAD);

std::shared_ptr<struct sockaddr> make_shared_sockaddr(int family_hint, const std::string &hostname, in_port_t port);

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_UTILITIES_HH_ */
