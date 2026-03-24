#ifndef _MBS_TF_COMMON_HH_
#define _MBS_TF_COMMON_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Common values and macros
 ******************************************************************************
 * Copyright: (C)2024 British Broadcasting Corporation
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

/* MBSTF Namespace macros */
#define MBSTF_NAMESPACE com::fiveg_mag::ref_tools::mbstf
#define MBSTF_NAMESPACE_START namespace MBSTF_NAMESPACE {
#define MBSTF_NAMESPACE_STOP  }
#define MBSTF_NAMESPACE_USING using namespace MBSTF_NAMESPACE
#define MBSTF_NAMESPACE_NAME(a) MBSTF_NAMESPACE::a

/* Constants */
#define GTP_HEADER_SIZE 2

/* Open5GS Logging */
extern int __mbstf_log_domain;
#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __mbstf_log_domain

extern void initialise_logging(void);

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_COMMON_HH_ */
