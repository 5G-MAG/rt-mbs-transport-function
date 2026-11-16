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

/* The GTP-U header the MB-UPF puts in front of each packet it forwards to the gNB, beyond the IP and UDP headers that
   the tunnel from the MBSTF to the MB-UPF already counts for. TS 29.281 V18.4.0 clause 5.1: "The GTP-U header is a
   variable length header whose minimum length is 8 bytes." The MB-UPF writes 20: the 8 octets, the 4 optional ones,
   and one extension header of 8 octets (a capture of its output: flags 0x34, header of 20 octets). The FLUTE packets
   are sized with this taken off the path MTU, so that the packet the MB-UPF sends on, with its own IP, UDP and GTP-U
   headers, fits the path MTU. With 2 taken off, a full-size FDT packet of 1470 octets became a 1518 octet packet
   at the MB-UPF, which cut it to the 1498 it could send, and the UE dropped what was left. */
#define GTP_HEADER_SIZE 20

/* Open5GS Logging */
extern int __mbstf_log_domain;
#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __mbstf_log_domain

extern void initialise_logging(void);

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_COMMON_HH_ */
