#ifndef _MBS_TF_MBSTF_NETWORK_FUNCTION_HH_
#define _MBS_TF_MBSTF_NETWORK_FUNCTION_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: MBSTF Network Function class
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

#include "ogs-app.h"
#include "ogs-proto.h"
#include "ogs-sbi.h"

#include <memory>

#include "common.hh"
#include "Open5GSNetworkFunction.hh"

MBSTF_NAMESPACE_START

class MBSTFNetworkFunction : public Open5GSNetworkFunction {
public:
    MBSTFNetworkFunction() : Open5GSNetworkFunction() {};
    MBSTFNetworkFunction(MBSTFNetworkFunction &&other) = delete;
    MBSTFNetworkFunction(const MBSTFNetworkFunction &other) = delete;
    MBSTFNetworkFunction &operator=(MBSTFNetworkFunction &&other) = delete;
    MBSTFNetworkFunction &operator=(const MBSTFNetworkFunction &other) = delete;
    virtual ~MBSTFNetworkFunction() {};

    int setMBSTFNFServiceInfo();
    int setMBSTFNFService();

    void initialise() {};

    virtual OpenAPI_nf_type_e nfType() const { return OpenAPI_nf_type_MBSTF; };

private:
    void addAddressesToNFService(ogs_sbi_nf_service_t *nf_service, ogs_sockaddr_t *addrs);
    char *m_serviceName;
    char *m_supportedFeatures;
    char *m_apiVersion;
    ogs_sockaddr_t *m_addr;

};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_MBSTF_NETWORK_FUNCTION_HH_ */
