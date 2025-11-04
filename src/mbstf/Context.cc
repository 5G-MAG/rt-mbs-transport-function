/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: App context class
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

#include <map>
#include <memory>
#include <string>
#include <cstring>
#include <stdexcept>
#include "ogs-sbi.h"
#include "ogs-app.h"

#include "common.hh"
#include "App.hh"
#include "DistributionSession.hh"
#include "Open5GSNetworkFunction.hh"
#include "Open5GSSBIServer.hh"
#include "Open5GSSockAddr.hh"
#include "Open5GSYamlDocument.hh"
#include "Open5GSYamlIter.hh"
#include "openapi/model/DistSessionState.h"

#include "Context.hh"

using reftools::mbstf::DistSessionState;

MBSTF_NAMESPACE_START

Context::Context()
    :distributionSessions()
    ,servers()
    ,cacheControl({60, 60})
    ,totalMaxBitRateSoftLimit(100)
    ,consecutiveIngestFailuresBeforeAbort(5)
{
}

Context::~Context()
{
    for (auto &svrs : servers) {
        for (auto &svr: svrs) {
            svr.reset();
        }
    }

}

bool Context::parseConfig()
{
    Open5GSYamlDocument doc(App::self().configDocument());
    Open5GSYamlIter root_iter(doc);
    while (root_iter.next()) {
        std::string root_key(root_iter.key());
        if (root_key == "mbstf") {
            Open5GSYamlIter mbstf_iter(root_iter);
            while (mbstf_iter.next()) {
                std::string mbstf_key(mbstf_iter.key());
                if (mbstf_key == "sbi" || mbstf_key == "service_name" || mbstf_key == "discovery") {
                    // Handled by SBI config parser
                } else if (mbstf_key == "serverResponseCacheControl") {
		    Open5GSYamlIter cc_array(mbstf_iter);
                    if (cc_array.type() == YAML_MAPPING_NODE) {
                        parseCacheControl(cc_array);
                    } else if (cc_array.type() == YAML_SEQUENCE_NODE) {
                        if (!cc_array.next()) break;
                        Open5GSYamlIter cc_iter(cc_array);
                        parseCacheControl(cc_iter);
                    } else if (cc_array.type() == YAML_SCALAR_NODE) {
                        break;
                    } else {
                        throw std::out_of_range("Bad configuration node at mbstf.serverResponseCacheControl");
                     }

		} else if (mbstf_key == "distSessionAPI" || mbstf_key == "httpPushIngest" || mbstf_key == "rtpIngest") {
                    Open5GSYamlIter distSess_array(mbstf_iter);
                    do {
                        if (distSess_array.type() == YAML_MAPPING_NODE) {
                            parseConfiguration(mbstf_key, distSess_array);
                        } else if (distSess_array.type() == YAML_SEQUENCE_NODE) {
                            if (!distSess_array.next()) break;
                            Open5GSYamlIter distSess_iter(distSess_array);
                            parseConfiguration(mbstf_key, distSess_iter);
                        } else if (distSess_array.type() == YAML_SCALAR_NODE) {
                            break;
                        } else {
                            throw std::out_of_range("Bad configuration node at mbstf.distSessionAPI");
                        }

                    } while (distSess_array.type() == YAML_SEQUENCE_NODE);

                } else if (mbstf_key == "totalMaxBitRateSoftLimit") {
                    if (mbstf_iter.type() == YAML_MAPPING_NODE) {
                        std::string limit_val(mbstf_iter.value());
                        size_t idx = 0;
                        totalMaxBitRateSoftLimit = std::stoi(limit_val, &idx);
                        if (idx != limit_val.size()) {
                            throw std::out_of_range("Bad configuration value at mbstf.totalMaxBitRateSoftLimit");
                        }
                    } else {
                        throw std::out_of_range("Bad configuration node at mbstf.totalMaxBitRateSoftLimit");
                    }
                } else if (mbstf_key == "consecutiveIngestFailuresBeforeAbort") {
                    if (mbstf_iter.type() == YAML_MAPPING_NODE) {
                        std::string num_val(mbstf_iter.value());
                        size_t idx = 0;
                        consecutiveIngestFailuresBeforeAbort = std::stoi(num_val, &idx);
                        if (idx != num_val.size()) {
                            throw std::out_of_range("Bad configuration value at mbstf.consecutiveIngestFailuresBeforeAbort");
                        }
                    } else {
                        throw std::out_of_range("Bad configuration node at mbstf.consecutiveIngestFailuresBeforeAbort");
                    }
                } else {
                    ogs_warn("Unknown key `mbstf.%s` in configuration", mbstf_key.c_str());
                }
            }
        }
    }

    //if (!validate()) {
    //    return false;
    //}

    return true;
}

void Context::addDistributionSession(const std::shared_ptr<DistributionSession> &session)
{
    std::string id(session->distributionSessionId());
    std::shared_ptr<DistributionSession> sess_ptr(session);
    distributionSessions.insert(std::make_pair(std::move(id), std::move(sess_ptr)));
    updateNFLoad();
}


void Context::deleteDistributionSession(const std::string &distributionSessionid)
{
    auto it = distributionSessions.find(distributionSessionid);
    if (it != distributionSessions.end()) {
        distributionSessions.erase(it);
        updateNFLoad();
    } else {
        throw std::out_of_range("MBST Distribution session not found");
    }
}


void Context::parseCacheControl(Open5GSYamlIter &iter) {
    while (iter.next()) {
        std::string cc_key(iter.key());
        std::string cc_val(iter.value());
        try {
            if (cc_key == "distMaxAge") {
                cacheControl.distMaxAge = std::stol(cc_val);
            } else if (cc_key == "ObjectMaxAge") {
                cacheControl.defaultObjectMaxAge = std::stol(cc_val);
            }
        } catch (std::out_of_range &ex) {
            ogs_error("Cache control value for %s of \"%s\" is too big for integer storage.", cc_key.c_str(), cc_val.c_str());
        } catch (std::invalid_argument &ex) {
            ogs_error("Cache control value for %s of \"%s\" is not understood as an integer.", cc_key.c_str(), cc_val.c_str());
        }
    }
}

void Context::parseConfiguration(std::string &pc_key, Open5GSYamlIter &iter)   {
     ogs_list_t list, list6;
     ogs_socknode_t *node = NULL, *node6 = NULL;
     int rv;
     int i, family = AF_UNSPEC;
     int num = 0;
     const char *hostname[OGS_MAX_NUM_OF_HOSTNAME];
     int num_of_advertise = 0;
     const char *advertise[OGS_MAX_NUM_OF_HOSTNAME];
     uint16_t port = 0;
     const char *dev = NULL;
     ogs_sockaddr_t *addr = NULL;
     ogs_sockopt_t option;
     bool is_option = false;

     while (iter.next()) {
         std::string sbi_key(iter.key());
	 if(sbi_key == "family") {
	     const char *v = iter.value();
	     if (v) family = atoi(v);
             if (family != AF_UNSPEC && family != AF_INET && family != AF_INET6) {
                 ogs_warn("Ignore family(%d) : ""AF_UNSPEC(%d), " "AF_INET(%d), AF_INET6(%d) ", family, AF_UNSPEC, AF_INET, AF_INET6);
                 family = AF_UNSPEC;
             }
	 } else if ((sbi_key == "addr") || (sbi_key == "name")) {
             Open5GSYamlIter hostname_iter(iter);
             ogs_assert(hostname_iter.type() != YAML_MAPPING_NODE);
             do {
                    if (hostname_iter.type() == YAML_SEQUENCE_NODE) {
                        if (!hostname_iter.next()) break;
                    }
                    ogs_assert(num < OGS_MAX_NUM_OF_HOSTNAME);
                    hostname[num++] = hostname_iter.value();
                } while (hostname_iter.type() == YAML_SEQUENCE_NODE);
	 } else if (sbi_key == "advertise") {
             Open5GSYamlIter advertise_iter(iter);
             ogs_assert(advertise_iter.type() != YAML_MAPPING_NODE);
             do {
                    if (advertise_iter.type() == YAML_SEQUENCE_NODE) {
                        if (!advertise_iter.next()) break;
                    }
                   ogs_assert(num_of_advertise < OGS_MAX_NUM_OF_HOSTNAME);
                   advertise[num_of_advertise++] = advertise_iter.value();
                } while (advertise_iter.type() == YAML_SEQUENCE_NODE);
        } else if (sbi_key == "port") {
             const char *v = iter.value();
             if (v) port = atoi(v);
        } else if (sbi_key == "dev") {
             dev = iter.value();
        } else if (sbi_key == "option") {
             /*
	     rv = ogs_app_config_parse_sockopt(&iter, &option);
             if (rv != OGS_OK) {
                 ogs_debug("ogs_app_config_parse_sockopt() failed");
                 return rv;
             }
	     */
             is_option = true;
	} else if (sbi_key == "tls") {
	    Open5GSYamlIter tls_iter(iter);
            while (tls_iter.next()) {
	      std::string tls_key(tls_iter.key());
              if (tls_key == "key") {
                   //key = tls_iter.value();
               } else if (tls_key == "pem") {
                   //pem = tls_iter.value();
               } else
                   ogs_warn("unknown key `%s`", tls_key.c_str());
            }
	} else
            ogs_warn("unknown key `%s`", sbi_key.c_str());

    }
    if (port == 0){
        ogs_warn("Specify the [%s] port, otherwise a random port will be used", pc_key.c_str());
    }

    addr = NULL;
    for (i = 0; i < num; i++) {
        rv = ogs_addaddrinfo(&addr, family, hostname[i], port, 0);
        ogs_assert(rv == OGS_OK);
    }

    ogs_list_init(&list);
    ogs_list_init(&list6);

    if (addr) {
        if (ogs_app()->parameter.no_ipv4 == 0)
            ogs_socknode_add(&list, AF_INET, addr, NULL);
        if (ogs_app()->parameter.no_ipv6 == 0)
            ogs_socknode_add(&list6, AF_INET6, addr, NULL);
	ogs_freeaddrinfo(addr);
    }

    if (dev) {
        rv = ogs_socknode_probe(
			ogs_app()->parameter.no_ipv4 ? NULL : &list,
                                    ogs_app()->parameter.no_ipv6 ? NULL : &list6,
                                    dev, port, NULL);
        ogs_assert(rv == OGS_OK);
    }

    addr = NULL;
    for (i = 0; i < num_of_advertise; i++) {
        rv = ogs_addaddrinfo(&addr,
                                    family, advertise[i], port, 0);
        ogs_assert(rv == OGS_OK);
    }
    node = (ogs_socknode_t *)ogs_list_first(&list);
    if (node) {
        int matches = 0;
        //ogs_sbi_server_t *server;
	matches = checkForAddr(node);

	if(!matches) {
	    std::shared_ptr<Open5GSSBIServer> newServer;
            newServer.reset(new Open5GSSBIServer(node, is_option ? &option : nullptr));
            newServer->ogsSBIServerAdvertise(addr);

            if (pc_key == "distSessionAPI") {
	        servers[SERVER_DISTRIBUTION_SESSION].push_back(newServer);
            } else if (pc_key == "httpPushIngest") {
		 servers[SERVER_OBJECT_PUSH].push_back(newServer);
	    } else if (pc_key == "rtpIngest") {
		servers[SERVER_RTP].push_back(newServer);
            }

            /*
                if (key) server->tls.key = key;
                if (pem) server->tls.pem = pem;
            */
        }
    }
    node6 = (ogs_socknode_t *)ogs_list_first(&list6);
    if (node6) {
        int matches = 0;
	matches = checkForAddr(node);

        if(!matches) {
            std::shared_ptr<Open5GSSBIServer> newServer;
            newServer.reset(new Open5GSSBIServer(node, is_option ? &option : nullptr));
            newServer->ogsSBIServerAdvertise(addr);

            if (pc_key == "distSessionAPI") {
                servers[SERVER_DISTRIBUTION_SESSION].push_back(newServer);
            } else if (pc_key == "httpPushIngest") {
                 servers[SERVER_OBJECT_PUSH].push_back(newServer);
            } else if (pc_key == "rtpIngest") {
                servers[SERVER_RTP].push_back(newServer);
            }
	}
    }

    if (addr) ogs_freeaddrinfo(addr);
    ogs_socknode_remove_all(&list);
    ogs_socknode_remove_all(&list6);
}

std::vector<std::shared_ptr<Open5GSSockAddr> > Context::DistributionSessionServerAddress()
{
    std::vector<std::shared_ptr<Open5GSSockAddr> > sockAddrs;
    std::vector<std::shared_ptr<Open5GSSBIServer>> srvs = servers[SERVER_DISTRIBUTION_SESSION];
    if(!srvs.empty()) {
        for (const auto &srv: srvs) {
            std::shared_ptr<Open5GSSockAddr> sockAddr;
            sockAddr.reset(new Open5GSSockAddr(srv->ogsSBIServer()->node.addr));
            sockAddrs.push_back(sockAddr);
        }
    }
    return sockAddrs;
}

int Context::checkForAddr(ogs_socknode_t *node)
{
    int i = 0;
    for (i=0; i<SERVER_MAX_NUM; i++) {
        std::vector<std::shared_ptr<Open5GSSBIServer>> srvs = servers[i];
        for (const auto &srv: srvs) {
            if( srv && ogs_sockaddr_is_equal(node->addr, srv->ogsSBIServer()->node.addr)) {
                return 1;
            }
        }
    }
    return 0;
}

void Context::updateNFLoad()
{
    ogs_sbi_nf_service_t *svc;
    ogs_sbi_nf_instance_t *this_nf = ogs_sbi_self()->nf_instance;

    double total_mbr = 0.0;
    for (const auto & [dist_sess_id, dist_sess] : distributionSessions) {
        if (dist_sess->getState() == DistSessionState::VAL_ACTIVE) {
            const std::optional<BitRate> &mbr = dist_sess->getMbr();
            if (mbr) {
                total_mbr += mbr.value().bitRate();
            }
        }
    }
    int new_load = static_cast<int>(total_mbr/1000000.0);

    this_nf->load += new_load;
    ogs_list_for_each(&this_nf->nf_service_list, svc) {
        if (std::string(svc->name) == "nmbstf-distsession") {
            svc->load += new_load;
        }
    }
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
