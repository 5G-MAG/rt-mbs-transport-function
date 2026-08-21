#ifndef _MBS_TF_CONTEXT_HH_
#define _MBS_TF_CONTEXT_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: MBSTF Context
 ******************************************************************************
 * Copyright: (C)2024-2026 British Broadcasting Corporation
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
#include <map>
#include <memory>
#include <optional>
#include <vector>

#include "ogs-sbi.h"
#include "ogs-app.h"

#include "common.hh"

MBSTF_NAMESPACE_START

class DistributionSession;
class Open5GSSBIServer;
class Open5GSSockAddr;
class Open5GSYamlIter;

class Context {
public:
    Context();
    Context(Context &&other) = delete;
    Context(const Context &other) = delete;
    Context &operator=(Context &&other) = delete;
    Context &operator=(const Context &other) = delete;
    virtual ~Context();

    bool parseConfig();

    std::vector<std::shared_ptr<Open5GSSockAddr> > DistributionSessionServerAddress();

/*
    void addDistributionSession(const std::string &session_id, const std::shared_ptr<DistributionSession> &session) {
        distributionSessions.insert(std::make_pair(session_id, std::shared_ptr<DistributionSession>(session)));
    }
*/
    void addDistributionSession(const std::shared_ptr<DistributionSession> &DistributionSession);
    void deleteDistributionSession(const std::string &distributionSessionid);
    const std::shared_ptr<DistributionSession> &findDistributionSession(const std::string &distributionSessionid);

    enum ServerType {
        SERVER_DISTRIBUTION_SESSION,
        SERVER_OBJECT_PUSH,
        SERVER_RTP,
        SERVER_MAX_NUM
    };

    std::map<std::string, std::shared_ptr<DistributionSession> > distributionSessions;
    std::vector<std::shared_ptr<Open5GSSBIServer> > servers[SERVER_MAX_NUM];
    struct {
        unsigned int distMaxAge;
        unsigned int defaultObjectMaxAge; // Use if not given by push/pull resource Cache-Control.
    } cacheControl;
    int totalMaxBitRateSoftLimit; //< total maximum bit rate this MBSTF ought to asked to handle
    int consecutiveIngestFailuresBeforeDeactivate; //< The number of consecutive ingest failures allowed before the session aborts
    size_t packetModeSchedulingQueueSize; //< The maximum queue size for packet mode scheduling per DistSession
    struct {
        /** The maximum time allowed before the manifest will be transmitted again
         *
         * This may be overridden my ManifestHandler specific class configuration.
         */
        std::optional<std::chrono::milliseconds> manifestRepetitionRate = std::nullopt;
    } manifestGlobals; //< ManifestHandler global configuration (can be overridden by ManifestHandler implement specific config)

    /** Parse a configuration time duration string
     *
     * Format:
     *     <INTEGER>[<UNITS>]
     *     Where INTEGER is any positive whole number in decimal and UNITS is optional and either "w", "d", "h", "m", "s" or "ms"
     *     for weeks, days, hours, minutes, seconds or milliseconds respectively. UNITS will be assumed to be seconds if not given.
     *
     * @param duration_string The duration in the format described.
     * @return The duration in milliseconds.
     * @throw std::out_of_range If the duration string cannnot be parsed into a duration.
     */
    static std::chrono::milliseconds parseDuration(const std::string &duration_string);

private:
    void parseCacheControl(Open5GSYamlIter &iter);
    void parseManifestHandlerGlobals(const std::string &pc_key, Open5GSYamlIter &iter);
    void parseConfiguration(std::string &pc_key, Open5GSYamlIter &iter);
    int checkForAddr(ogs_socknode_t *node);
    void updateNFLoad();
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_CONTEXT_HH_ */
