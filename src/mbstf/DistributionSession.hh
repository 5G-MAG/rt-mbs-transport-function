#ifndef _MBS_TF_DISTRIBUTION_SESSION_HH_
#define _MBS_TF_DISTRIBUTION_SESSION_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Distribution Session class
 ******************************************************************************
 * Copyright: (C)2024-2025 British Broadcasting Corporation
 * Author(s): Dev Audsin <dev.audsin@bbc.co.uk>
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

#include <chrono>
#include <memory>
#include "openapi/model/DistSessionState.h"
#include "openapi/model/ObjDistributionData.h"
#include "common.hh"
#include "BitRate.hh"
//#include "Subscriber.hh"

namespace fiveg_mag_reftools {
    class CJson;
}

namespace reftools::mbstf {
    class CreateReqData;
    class ObjDistributionData;
}

MBSTF_NAMESPACE_START

class Open5GSEvent;
class Controller;

class DistributionSession { // : public Subscriber {
public:
    using SysTimeMS = std::chrono::system_clock::time_point;

    DistributionSession(fiveg_mag_reftools::CJson &json, bool as_request);
    //DistributionSession(const std::shared_ptr<reftools::mbstf::CreateReqData> &create_req_data);
    DistributionSession() = delete;
    DistributionSession(DistributionSession &&other) = delete;
    DistributionSession(const DistributionSession &other) = delete;
    DistributionSession &operator=(DistributionSession &&other) = delete;
    DistributionSession &operator=(const DistributionSession &other) = delete;

    virtual ~DistributionSession();

    fiveg_mag_reftools::CJson json(bool as_request) const;

    static const std::shared_ptr<DistributionSession> &find(const std::string &id); // throws std::out_of_range if id does not exist
    const std::string &distributionSessionId() const { return m_distributionSessionId; };
    const std::shared_ptr<reftools::mbstf::CreateReqData> &distributionSessionReqData() const {return m_createReqData;};
    DistributionSession &distributionSessionReqData(const std::shared_ptr<reftools::mbstf::CreateReqData> &req_data);
    const SysTimeMS &generated() const {return m_generated;};
    const std::string &hash() const {return m_hash;};
    void setController(std::shared_ptr<Controller> controller) {m_controller = controller;};

    static bool processEvent(Open5GSEvent &event);

    const reftools::mbstf::DistSessionState &getState() const;
    DistributionSession &setState(const reftools::mbstf::DistSessionState &state);
    const reftools::mbstf::ObjDistributionData::ObjAcquisitionIdsPullType &getObjectAcquisitionPullUrls() const;
    const std::string &getObjectDistributionOperatingMode() const;
    const std::optional<std::string> &getDestIpAddr() const;
    const std::optional<std::string> &getTunnelAddr() const;
    in_port_t getPortNumber() const;
    in_port_t getTunnelPortNumber() const;
    uint32_t getRateLimit() const;
    std::optional<BitRate> getMbr() const;
    const std::optional<std::string> &getObjectIngestBaseUrl() const;
    const std::string &getObjectAcquisitionMethod() const;
    void setObjectIngestBaseUrl(std::string ingestBaseUrl);
    const std::optional<std::string> &getObjectAcquisitionPushId() const;
    bool setObjectAcquisitionIdPush(std::optional<std::string> &id);
    const std::optional<std::string> &objectDistributionBaseUrl() const;

    // TODO: Forwarding Events from the Controller to m_eventSubscriptions
    // virtual void processEvent(Event &event, SubscriptionService &event_service);

private:
    class InitStateAction;
    class StateTransitionAction;

    class Action {
    public:
        typedef enum {
            INIT_STATE,
            STATE_TRANSITION
        } ActionType;

        Action(ActionType typ): m_type(typ) {};
        virtual ~Action() {};

        ActionType getType() const { return m_type; };

        static InitStateAction initState();
        static StateTransitionAction stateTransition(reftools::mbstf::DistSessionState::Enum new_state);
    protected:
        ActionType m_type;
    };

    class InitStateAction : public Action {
    public:
        InitStateAction() :Action(Action::INIT_STATE) {};
    };

    class StateTransitionAction : public Action {
    public:
        StateTransitionAction(reftools::mbstf::DistSessionState::Enum new_state) :Action(Action::STATE_TRANSITION), m_newState(new_state) {};
        virtual ~StateTransitionAction() {};

        reftools::mbstf::DistSessionState::Enum newState() const { return m_newState; };

    private:
        reftools::mbstf::DistSessionState::Enum m_newState;
    };

    void _transitionTo(reftools::mbstf::DistSessionState::Enum new_state);
    void _changeState(void (DistributionSession::*f)(const DistributionSession::Action &action));
    void _constructedState(const Action &action);
    void _inactiveState(const Action &action);
    void _establishedState(const Action &action);
    void _activeState(const Action &action);
    void _deactivatingState(const Action &action);
    void _setLastUsed();
    void _setHash();

    std::shared_ptr<reftools::mbstf::CreateReqData> m_createReqData;
    SysTimeMS m_generated;
    SysTimeMS m_lastUsed;
    std::string m_hash;
    std::string m_distributionSessionId;
    std::shared_ptr<Controller> m_controller;
    // MBSTF event notification (TODO)
    //std::list<DistributionSessionSubscription> m_eventSubscriptions;
    std::function<void(const Action&)> m_currentStateFunction;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_DISTRIBUTION_SESSION_HH_ */
