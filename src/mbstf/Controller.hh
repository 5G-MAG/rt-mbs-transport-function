#ifndef _MBS_TF_CONTROLLER_HH_
#define _MBS_TF_CONTROLLER_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Session Controller Base
 ******************************************************************************
 * Copyright: (C)2024-2025 British Broadcasting Corporation
 * Author(s): Dev Audsin <dev.audsin@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include "common.hh"
#include "SubscriptionService.hh"

MBSTF_NAMESPACE_START

class DistributionSession;

class Controller : public SubscriptionService {
public:
    Controller() = delete;
    Controller(DistributionSession &distributionSession);
    Controller(const Controller &) = delete;
    Controller(Controller &&) = delete;

    virtual ~Controller() {};

    Controller &operator=(const Controller &) = delete;
    Controller &operator=(Controller &&) = delete;

    DistributionSession &distributionSession() {return m_distributionSession;};
    const DistributionSession &distributionSession() const {return m_distributionSession;};

    virtual void reconfigure() {};

    virtual void establishInactiveInputs() = 0; /* Inactive state for DistSession */
    virtual void establishActiveInputs() = 0;   /* Established state for DistSession */
    virtual void activateOutput() = 0;          /* Active state for DistSession */
    virtual void deactivateOutput() = 0;        /* Deactivating state for DistSession */

private:
    DistributionSession &m_distributionSession;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_CONTROLLER_HH_ */
