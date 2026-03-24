#ifndef _MBS_TF_CONTROLLER_FACTORY_HH_
#define _MBS_TF_CONTROLLER_FACTORY_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Session Controller Factory
 ******************************************************************************
 * Copyright: (C)2025 British Broadcasting Corporation
 * Author(s): David Waring <david.waring2@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include "common.hh"

MBSTF_NAMESPACE_START

class Controller;
class DistributionSession;

class ControllerFactoryConstructor {
public:
    virtual unsigned int priority() = 0;
    virtual Controller *makeController(DistributionSession &distributionSession) = 0;
};

template <class C>
class ControllerConstructor : public ControllerFactoryConstructor {
public:
    using controller = C;

    virtual unsigned int priority() { return controller::factoryPriority(); };
    virtual Controller *makeController(DistributionSession &distributionSession) {
        return new controller(distributionSession);
    }
};

class ControllerFactory {
public:
    static bool registerController(ControllerFactoryConstructor *controller_constructor);
    static Controller *makeController(DistributionSession &distributionSession);
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_CONTROLLER_FACTORY_HH_ */
