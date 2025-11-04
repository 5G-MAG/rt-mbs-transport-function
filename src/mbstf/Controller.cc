/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Controller
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

#include "Controller.hh"

MBSTF_NAMESPACE_START

Controller::Controller(DistributionSession &distributionSession)
    :SubscriptionService(), m_distributionSession(distributionSession)
{
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
