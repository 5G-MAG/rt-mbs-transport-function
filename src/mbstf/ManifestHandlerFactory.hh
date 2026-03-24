#ifndef _MBS_TF_MANIFEST_HANDLER_FACTORY_HH_
#define _MBS_TF_MANIFEST_HANDLER_FACTORY_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Manifest Handler Factory
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
#include "ObjectStore.hh"

MBSTF_NAMESPACE_START

class ManifestHandler;
class ObjectController;

class ManifestHandlerConstructor {
public:
    virtual unsigned int priority() = 0;
    virtual ManifestHandler *makeManifestHandler(const std::shared_ptr<ObjectStore::Object> &object, ObjectController *controller,
                                                 bool pull_distribution) = 0;
};

template <class H>
class ManifestHandlerConstructorClass : public ManifestHandlerConstructor {
public:
    using manifest_handler = H;

    virtual unsigned int priority() { return manifest_handler::factoryPriority(); };
    virtual ManifestHandler *makeManifestHandler(const std::shared_ptr<ObjectStore::Object> &object, ObjectController *controller,
                                                 bool pull_distribution) {
        return new manifest_handler(object, controller, pull_distribution);
    }
};

class ManifestHandlerFactory {
public:
    static bool registerManifestHandler(const std::string &content_type, ManifestHandlerConstructor *manifest_handler_constructor);
    static ManifestHandler *makeManifestHandler(const std::shared_ptr<ObjectStore::Object> &object, ObjectController *controller,
                                                bool pull_distribution);
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_MANIFEST_HANDLER_FACTORY_HH_ */
