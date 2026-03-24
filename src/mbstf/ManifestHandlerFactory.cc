/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: Manifest Handler Factory
 ******************************************************************************
 * Copyright: (C)2025-2026 British Broadcasting Corporation
 * Author(s): David Waring <david.waring2@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include <algorithm>
#include <exception>
#include <list>
#include <memory>

#include "common.hh"
#include "ObjectStore.hh"

#include "ManifestHandlerFactory.hh"

MBSTF_NAMESPACE_START

namespace {
    static struct ManifestHandlerConstructorCompare {
        bool operator()(const std::unique_ptr<ManifestHandlerConstructor> &a, const std::unique_ptr<ManifestHandlerConstructor> &b)
        {
            return (a->priority() > b->priority());
        };
    } g_factoryCompare;

    static std::map<std::string, std::list<std::unique_ptr<ManifestHandlerConstructor> > > &constructorsByContentType()
    {
         static std::map<std::string, std::list<std::unique_ptr<ManifestHandlerConstructor> > > g_constructorsByContentType;
         return g_constructorsByContentType;
    }
}

bool ManifestHandlerFactory::registerManifestHandler(const std::string &content_type, ManifestHandlerConstructor *manifest_handler_constructor)
{
    // Find the prioritised list for the content_type, make new list of one doesn't exist
    std::list<std::unique_ptr<ManifestHandlerConstructor> > &list = constructorsByContentType()[content_type];
    // Make the value to store in the list (take ownership of manifest_handler_constructor)
    std::unique_ptr<ManifestHandlerConstructor> cc(manifest_handler_constructor);
    // Add the ManifestHandlerConstructor to the list in priority order
    list.insert(std::lower_bound(list.begin(), list.end(), cc, g_factoryCompare), std::move(cc));

    return true;
}

ManifestHandler *ManifestHandlerFactory::makeManifestHandler(const std::shared_ptr<ObjectStore::Object> &object, ObjectController *controller, bool pull_distribution)
{
    std::string media_type = object->second.mediaType();
    ogs_debug("Looking for manifest handler for \"%s\" media", media_type.c_str());
    // Try manifest handlers for the media type of the object, fallback to any media type (empty string)
    while (true) {
        auto it = constructorsByContentType().find(media_type);
        if (it != constructorsByContentType().end()) {
            std::list<std::unique_ptr<ManifestHandlerConstructor> > &list = it->second;
            ogs_debug("Trying %zi manifest handlers", list.size());
            for (const auto &mhc : list) {
                try {
                    return mhc->makeManifestHandler(object, controller, pull_distribution);
                } catch (std::runtime_error &ex) {
                    // manifest recognised but there was a parsing error, rethrow so caller can handle
                    throw ex;
                } catch (std::exception &ex) {
                    // That manifest handler couldn't handle that Object, let's try the next
                }
            }
        }
        if (media_type.empty()) break;
        media_type.clear();
    }
    return nullptr;
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
