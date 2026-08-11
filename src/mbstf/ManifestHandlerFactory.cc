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
#include <cctype>
#include <exception>
#include <list>
#include <memory>
#include <vector>

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

    // A real Content-Type header can legitimately carry parameters (charset, profiles,
    // version, ...) after the base media type, but handlers register against exact literal
    // strings (e.g. "application/dash+xml") -- normalise (strip from the first ';', trim
    // trailing whitespace, lower-case) and try that too, so a header such as
    // "application/dash+xml; charset=utf-8" still finds its handler instead of falling all
    // the way through to the generic "any media type" bucket.
    std::string normalised = media_type;
    auto semi = normalised.find(';');
    if (semi != std::string::npos) normalised.erase(semi);
    while (!normalised.empty() && std::isspace(static_cast<unsigned char>(normalised.back()))) normalised.pop_back();
    std::transform(normalised.begin(), normalised.end(), normalised.begin(),
                    [](unsigned char c) { return std::tolower(c); });

    // Try, in order: the raw media type (so a handler that specifically registered a
    // parametrised key, e.g. ObjectManifestHandler's ";version=Rel17" variants, still takes
    // priority), the normalised bare media type, then any handler registered for "".
    std::vector<std::string> candidates{media_type};
    if (normalised != media_type) candidates.push_back(normalised);
    candidates.push_back("");

    for (const std::string &candidate : candidates) {
        auto it = constructorsByContentType().find(candidate);
        if (it == constructorsByContentType().end()) continue;
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
    return nullptr;
}

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
