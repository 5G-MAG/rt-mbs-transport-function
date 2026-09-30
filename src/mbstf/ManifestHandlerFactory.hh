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
#include "Open5GSYamlIter.hh"

MBSTF_NAMESPACE_START

class ManifestHandler;
class ObjectController;

/* Which operating modes a manifest handler serves. A controller asks the factory only for handlers
   suited to its mode, rather than checking the handler it was given afterwards. OBJECT_COLLECTION
   uses the carousel handlers: TS 26.502 V18.6.0 table 6.1-1, NOTE: "OBJECT_COLLECTION operating mode
   is a special case of OBJECT_CAROUSEL operating mode". */
enum ManifestHandlerSuitability : unsigned int {
    SUITABLE_FOR_STREAMING = 0x1,
    SUITABLE_FOR_CAROUSEL  = 0x2
};

class ManifestHandlerConstructor {
public:
    virtual ~ManifestHandlerConstructor() {};
    virtual unsigned int priority() = 0;
    /* The manifest type this constructor makes handlers for; the same pointer as the handlers'
       manifestHandlerType(), so types are told apart by pointer. */
    virtual const char *manifestHandlerType() const = 0;
    unsigned int suitability() const { return m_suitability; };
    void suitability(unsigned int flags) { m_suitability = flags; };
    virtual ManifestHandler *makeManifestHandler(const std::shared_ptr<ObjectStore::Object> &object, ObjectController *controller,
                                                 bool pull_distribution) = 0;
    virtual bool parseConfiguration(const std::string &section_name, Open5GSYamlIter &iter) = 0;
    virtual void tidyConfiguration() = 0;
private:
    unsigned int m_suitability = 0;
};

template <class H>
class ManifestHandlerConstructorClass : public ManifestHandlerConstructor {
public:
    using manifest_handler = H;

    virtual unsigned int priority() { return manifest_handler::factoryPriority(); };
    virtual const char *manifestHandlerType() const { return manifest_handler::manifestHandlerTypeName(); };
    virtual ManifestHandler *makeManifestHandler(const std::shared_ptr<ObjectStore::Object> &object, ObjectController *controller,
                                                 bool pull_distribution) {
        return new manifest_handler(object, controller, pull_distribution);
    }
    virtual bool parseConfiguration(const std::string &section_name, Open5GSYamlIter &iter) {
        return H::parseConfiguration(section_name, iter);
    }
    virtual void tidyConfiguration() {
        H::tidyConfiguration();
    }
};

class ManifestHandlerFactory {
public:
    static bool registerManifestHandler(const std::string &content_type, ManifestHandlerConstructor *manifest_handler_constructor,
                                        unsigned int suitability);
    /* Only handlers registered with at least one of the suitability flags are tried. */
    static ManifestHandler *makeManifestHandler(const std::shared_ptr<ObjectStore::Object> &object, ObjectController *controller,
                                                bool pull_distribution, unsigned int suitability);
    /* How many different manifest types are registered with one of the suitability flags; several
       registrations of one handler (one per content type spelling) count once. */
    static size_t numberOfManifestHandlerTypes(unsigned int suitability);
    static bool parseConfiguration(const std::string &section_name, Open5GSYamlIter &iter);
    static void tidyConfigurations();
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_MANIFEST_HANDLER_FACTORY_HH_ */
