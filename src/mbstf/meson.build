# License: 5G-MAG Public License (v1.0)
# Author(s): David Waring <david.waring2@bbc.co.uk>
#            Dev Audsin <dev.audsin@bbc.co.uk>
# Copyright: (C) 2024-2025 British Broadcasting Corporation
#
# Licensed under the License terms and conditions for use, reproduction, and
# distribution of 5G-MAG software (the “License”).  You may not use this file
# except in compliance with the License.  You may obtain a copy of the License
# at https://www.5g-mag.com/reference-tools.  Unless required by applicable
# law or agreed to in writing, software distributed under the License is
# distributed on an “AS IS” BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.

libapp_dep = open5gs_project.get_variable('libapp_dep')
libcrypt_dep = open5gs_project.get_variable('libcrypt_dep')
libsbi_dep = open5gs_project.get_variable('libsbi_dep')
libsbi_openapi_dep = open5gs_project.get_variable('libsbi_openapi_dep')
open5gs_sysconfdir = open5gs_project.get_variable('open5gs_sysconfdir')
srcinc = open5gs_project.get_variable('srcinc')
libdir = open5gs_project.get_variable('libdir')
python3_exe = open5gs_project.get_variable('python3_exe')
mkdir_p = open5gs_project.get_variable('mkdir_p')
install_conf = open5gs_project.get_variable('install_conf')
sbi_openapi_inc = open5gs_project.get_variable('libsbi_openapi_model_inc')
libinc = open5gs_project.get_variable('libinc')
app_type = 'MBSTF'

latest_apis = get_option('latest_apis')
fiveg_api_approval = get_option('fiveg_api_approval')
fiveg_api_release = get_option('fiveg_api_release')

fs = import('fs')

boost_dep = dependency('boost', required: true)
uuid_dep = dependency('uuid', required: true)
zlib_dep = dependency('zlib', required: true)
libmpdpp_dep = dependency('mpd++', fallback: ['libmpdpp'])

test_source_subscriber_subscription = files('''
  App.cc
  App.hh
  SubscriptionService.cc
  SubscriptionService.hh
  Subscriber.cc
  Subscriber.hh
  Event.cc
  Event.hh
  '''.split())

test_source_object_store = test_source_subscriber_subscription + files('''
  ObjectStore.cc
  ObjectStore.hh
  '''.split())


test_source_object_list_packager = test_source_object_store + files('''
  ObjectListController.cc
  ObjectListController.hh
  ObjectListPackager.cc
  ObjectListPackager.hh
  '''.split())

test_source_pull_object_ingester = test_source_object_store + files('''
  PullObjectIngester.cc
  PullObjectIngester.hh
  '''.split())

test_source_dash_manifest_handler = test_source_object_store + test_source_pull_object_ingester + files('''
  DASHManifestHandler.cc
  DASHManifestHandler.hh
  '''.split())


libmbstf_dist_sources = files('''
    BitRate.cc
    BitRate.hh
    common.cc
    common.hh
    CaseInsensitiveTraits.hh
    Context.cc
    Context.hh
    Controller.cc
    Controller.hh
    ControllerFactory.cc
    ControllerFactory.hh
    Curl.cc
    Curl.hh
    DASHManifestHandler.cc
    DASHManifestHandler.hh
    DistributionSession.cc
    DistributionSession.hh
    DistributionSessionEvents.cc
    DistributionSessionEvents.hh
    DistributionSessionNotificationEvent.cc
    DistributionSessionNotificationEvent.hh
    DistributionSessionSubscription.cc
    DistributionSessionSubscription.hh
    Event.cc
    Event.hh
    EventHandler.hh
    hash.hh
    LocalEvents.hh
    ManifestHandler.hh
    ManifestHandlerFactory.cc
    ManifestHandlerFactory.hh
    MBSTFEventHandler.cc
    MBSTFEventHandler.hh
    MBSTFNetworkFunction.hh
    NfServer.cc
    NfServer.hh
    ObjectController.cc
    ObjectController.cc
    ObjectListController.cc
    ObjectListController.hh
    ObjectManifestController.cc
    ObjectManifestController.hh
    ObjectStore.cc
    ObjectStore.hh
    ObjectStreamingController.cc
    ObjectStreamingController.hh
    ObjectIngester.cc
    ObjectIngester.hh
    ObjectPackager.cc
    ObjectPackager.hh
    ObjectListPackager.cc
    ObjectListPackager.hh
    Open5GSEvent.hh
    Open5GSFSM.hh
    Open5GSNetworkFunction.cc
    Open5GSNetworkFunction.hh
    Open5GSSBIClient.cc
    Open5GSSBIClient.hh
    Open5GSSBIMessage.cc
    Open5GSSBIMessage.hh
    Open5GSSBIRequest.cc
    Open5GSSBIRequest.hh
    Open5GSSBIResponse.cc
    Open5GSSBIResponse.hh
    Open5GSSBIServer.cc
    Open5GSSBIServer.hh
    Open5GSSBIStream.hh
    Open5GSSockAddr.hh
    Open5GSTimer.hh
    Open5GSYamlDocument.hh
    Open5GSYamlIter.cc
    Open5GSYamlIter.hh
    PullObjectIngester.cc
    PullObjectIngester.hh
    PushObjectIngester.cc
    PushObjectIngester.hh
    SubscriptionService.cc
    SubscriptionService.hh
    Subscriber.cc
    Subscriber.hh
    TimerFunc.hh
    utilities.cc
    utilities.hh
'''.split())

api_tag = latest_apis?'REL-'+fiveg_api_release:'TSG'+fiveg_api_approval+'-Rel'+fiveg_api_release

gen_5gmbstf_sh = find_program('sh')
openapi_dep_file = meson.current_source_dir() / '.openapi.srcs'
message('Generating OpenAPI bindings for version '+api_tag+' of the 5G APIs...')
openapi_gen_result = run_command([gen_5gmbstf_sh,'-c','"$MESON_SOURCE_ROOT/$MESON_SUBDIR/generator-mbstf" -M "'+openapi_dep_file+'" -b '+api_tag], capture: true, check: true)
libmbstf_openapi_gen_sources = files(fs.read(openapi_dep_file).split())

version_conf = configuration_data()
version_conf.set_quoted('MBSTF_NAME', meson.project_name())
version_conf.set_quoted('MBSTF_VERSION', meson.project_version())
version_conf.set_quoted('MBSTF_TYPE', app_type)
version_conf.set_quoted('FIVEG_API_RELEASE', fiveg_api_release)

libmbstf_gen_sources = [configure_file(output : 'mbstf-version.h', configuration : version_conf)]

libmbstf_sources = libmbstf_dist_sources + libmbstf_gen_sources + libmbstf_openapi_gen_sources

libmbstf_libinc = include_directories('.')
libmbstf_lib_openapiinc = include_directories('openapi/model')

libmbstf = static_library('mbstf',
    sources : libmbstf_sources,
    include_directories : [libmbstf_libinc, libmbstf_lib_openapiinc, sbi_openapi_inc, libinc],
    dependencies : [libsbi_dep,
                    libsbi_openapi_dep,
                    libapp_dep,
                    libcrypt_dep,
                    rt_libflute_dep,
                    boost_dep,
                    uuid_dep,
                    libmpdpp_dep],
    install : false)

libmbstf_dep = declare_dependency(
    link_with : libmbstf,
    dependencies : [libsbi_dep,
                    libsbi_openapi_dep,
                    libapp_dep,
                    libcrypt_dep,
                    rt_libflute_dep,
                    boost_dep,
                    uuid_dep,
                    libmpdpp_dep])
libmbstf_whole_dep = declare_dependency(
    link_whole : libmbstf,
    dependencies : [libsbi_dep,
                    libsbi_openapi_dep,
                    libapp_dep,
                    libcrypt_dep,
                    rt_libflute_dep,
                    boost_dep,
                    uuid_dep,
                    libmpdpp_dep])

mbstf_sources = files('''
    App.cc
    App.hh
'''.split()) + open5gs_project.get_variable('app_main_c')

mbstf_config_source = '''
    mbstf.yaml
'''.split()

mbstf_include = include_directories('.')

executable('open5gs-mbstfd',
    sources : mbstf_sources,
    c_args : '-DDEFAULT_CONFIG_FILENAME="@0@/mbstf.yaml"'.format(open5gs_sysconfdir),
    cpp_args : '-DDEFAULT_CONFIG_FILENAME="@0@/mbstf.yaml"'.format(open5gs_sysconfdir),
    include_directories : [srcinc ],
    dependencies : [libmbstf_whole_dep],
    install_rpath : libdir,
    install : true)

meson.add_install_script(python3_exe, '-c', mkdir_p.format(open5gs_sysconfdir))
conf_configuration = configuration_data()
foreach conf_file : mbstf_config_source
    gen = configure_file(input : conf_file + '.in', configuration : conf_configuration, output : conf_file)
    meson.add_install_script(python3_exe, '-c', install_conf.format(gen.full_path(), open5gs_sysconfdir))
endforeach
