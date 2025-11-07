# License: 5G-MAG Public License (v1.0)
# Author(s): Dev Audsin <dev.audsin@bbc.co.uk>
# Copyright: (C) 2024 British Broadcasting Corporation
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

libuuid_dep=dependency('uuid', required:true)
test('test_object_store', 
    executable('testObjectStore', 'test_ObjectStore.cc', test_source_object_store, install:false, include_directories:[libmbstf_libinc, libinc], dependencies : [libmbstf_dep])
    ,verbose: true, timeout: 600, protocol: 'exitcode')

test('test_subscriber_subscription',
    executable('testSubscriberSubscription', 'test_SubscriberSubscription.cc', test_source_subscriber_subscription, install:false, include_directories:[libmbstf_libinc, libinc], dependencies : [libmbstf_dep])
    ,verbose: true, timeout: 600, protocol: 'exitcode')

#test('test_pull_object_ingester', 
#    executable('testPullObjectIngester', 'test_PullObjectIngester.cc', test_source_pull_object_ingester, install:false, include_directories:[libmbstf_libinc, libinc], dependencies : [libmbstf_dep])
#    ,verbose: true, timeout: 600, protocol: 'exitcode')

#test('test_object_list_packager', 
#    executable('testObjectListPackager', 'test_ObjectListPackager.cc', test_source_object_list_packager, install:false, include_directories:[libmbstf_libinc, libinc], dependencies : [libmbstf_dep, boost_dep, rt_libflute_dep, libuuid_dep])
#   ,verbose: true, timeout: 600, protocol: 'exitcode')
#test_object_store = executable('testObjectStore', 'test_ObjectStore.cc', test_source_object_store, install:false, include_directories:[libmbstf_libinc, libinc])
#test_object_store = executable('testObjectStore', 'test_ObjectStore.cc', test_source_object_store, install:false, include_directories:[libmbstf_libinc, libinc])
#test('run_test_object_store', executable('testObjectStore'))
