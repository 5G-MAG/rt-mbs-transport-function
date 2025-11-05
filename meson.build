# License: 5G-MAG Public License (v1.0)
# Copyright: (C) 2024-2025 British Broadcasting Corporation
# Author(s): David Waring <david.waring2@bbc.co.uk>
#            Dev Audsin <dev.audsin@bbc.co.uk>
#
# For full license terms please see the LICENSE file distributed with this
# program. If this file is missing then the license can be retrieved from
# https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view

# Meson module fs and its functions like fs.hash_file require atleast meson 0.59.0 

project('rt-mbs-transport-function', 'c', 'cpp', 
    version : '1.2.0',
    license : '5G-MAG Public',
    meson_version : '>= 1.4.0',
    default_options : [
        'c_std=gnu99',
        'cpp_std=gnu++20',
    ],
)

cplusplus = meson.get_compiler('cpp')
if not cplusplus.links('''#include <chrono>

int main(int argc, char *argv[])
{
  std::chrono::system_clock::time_point tmptime;
  std::chrono::parse("%Y", tmptime);
  return 0;
}
''', name: 'STL contains std::chrono::parse')
  error('std::chrono::parse function not found in STL, please use gcc 14.1 or later as the compiler')
endif

cmake=import('cmake')

open5gs_project=subproject('open5gs', required: true)

libflute_project=cmake.subproject('rt-libflute')
#message('rt-libflute CMake targets:\n - ' + '\n - '.join(libflute_project.target_list()))
rt_libflute_dep=libflute_project.dependency('flute')

#subdir('lib')
subdir('src')

#systemd_path_cmd = find_program('systemd-path', required: false)
#if systemd_path_cmd.found()
#  subdir('systemd')
#endif

subdir('tests')
