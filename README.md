<h1 align="center">5G MBS User Services: MBS Transport Function</h1>
<p align="center">
  <img src="https://img.shields.io/github/v/tag/5G-MAG/rt-mbs-transport-function?label=version" alt="Version">
  <img src="https://img.shields.io/badge/Status-Under_Development-yellow" alt="Under Development">
  <img src="https://img.shields.io/badge/License-5G--MAG%20Public%20License%20(v1.0)-blue" alt="License">
</p>

## Introduction

This repository provides a 5G MBS Transport Function which forms part of the MBS User Services. This NF provides the interfaces designated as Nmb2, Nmb8 and Nmb9 in the [3GPP TS 29.581 V18.5.0](https://www.3gpp.org/DynaReport/29581.htm) specification.

Additional information can be found at: https://5g-mag.github.io/Getting-Started/pages/5g-multicast-broadcast-services/

## Install dependencies

Please use a linux distribution with GCC 14 or later (e.g. Ubuntu 24.04 or later) as this release requires C++ features that were initially implemented in GCC version 14.

For builds on Ubuntu 24.04, the following commands will ensure the dependencies and correct GCC version are available:
```bash
sudo add-apt-repository universe
sudo apt update
sudo apt install git ninja-build build-essential flex bison libglibmm-2.4-dev libsctp-dev libgnutls28-dev libgcrypt-dev libssl-dev libidn11-dev libmongoc-dev libbson-dev libyaml-dev libnghttp2-dev libmicrohttpd-dev libcurl4-gnutls-dev libtins-dev libtalloc-dev libpcre2-dev libboost-system-dev libboost-thread-dev libboost-program-options-dev libboost-test-dev libspdlog-dev libtinyxml2-dev libconfig++-dev uuid-dev libxml2-dev gcc-14 g++-14 curl wget default-jdk cmake jq util-linux-extra mm-common python3-pip
sudo sh -c 'for i in cpp g++ gcc gcc-ar gcc-nm gcc-ranlib gcov gcov-dump gcov-tool lto-dump; do rm -f /usr/bin/$i; ln -s $i-14 /usr/bin/$i; done'
sudo python3 -m pip install --break-system-packages --upgrade meson
```

## Downloading

Release tar files can be downloaded from <https://github.com/5G-MAG/rt-mbs-transport-function/releases>.

The source can be obtained by cloning the github repository.

For example to download the latest release you can use:

```bash
cd ~
git clone --recurse-submodules https://github.com/5G-MAG/rt-mbs-transport-function.git
```

## Building

The build process requires a working Internet connection as the API files are retrieved at build time.

To build the 5G Data Collection Application Function from the source:

```bash
cd ~/rt-mbs-transport-function
meson build
ninja -C build
```

**Note:** Errors during the `meson build` command are often caused by missing dependencies or a network issue while trying to retrieve the API files and `openapi-generator` JAR file. See the `~/rt-mbs-transport-function/build/meson-logs/meson-log.txt` log file for the errors in greater detail. Search for `generator-libspdc` to find the start of the API fetch sequence.

## Unit tests (optional)

There are some unit tests that can be run using:

```bash
cd ~/rt-mbs-transport-function
meson test -C build --suite rt-mbs-transport-function
```

This will build the MBSTF (if not already built) and then will run the unit tests. The results of the testing are displayed.

## Installing

To install the built MBS Transport Function as a system process:

```bash
cd ~/rt-mbs-transport-function/build
sudo meson install --no-rebuild
```

## Running

The MBS Transport Function requires a running 5G Core NRF Network Function to register with. If you do not have a running 5G Core, the [Open5GS](https://open5gs.org/) Network Functions are installed as part of the installation procedure and the Open5GS NRF can be started using:

```bash
sudo /usr/local/bin/open5gs-nrfd &
```

Make sure the IP address and port details of the NRF you are running are configured in the `nrf` section of `/usr/local/etc/open5gs/mbstf.yaml` and then run the MBS Transport Function. For example:

```bash
sudo /usr/local/bin/open5gs-mbstfd &
```

## Development

This project follows
the [Gitflow workflow](https://www.atlassian.com/git/tutorials/comparing-workflows/gitflow-workflow). The
`development` branch of this project serves as an integration branch for new features. Consequently, please make sure to
switch to the `development` branch before starting the implementation of a new feature.

