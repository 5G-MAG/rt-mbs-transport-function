<p align="center">
  <img src=".github/banner.svg" width="100%" alt="Reference Tools · 5G Multicast Broadcast Services (MBS): MBS Transport Function (MBSTF)">
</p>

<p align="center">
  An MBS Transport Function (MBSTF) for the 5G MBS User Services, providing the Nmb2, Nmb8 and Nmb9
  interfaces specified in 3GPP TS 29.581 V18.5.0.
</p>

<p align="center">
  <img alt="Status: Under Development"
    src="https://img.shields.io/badge/Status-Under%20Development-e67e22">
  <a href="https://github.com/5G-MAG/rt-mbs-transport-function/releases"><img alt="Version"
    src="https://img.shields.io/github/v/release/5G-MAG/rt-mbs-transport-function?label=Version"></a>
  <a href="LICENSE"><img alt="License: 5G-MAG Public License v1.0"
    src="https://img.shields.io/badge/License-5G--MAG%20PL%20v1.0-blue"></a>
</p>

<p align="center">
  <a href="https://www.5g-mag.com/reference-tools/5g-mbs/">Project page</a> &nbsp;&middot;&nbsp;
  <a href="https://github.com/5G-MAG/rt-mbs-transport-function/issues">Issues</a> &nbsp;&middot;&nbsp;
  <a href="https://www.5g-mag.com/contributing">Contributing</a>
</p>

---

## At a glance

|  |  |
|---|---|
| **Implements** | [3GPP TS 29.581 V18.5.0](https://www.3gpp.org/DynaReport/29581.htm), the interfaces designated as Nmb2, Nmb8 and Nmb9 |
| **Part of** | [5G Multicast Broadcast Services (MBS)](https://www.5g-mag.com/reference-tools/5g-mbs/), alongside [open5gs](https://github.com/5G-MAG/open5gs), [rt-5gc-service-consumers](https://github.com/5G-MAG/rt-5gc-service-consumers), [rt-libflute](https://github.com/5G-MAG/rt-libflute), [rt-mbs-application](https://github.com/5G-MAG/rt-mbs-application), [rt-mbs-application-provider](https://github.com/5G-MAG/rt-mbs-application-provider), [rt-mbs-client](https://github.com/5G-MAG/rt-mbs-client), [rt-mbs-examples](https://github.com/5G-MAG/rt-mbs-examples), [rt-mbs-function](https://github.com/5G-MAG/rt-mbs-function), [rt-media-origin](https://github.com/5G-MAG/rt-media-origin), [rt-srsRAN_Project](https://github.com/5G-MAG/rt-srsRAN_Project), [srsRAN_4G](https://github.com/5G-MAG/srsRAN_4G), [srsRAN_4G_mbs](https://github.com/5G-MAG/srsRAN_4G_mbs) and [srsRAN_Project_mbs](https://github.com/5G-MAG/srsRAN_Project_mbs) |

## Introduction

The MBS Transport Function is the network function of the MBS User Services that ingests content
and sends it out for multicast and broadcast delivery. The MBS Function
([rt-mbs-function](https://github.com/5G-MAG/rt-mbs-function)) controls it through Nmbstf
distribution sessions. It ingests objects, by pull or push, or packets, and uses
[rt-libflute](https://github.com/5G-MAG/rt-libflute) to send objects over FLUTE. Like the MBS
Function, it is built as an [Open5GS](https://open5gs.org/) network function that registers with a
5G Core NRF.

More information is on the [project page](https://www.5g-mag.com/reference-tools/5g-mbs/).

## Specification

Built against 3GPP TS 29.581 V18.5.0. The API bindings are generated at build time from the 3GPP 5G
APIs, by default at tag `TSG111-Rel18` (build options `fiveg_api_release` and `fiveg_api_approval`
in `meson_options.txt`): the TS 29.581 Nmbstf distribution session API and the TS 26.517 object
manifest model.

Clause-by-clause coverage, and what is still absent, is recorded on the project page rather than
here: <https://www.5g-mag.com/reference-tools/5g-mbs/>

## Install dependencies

Use a Linux distribution with GCC 14 or later (for example Ubuntu 24.04 or later): this release
needs C++ features first implemented in GCC 14.

On Ubuntu 24.04, these commands install the dependencies, make GCC 14 the default compiler and
install Meson with `pip`:

```bash
sudo add-apt-repository universe
sudo apt update
sudo apt install git ninja-build build-essential flex bison libglibmm-2.4-dev libsctp-dev libgnutls28-dev libgcrypt-dev libssl-dev libidn11-dev libmongoc-dev libbson-dev libyaml-dev libnghttp2-dev libmicrohttpd-dev libcurl4-gnutls-dev libtins-dev libtalloc-dev libpcre2-dev libboost-system-dev libboost-thread-dev libboost-program-options-dev libboost-test-dev libspdlog-dev libtinyxml2-dev libconfig++-dev uuid-dev libxml2-dev gcc-14 g++-14 curl wget default-jdk cmake jq util-linux-extra mm-common python3-pip
sudo sh -c 'for i in cpp g++ gcc gcc-ar gcc-nm gcc-ranlib gcov gcov-dump gcov-tool lto-dump; do rm -f /usr/bin/$i; ln -s $i-14 /usr/bin/$i; done'
sudo python3 -m pip install --break-system-packages --upgrade meson
```

## Downloading

Release tar files are available from <https://github.com/5G-MAG/rt-mbs-transport-function/releases>.

Alternatively, clone the repository with its submodules. The default branch holds the latest
release:

```bash
cd ~
git clone --recurse-submodules https://github.com/5G-MAG/rt-mbs-transport-function.git
```

## Building

The build needs a working Internet connection, because the API files are retrieved at build time.

To build the MBS Transport Function from source:

```bash
cd ~/rt-mbs-transport-function
meson build
ninja -C build
```

Errors during `meson build` are usually caused by missing dependencies, or by a network problem while
retrieving the API files and the `openapi-generator` JAR file. The details are in
`~/rt-mbs-transport-function/build/meson-logs/meson-log.txt`; search it for `generator-libspdc` to
find the start of the API fetch sequence.

## Installing

To install the MBS Transport Function as a system process:

```bash
cd ~/rt-mbs-transport-function/build
sudo meson install --no-rebuild
```

## Running

The MBS Transport Function needs a running 5G Core NRF to register with. If you do not have a 5G
Core, the installation also installs the [Open5GS](https://open5gs.org/) network functions, and you
can start the Open5GS NRF with:

```bash
sudo /usr/local/bin/open5gs-nrfd &
```

Set the IP address and port of your NRF in the `nrf` section of `/usr/local/etc/open5gs/mbstf.yaml`,
then start the MBS Transport Function, for example:

```bash
sudo /usr/local/bin/open5gs-mbstfd &
```

## Development

This project follows the
[Gitflow workflow](https://www.atlassian.com/git/tutorials/comparing-workflows/gitflow-workflow). The
`development` branch is the integration branch for new features: switch to it before starting work on
a new feature.

### Unit tests (optional)

To run the unit tests:

```bash
cd ~/rt-mbs-transport-function
meson test -C build --suite rt-mbs-transport-function
```

This builds the MBSTF if it is not already built, runs the unit tests and displays the results.

## Contributing

Contributions are welcome. How to raise an issue, fork the repository and open a pull request, and
the Contributor License Agreement required before code can be merged, are described at
<https://www.5g-mag.com/contributing>.

## License

Distributed under the 5G-MAG Public License v1.0. See [LICENSE](LICENSE).
