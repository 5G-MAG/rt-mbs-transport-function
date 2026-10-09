<p align="center">
  <img src=".github/banner.svg" width="100%" alt="5G-MAG Reference Tools, 5G Multicast Broadcast Services: MBS Transport Function (MBSTF)">
</p>

<p align="center">
  The MBS Transport Function (MBSTF), the user-plane function that delivers MBS content as
  FLUTE object streams, per 3GPP TS 26.502 and TS 29.581.
</p>

<p align="center">
  <img alt="Status: under development"
    src="https://img.shields.io/badge/Status-Under_Development-yellow">
  <a href="https://github.com/5G-MAG/rt-mbs-transport-function/releases"><img alt="Version"
    src="https://img.shields.io/github/v/release/5G-MAG/rt-mbs-transport-function?label=Version&sort=semver"></a>
  <a href="LICENSE"><img alt="5G-MAG Public License v1.0"
    src="https://img.shields.io/badge/License-5G--MAG%20PL%20v1.0-blue"></a>
</p>

<p align="center">
  <a href="https://www.5g-mag.com/reference-tools/5g-multicast-broadcast-services">Project page</a> &nbsp;&middot;&nbsp;
  <a href="https://github.com/5G-MAG/rt-mbs-transport-function/issues">Issues</a> &nbsp;&middot;&nbsp;
  <a href="https://www.5g-mag.com/contributing">Contributing</a>
</p>

---

## At a glance

|  |  |
|---|---|
| **Implements** | 3GPP TS 26.502, *5G multicast-broadcast services; User Service architecture*, and TS 29.581, *Nmb8 service API* |
| **Role** | MBSTF: object ingest, FLUTE packaging, MBS delivery over the user plane |
| **Built with** | C++ and meson, on top of Open5GS |
| **Works with** | [rt-mbs-function](https://github.com/5G-MAG/rt-mbs-function) (MBSF), which drives it over Nmb8, and [rt-mbs-client](https://github.com/5G-MAG/rt-mbs-client) at the receiving end |
| **Part of** | [5G Multicast Broadcast Services](https://www.5g-mag.com/reference-tools/5g-multicast-broadcast-services) |

## Introduction

This repository provides the MBS Transport Function. It takes content by PULL or PUSH, packages it into
FLUTE object streams, and transmits them on the MBS session the MBSF has established, whether that
session is broadcast or multicast.

It is built on the [Open5GS](https://open5gs.org/) framework and registers with an NRF like any
other network function.

## Specification

Built against these versions, named rather than referred to by release:

- **3GPP TS 26.502 V18.6.0**, *5G multicast-broadcast services; User Service architecture*
- **3GPP TS 29.581 V18.6.0**, *Nmb8 service API*
- **3GPP TS 26.346 V18.2.0**, *MBMS protocols and codecs*, for the FLUTE and FDT profiling

Clause-by-clause coverage, and what is still absent, is recorded on the project page rather than
here: <https://www.5g-mag.com/reference-tools/5g-multicast-broadcast-services>

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

### The build fetches the 5G APIs

The OpenAPI bindings are generated at configure time from the 3GPP 5G APIs, which the build clones
from `forge.3gpp.org`. The build therefore needs network access to that host, and Java, which is
why `default-jdk` is in the list above.

That host currently serves an **incomplete certificate chain**: it sends its own certificate but
not the Sectigo intermediate that signs it. A browser fetches the missing intermediate by itself,
but `git` and `curl` do not, so the clone fails with:

```
fatal: unable to access 'https://forge.3gpp.org/rep/all/5G_APIs.git/':
  SSL certificate verification failed: certificate signer not trusted
```

If you see that, install the missing intermediate rather than disabling verification. On Debian
and Ubuntu, fetch *Sectigo Public Server Authentication CA OV R36* from
<https://crt.sh/>, put the PEM in `/usr/local/share/ca-certificates/` with a `.crt`
extension, and run `sudo update-ca-certificates`.

## Downloading

Release tar files can be downloaded from <https://github.com/5G-MAG/rt-mbs-transport-function/releases>.

The source can be obtained by cloning the github repository.

For example to download the latest release you can use:

```bash
git clone --recurse-submodules https://github.com/5G-MAG/rt-mbs-transport-function.git
cd rt-mbs-transport-function
```

`--recurse-submodules` is not optional: this repository carries `rt-common-shared` as a submodule
and the build fails without it. If you have already cloned without it, run
`git submodule update --init --recursive`.

## Dependencies

Two 5G-MAG libraries are pulled in by the build and fetched automatically. They are listed here
because a version mismatch surfaces as a compile or link error rather than as a missing
dependency.

| Dependency | How | What it supplies |
|---|---|---|
| `rt-common-shared` | git submodule | the HTTP server and the shared Open5GS tooling, including the OpenAPI generator this build runs |
| `rt-libflute` | meson wrap | the FLUTE transmitter, the TS 26.346 annex L.6 profiled FDT schema, the scheme-specific FEC OTI and the RFC 5053 Raptor scheme |

## Building

The build process requires a working Internet connection as the API files are retrieved at build time.

To build the 5G Data Collection Application Function from the source:

```bash
meson setup build
ninja -C build
```

**Note:** Errors during the `meson build` command are often caused by missing dependencies or a network issue while trying to retrieve the API files and `openapi-generator` JAR file. See the `build/meson-logs/meson-log.txt` log file for the errors in greater detail. Search for `generator-libspdc` to find the start of the API fetch sequence.

## Unit tests (optional)

There are some unit tests that can be run using:

```bash
meson test -C build --suite rt-mbs-transport-function
```

This will build the MBSTF (if not already built) and then will run the unit tests. The results of the testing are displayed.

## Installing

To install the built MBS Transport Function as a system process:

```bash
sudo meson install -C build --no-rebuild
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

## Configuration

Configuration is a YAML file in the Open5GS style, installed as
`/usr/local/etc/open5gs/mbstf.yaml` and passed with `-c` when running from a build tree. The
sections that matter are `nrf`, which must point at a reachable NRF, and the MBSTF's own SBI
address and the local address it sends FLUTE from.

## Development

This project follows
the [Gitflow workflow](https://www.atlassian.com/git/tutorials/comparing-workflows/gitflow-workflow). The
`development` branch of this project serves as an integration branch for new features. Consequently, please make sure to
switch to the `development` branch before starting the implementation of a new feature.

## Contributing

Contributions are welcome. How to raise an issue, fork the repository and open a pull request, and
the Contributor License Agreement required before code can be merged, are described at
<https://www.5g-mag.com/contributing>.

## License

See [LICENSE](LICENSE).
