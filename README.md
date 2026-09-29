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
| **Implements** | [3GPP TS 29.581 V18.6.0](https://www.3gpp.org/DynaReport/29581.htm), the interfaces designated as Nmb2, Nmb8 and Nmb9 |
| **Part of** | [5G Multicast Broadcast Services (MBS)](https://www.5g-mag.com/reference-tools/5g-mbs/), alongside [open5gs](https://github.com/5G-MAG/open5gs), [rt-5gc-service-consumers](https://github.com/5G-MAG/rt-5gc-service-consumers), [rt-libflute](https://github.com/5G-MAG/rt-libflute), [rt-mbs-application](https://github.com/5G-MAG/rt-mbs-application), [rt-mbs-application-provider](https://github.com/5G-MAG/rt-mbs-application-provider), [rt-mbs-client](https://github.com/5G-MAG/rt-mbs-client), [rt-mbs-examples](https://github.com/5G-MAG/rt-mbs-examples), [rt-mbs-function](https://github.com/5G-MAG/rt-mbs-function), [rt-media-origin](https://github.com/5G-MAG/rt-media-origin), [rt-srsRAN_Project](https://github.com/5G-MAG/rt-srsRAN_Project), [srsRAN_4G](https://github.com/5G-MAG/srsRAN_4G), [srsRAN_4G_mbs](https://github.com/5G-MAG/srsRAN_4G_mbs) and [srsRAN_Project_mbs](https://github.com/5G-MAG/srsRAN_Project_mbs) |

## Introduction

The MBS Transport Function is the network function of the MBS User Services that ingests content
and sends it out for multicast and broadcast delivery. The MBS Function
([rt-mbs-function](https://github.com/5G-MAG/rt-mbs-function)) controls it through Nmbstf
distribution sessions. It ingests objects, by pull or push, or packets, and uses
[rt-libflute](https://github.com/5G-MAG/rt-libflute) to send objects over FLUTE on the MBS session
the MBS Function has established, broadcast or multicast. Like the MBS Function, it is built as an
[Open5GS](https://open5gs.org/) network function that registers with a 5G Core NRF.

More information is on the [project page](https://www.5g-mag.com/reference-tools/5g-mbs/).

## Specification

Built against these versions:

- **3GPP TS 29.581 V18.6.0**, the Nmbstf distribution session API
- **3GPP TS 26.502 V18.6.0**, the MBS User Service architecture
- **3GPP TS 26.346 V18.2.0**, for the FLUTE and FDT profiling

The API bindings are generated at build time from the 3GPP 5G APIs, by default at tag `TSG111-Rel18`
(build options `fiveg_api_release` and `fiveg_api_approval` in `meson_options.txt`): the TS 29.581
Nmbstf distribution session API and the TS 26.517 object manifest model.

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

### The build fetches the 5G APIs

The OpenAPI bindings are generated at configure time from the 3GPP 5G APIs, which the build clones
from `forge.3gpp.org`. The build therefore needs network access to that host, and Java, which is
why `default-jdk` is in the list above.

That host currently serves an incomplete certificate chain: it sends its own certificate but not the
Sectigo intermediate that signs it. A browser fetches the missing intermediate by itself, but `git`
and `curl` do not, so the clone fails with:

```
fatal: unable to access 'https://forge.3gpp.org/rep/all/5G_APIs.git/':
  SSL certificate verification failed: certificate signer not trusted
```

If you see that, install the missing intermediate rather than disabling verification. On Debian and
Ubuntu, fetch *Sectigo Public Server Authentication CA OV R36* from <https://crt.sh/>, put the PEM in
`/usr/local/share/ca-certificates/` with a `.crt` extension, and run `sudo update-ca-certificates`.

## Downloading

Release tar files are available from <https://github.com/5G-MAG/rt-mbs-transport-function/releases>.

Alternatively, clone the repository with its submodules. The default branch holds the latest
release:

```bash
git clone --recurse-submodules https://github.com/5G-MAG/rt-mbs-transport-function.git
cd rt-mbs-transport-function
```

`--recurse-submodules` is required: `rt-common-shared` is a submodule and the build fails without
it. If you have already cloned without it, run `git submodule update --init --recursive`.

### 5G-MAG libraries fetched by the build

Two 5G-MAG libraries are fetched automatically. They are listed because a version mismatch shows up
as a compile or link error rather than as a missing dependency.

| Dependency | How | What it supplies |
|---|---|---|
| `rt-common-shared` | git submodule | the HTTP server and the shared Open5GS tooling, including the OpenAPI generator this build runs |
| `rt-libflute` | meson wrap | the FLUTE transmitter, the TS 26.346 annex L.6 profiled FDT schema, the scheme-specific FEC OTI and the RFC 5053 Raptor scheme |

## Building

The build needs a working Internet connection, because the API files are retrieved at build time.

To build the MBS Transport Function from source:

```bash
meson setup build
ninja -C build
```

Errors during `meson setup build` are usually caused by missing dependencies, or by a network problem
while retrieving the API files and the `openapi-generator` JAR file. The details are in
`build/meson-logs/meson-log.txt`; search it for `generator-mbstf` to find the start of the API fetch
sequence.

## Installing

To install the MBS Transport Function as a system process:

```bash
sudo meson install -C build --no-rebuild
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

## Configuration

The configuration is a YAML file in the Open5GS style, installed as
`/usr/local/etc/open5gs/mbstf.yaml`; when running from a build tree, pass it with `-c`. The sections
that matter are `nrf`, which must point at a reachable NRF, and the MBS Transport Function's own
section, which sets its SBI, distribution session API and ingest addresses.

## Development

This project follows the
[Gitflow workflow](https://www.atlassian.com/git/tutorials/comparing-workflows/gitflow-workflow). The
`development` branch is the integration branch for new features: switch to it before starting work on
a new feature.

### Unit tests (optional)

To run the unit tests:

```bash
meson test -C build --suite rt-mbs-transport-function
```

This builds the MBSTF if it is not already built, runs the unit tests and displays the results.

## Contributing

Contributions are welcome. How to raise an issue, fork the repository and open a pull request, and
the Contributor License Agreement required before code can be merged, are described at
<https://www.5g-mag.com/contributing>.

## License

Distributed under the 5G-MAG Public License v1.0. See [LICENSE](LICENSE).
