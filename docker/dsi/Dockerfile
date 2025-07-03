FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
 git ninja-build build-essential flex bison libglibmm-2.4-dev libsctp-dev libgnutls28-dev libgcrypt-dev libssl-dev libidn11-dev libmongoc-dev libbson-dev libyaml-dev libnghttp2-dev libmicrohttpd-dev libcurl4-gnutls-dev libtins-dev libtalloc-dev libpcre2-dev libboost-system-dev libboost-thread-dev libboost-program-options-dev libboost-test-dev libspdlog-dev libtinyxml2-dev libconfig++-dev uuid-dev libxml2-dev gcc-14 g++-14 curl wget default-jdk cmake jq util-linux-extra mm-common python3-pip

# Set GCC 14 as default
RUN for i in cpp g++ gcc gcc-ar gcc-nm gcc-ranlib gcov gcov-dump gcov-tool lto-dump; do \
      rm -f /usr/bin/$i; ln -s $i-14 /usr/bin/$i; \
    done

# Upgrade meson
RUN python3 -m pip install --break-system-packages --upgrade meson

WORKDIR /rt-mbs-transport-function
COPY . .

# Build
RUN meson setup --prefix /usr --sysconfdir /etc --localstatedir /var build && ninja -C build

# Unit tests
RUN meson test -C build --suite rt-mbs-transport-function

# Install
RUN meson install -C build --no-rebuild
RUN ldconfig

CMD ["/usr/bin/open5gs-mbstfd"]
