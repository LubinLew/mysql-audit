FROM alpine:latest

################################################################################

#RUN sed -i 's#dl-cdn.alpinelinux.org#mirrors.tuna.tsinghua.edu.cn#g' /etc/apk/repositories

# basic tools
RUN apk add git bash curl

# compiler
RUN apk add build-base cmake make bison flex autoconf automake

# static boost
RUN apk add boost1.82-static boost1.82-dev

# static dependency for GnuTLS
RUN apk add nettle-dev nettle-static

# static gcrypt
RUN apk add libgcrypt-dev libgcrypt-static libgpg-error-static

# static zlib
RUN apk add zlib-dev zlib-static

# static zstd
RUN apk add zstd-dev zstd-static

# tools for hyperscan
RUN apk add ragel python3

################################################################################
ARG INSTALL_PATH=/usr
ARG LIBPCAP_VERSION=master
ARG LIBTINS_VERSION=master
ARG JSON_VERSION=develop
ARG HYPERSCAN_VERSION=v5.4.2
ARG GNUTLS_VERSION=3.6.16
RUN mkdir /src && cd /src

## buil static libpcap
RUN git clone --depth 1 -b ${LIBPCAP_VERSION} https://github.com/the-tcpdump-group/libpcap.git && \
  cd libpcap &&              \ 
 ./autogen.sh &&             \
 ./configure                 \
    --prefix=${INSTALL_PATH} \
    --enable-shared=no       \
    --enable-usb=no          \
    --enable-netmap=no       \
    --enable-dbus=no         \
    --enable-bluetooth=no    \
    --without-libnl &&       \
  make && make install &&    \
  cd ../ && rm -rf libpcap


## build static libtins
RUN git clone --depth 1 -b ${LIBTINS_VERSION} https://github.com/mfontanini/libtins.git && \
  cd libtins && mkdir build && cd build && \
  cmake ..                       \
   -DCMAKE_BUILD_TYPE=MinSizeRel \
   -DLIBTINS_BUILD_SHARED=0      \
   -DLIBTINS_ENABLE_CXX11=1      \
   -DLIBTINS_ENABLE_WPA2=0       \
   -DLIBTINS_ENABLE_DOT11=0      \
   -DCMAKE_INSTALL_PREFIX=${INSTALL_PATH} && \
  make -j`nproc` && make install && \
  cd ../ && rm -rf libtins


## build static gnutls
RUN curl -Lko gnutls-${GNUTLS_VERSION}.tar.xz http://www.ring.gr.jp/pub/net/gnupg/gnutls/v3.6/gnutls-${GNUTLS_VERSION}.tar.xz && \
  tar xf gnutls-${GNUTLS_VERSION}.tar.xz && \
  cd gnutls-${GNUTLS_VERSION} &&    \
  ./configure                       \
    --prefix=${INSTALL_PATH}        \
    --disable-threads               \
    --disable-maintainer-mode       \
    --disable-bash-tests            \
    --disable-doc                   \
    --disable-tools                 \
    -disable-tls13-interop          \
    --enable-sha1-support           \
    --disable-ssl2-support          \
    --disable-dtls-srtp-support     \
    --disable-tests                 \
    --disable-rpath                 \
    --disable-full-test-suite       \
    --enable-static=yes             \
    --enable-shared=no              \
    --with-included-libtasn1        \
    --with-included-unistring       \
    --without-p11-kit               \
    --without-tpm                   \
    --disable-dhe                   \
    --disable-ecdhe                 \
    --disable-gost                  \
    --disable-ocsp &&               \
  make -j`nproc` && make install && \
  rm -rf gnutls-${GNUTLS_VERSION}


## hyperscan
RUN git clone --depth 1 -b ${HYPERSCAN_VERSION} https://github.com/intel/hyperscan.git && \
cd hyperscan && mkdir build && cd build &&    \
  cmake ..                                    \
    -DCMAKE_BUILD_TYPE=MinSizeRel             \
    -DBUILD_EXAMPLES=OFF                      \
    -DCMAKE_INSTALL_PREFIX=${INSTALL_PATH} && \
  make -j`nproc` && make install &&           \
  cd ../ && rm -rf hyperscan


## nlohmann::json
RUN git clone --depth 1 -b ${JSON_VERSION} https://github.com/nlohmann/json.git && \
  mv json/single_include/nlohmann ${INSTALL_PATH}/include && rm -rf json

################################################################################
