ARG CROSS_BASE_IMAGE
ARG CROSS_DEB_ARCH
FROM $CROSS_BASE_IMAGE

ARG CROSS_DEB_ARCH
RUN dpkg --add-architecture ${CROSS_DEB_ARCH} && \
    apt-get -y update && \
    apt-get install -y pkg-config \
    # dependencies required to build libsecccomp-rs
    libseccomp-dev:${CROSS_DEB_ARCH} \
    # dependencies required to build libbpf-sys
    libelf-dev:${CROSS_DEB_ARCH} \
    zlib1g-dev:${CROSS_DEB_ARCH} \
    # dependencies to build wasmedge-sys
    libzstd-dev:${CROSS_DEB_ARCH} \
    libfmt-dev:${CROSS_DEB_ARCH}

COPY hack/busctl.sh /bin/busctl
RUN chmod +x /bin/busctl
