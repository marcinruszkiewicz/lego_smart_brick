FROM --platform=linux/amd64 ubuntu:22.04

RUN apt-get update && apt-get install -y wget xz-utils && rm -rf /var/lib/apt/lists/*

RUN wget -q https://github.com/foss-for-synopsys-dwc-arc-processors/toolchain/releases/download/arc-2025.09-release/arc_gnu_2025.09_prebuilt_elf32_le_linux_install.tar.xz \
    -O /tmp/arc-toolchain.tar.xz && \
    mkdir -p /opt/arc && \
    tar xf /tmp/arc-toolchain.tar.xz -C /opt/arc --strip-components=1 && \
    rm /tmp/arc-toolchain.tar.xz

ENV PATH="/opt/arc/bin:${PATH}"

WORKDIR /work
