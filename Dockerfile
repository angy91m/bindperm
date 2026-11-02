FROM debian:11
RUN sed -i 's/deb.debian.org/archive.debian.org/g' /etc/apt/sources.list && \
    sed -i 's/security.debian.org/archive.debian.org/g' /etc/apt/sources.list && \
    sed -i '/bullseye-updates/d' /etc/apt/sources.list
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential git make pkg-config ca-certificates wget gnupg lsb-release \
      software-properties-common libelf-dev zlib1g-dev libcap-dev
RUN wget -qO /tmp/llvm.sh https://apt.llvm.org/llvm.sh && bash /tmp/llvm.sh 16
RUN git clone --recurse-submodules --branch v7.5.0 https://github.com/libbpf/bpftool /src/bpftool \
 && make -C /src/bpftool/libbpf/src BUILD_STATIC_ONLY=y PREFIX=/opt/libbpf LIBDIR=/opt/libbpf/lib install \
 && make -C /src/bpftool/src install
WORKDIR /work