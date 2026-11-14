# Tools image of a swarmlabre run (`swarmlabre-tools`): REA + headless Ghidra + JDK 21 + JADX + Apktool.
# Build the base first: docker build -t swarmlabre-agent sandbox/   then: docker build -f sandbox/Dockerfile.re -t swarmlabre-tools sandbox/
# Arm64 only for now (amd64 support is not built yet): Ghidra ships decompiler natives for x86_64, so they are compiled here, on the same Debian release as the
# base image (a build on Ubuntu needs a newer glibc than bookworm has). Everything is fetched at build time and pinned; nothing at run time.

# --- stage: Ghidra decompiler/sleigh natives for linux_arm_64 (Makefile build, no Gradle) ---
FROM node:22-slim AS ghidra-natives
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates build-essential bison flex zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL -o /tmp/src.tgz https://github.com/NationalSecurityAgency/ghidra/archive/refs/tags/Ghidra_12.1.4_build.tar.gz \
    && echo "2a858300c350f05ae2e729dff86b4f584d0b9a6b398879c55025574e67696cec  /tmp/src.tgz" | sha256sum -c - \
    && mkdir /src && tar -xzf /tmp/src.tgz -C /src --strip-components=1 --wildcards '*/Ghidra/Features/Decompiler/src/decompile/*'
WORKDIR /src/Ghidra/Features/Decompiler/src/decompile/cpp
# ARCH_TYPE= overrides the Makefile's -m32 fallback on non-x86 machines
RUN mkdir -p ghi_opt sla_opt && make -j"$(nproc)" ARCH_TYPE= ghidra_opt sleigh_opt \
    && mkdir -p /natives && cp ghidra_opt /natives/decompile && cp sleigh_opt /natives/sleigh

# --- stage: Ghidra 12.1.4 release with those natives (REA's verified build) ---
FROM node:22-slim AS ghidra
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates unzip && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL -o /tmp/g.zip https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip \
    && echo "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db  /tmp/g.zip" | sha256sum -c - \
    && unzip -q /tmp/g.zip -d /opt && mv /opt/ghidra_12.1.4_PUBLIC /opt/ghidra && rm /tmp/g.zip \
    && mkdir -p /opt/ghidra/Ghidra/Features/Decompiler/os/linux_arm_64
COPY --from=ghidra-natives /natives/ /opt/ghidra/Ghidra/Features/Decompiler/os/linux_arm_64/
RUN chmod 755 /opt/ghidra/Ghidra/Features/Decompiler/os/linux_arm_64/*

# --- stage: JDK 21 (Ghidra and REA's Ghidra bridge need a full JDK, not a JRE) ---
FROM eclipse-temurin@sha256:3e3c176ffed168beb42c607be9bc1639b466cf00261a0fb04425562c9d0c5c2b AS jdk

# --- stage: Binwalk 3.1.0 (REA's verified build; region inspection only, so none of its extraction helpers are installed) ---
FROM rust@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS binwalk
RUN apt-get update && apt-get install -y --no-install-recommends libfontconfig1-dev liblzma-dev && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL -o /tmp/b.tgz https://github.com/ReFirmLabs/binwalk/archive/refs/tags/v3.1.0.tar.gz \
    && echo "06f595719417b70a592580258ed980237892eadc198e02363201abe6ca59e49a  /tmp/b.tgz" | sha256sum -c - \
    && mkdir /src && tar -xzf /tmp/b.tgz -C /src --strip-components=1
WORKDIR /src
RUN cargo build --release --locked && install -m 755 target/release/binwalk /binwalk

# --- stage: Android and capture tools, all checksum-pinned (JADX jar is the one REA audited; mitmdump is the standalone aarch64 build) ---
FROM node:22-slim AS tools
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*
RUN set -e; cd /tmp \
    && curl -fsSL -o jadx.jar https://github.com/1013503897/jadx-headless-mcp/releases/download/v0.7.1/jadx-headless-mcp-0.7.1-all.jar \
    && echo "6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75  jadx.jar" | sha256sum -c - \
    && curl -fsSL -o apktool.jar https://github.com/iBotPeaches/Apktool/releases/download/v3.0.3/apktool_3.0.3.jar \
    && echo "dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423  apktool.jar" | sha256sum -c - \
    && curl -fsSL -o mitm.tgz https://downloads.mitmproxy.org/12.2.3/mitmproxy-12.2.3-linux-aarch64.tar.gz \
    && echo "b358643a6c4f4b39e33d985350f660b724fece95687d7daa899ef0c4e211f681  mitm.tgz" | sha256sum -c - \
    && tar -xzf mitm.tgz mitmdump \
    && mkdir /out && mv jadx.jar apktool.jar mitmdump /out/

# --- final image: the base image (swarmlabre-agent) plus the reverse engineering tools ---
FROM swarmlabre-agent
# REA refuses to launch a child process without a procps `ps` on the PATH
# file and xxd: the skill and the profile prompt use them
RUN apt-get update && apt-get install -y --no-install-recommends procps file xxd && rm -rf /var/lib/apt/lists/* \
    && find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null; true
# profiles with `proxy = "socket"` have no network: this forwarder and entry script give pi a loopback URL for the model proxy's Unix socket
COPY sock-fwd.js /usr/local/lib/sock-fwd.js
COPY --chmod=755 swarmlabre-net-entry /usr/local/bin/swarmlabre-net-entry
# REA: lifecycle scripts off; the one analysis provider is the Ghidra below
RUN npm install -g --ignore-scripts rea-agents@6.4.0 \
    && rm -rf /usr/local/lib/node_modules/rea-agents/skills   # its bundled general skill assumes MCP and runtime capture; the profile mounts /skills/rea-reverse-engineering instead
COPY --from=jdk /opt/java/openjdk /opt/jdk
COPY --from=ghidra /opt/ghidra /opt/ghidra
ENV JAVA_HOME=/opt/jdk GHIDRA_INSTALL_DIR=/opt/ghidra REA_ANALYSIS_PROVIDER=ghidra PATH=/opt/jdk/bin:$PATH
# Android (JADX + Apktool), firmware region inspection (Binwalk) and saved mitmproxy captures (mitmdump); REA is told where each is by env
RUN apt-get update && apt-get install -y --no-install-recommends libfontconfig1 && rm -rf /var/lib/apt/lists/*
COPY --from=tools /out/jadx.jar /opt/android/jadx-headless-mcp.jar
COPY --from=tools /out/apktool.jar /opt/android/apktool.jar
COPY --from=tools /out/mitmdump /usr/local/bin/mitmdump
COPY --from=binwalk /binwalk /usr/local/bin/binwalk
RUN printf '#!/bin/sh\nexec java -jar /opt/android/apktool.jar "$@"\n' > /usr/local/bin/apktool && chmod 755 /usr/local/bin/apktool
ENV REA_JADX_MCP_JAR=/opt/android/jadx-headless-mcp.jar REA_APKTOOL_COMMAND=/usr/local/bin/apktool REA_BINWALK_COMMAND=/usr/local/bin/binwalk REA_MITMDUMP_COMMAND=/usr/local/bin/mitmdump
# Unpacking: the agent gets samples whose extension lies (a `.tgz` that is really 7z), so give it extractors for the usual containers.
# 7z reads 7z/zip/rar/cab/iso/wim/squashfs/cpio; bsdtar and unar are second opinions; the rest cover Windows installers, firmware and rpm.
# No unrar (non-free), no unblob (pip). Last layer on purpose, so adding a tool does not rebuild the layers above. setuid bits stripped again.
RUN apt-get update && apt-get install -y --no-install-recommends p7zip-full unzip zip libarchive-tools unar cabextract unshield innoextract msitools \
        squashfs-tools cpio zstd lz4 lzop rpm2cpio \
    && rm -rf /var/lib/apt/lists/* \
    && find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null; true
# rea gives Ghidra import + auto-analysis 330 s by default (config/ghidraStartupTimeout.js); a 2.5 MB PE with Git, curl and OpenSSL linked in
# exceeded it on the machine this was developed on (provider_timeout on every analyze/search/decompile). 25 min; the shell `timeout` does not change it.
ENV REA_GHIDRA_STARTUP_TIMEOUT_MS=1500000
