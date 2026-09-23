# Keep filesystem construction independent of the host distribution. The base
# image, Debian snapshot, packages, and external e2fsdroid bytes are all fixed.
FROM docker.io/library/debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

ENV DEBIAN_FRONTEND=noninteractive
ARG DEBIAN_SNAPSHOT=20260716T110000Z
ARG E2FSPROGS_VERSION=1.47.0-2+b2
ARG FAKEROOT_VERSION=1.31-1.2
ARG PLATFORM_TOOLS_URL=https://dl.google.com/android/repository/platform-tools_r33.0.3-linux.zip
ARG PLATFORM_TOOLS_SHA256=ab885c20f1a9cb528eb145b9208f53540efa3d26258ac3ce4363570a0846f8f7
ARG E2FSDROID_SHA256=5acfcba27c1a362a9df97879100910d79014090c1ef999a7bc9d7a74998fa0b4

RUN sed -i \
      -e "s|http://deb.debian.org/debian-security|http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}|" \
      -e "s|http://deb.debian.org/debian|http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}|" \
      /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install --yes --no-install-recommends \
       ca-certificates \
       curl \
       e2fsprogs=${E2FSPROGS_VERSION} \
       fakeroot=${FAKEROOT_VERSION} \
       unzip \
    && test "$(dpkg-query -W e2fsprogs | cut -f2)" = "${E2FSPROGS_VERSION}" \
    && test "$(dpkg-query -W fakeroot | cut -f2)" = "${FAKEROOT_VERSION}" \
    && curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
       --retry 3 --connect-timeout 10 --max-time 300 \
       --output /tmp/platform-tools.zip "${PLATFORM_TOOLS_URL}" \
    && printf '%s  %s\n' "${PLATFORM_TOOLS_SHA256}" /tmp/platform-tools.zip \
       | sha256sum --check --strict \
    && unzip -q /tmp/platform-tools.zip platform-tools/e2fsdroid -d /tmp \
    && printf '%s  %s\n' "${E2FSDROID_SHA256}" /tmp/platform-tools/e2fsdroid \
       | sha256sum --check --strict \
    && install -m 0555 /tmp/platform-tools/e2fsdroid /usr/local/bin/e2fsdroid \
    && rm -rf \
       /tmp/platform-tools \
       /tmp/platform-tools.zip \
       /var/lib/apt/lists/* \
       /var/cache/apt/* \
       /var/log/apt/* \
       /var/log/alternatives.log \
       /var/log/dpkg.log

COPY scripts/build-rootfs-in-toolchain.sh /usr/local/bin/build-rootfs-in-toolchain
RUN chmod 0555 /usr/local/bin/build-rootfs-in-toolchain

ENTRYPOINT ["/usr/local/bin/build-rootfs-in-toolchain"]
