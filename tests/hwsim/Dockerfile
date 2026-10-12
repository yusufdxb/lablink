# Simulated-radio test image: real NetworkManager, wpa_supplicant, dnsmasq
# and polkit (Ubuntu 22.04, the release the Linux workstation runs), plus
# the tools the isolation tests need. Used by tests/hwsim/run.sh only.
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      network-manager wpasupplicant dnsmasq-base iptables iw iproute2 \
      iputils-ping isc-dhcp-client tcpdump socat dbus procps rfkill \
      ca-certificates kmod wireguard-tools dnsutils policykit-1 util-linux jq bc \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash fielduser
CMD ["sleep", "infinity"]
