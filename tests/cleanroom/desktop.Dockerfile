# A fresh Ubuntu "desktop user" machine for the LabLink clean-room test:
# systemd (so `systemctl --user` works), a normal user with no Rust, no
# LabLink and no SSH client. Xvfb/xdotool/xwd only drive and capture the GUI.
ARG BASE=ubuntu:24.04
FROM ${BASE}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus dbus-user-session sudo bash-completion \
        ca-certificates iproute2 iputils-ping procps xvfb xdotool x11-apps libgl1-mesa-dri \
    && rm -rf /var/lib/apt/lists/* \
    && (userdel -r ubuntu 2>/dev/null || true) \
    && useradd -m -u 1000 -s /bin/bash tester \
    && mkdir -p /var/lib/systemd/linger && touch /var/lib/systemd/linger/tester \
    && systemctl mask getty.target console-getty.service 2>/dev/null || true
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
