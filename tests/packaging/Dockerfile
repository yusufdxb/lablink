FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 procps dbus xvfb xauth xdotool openssh-client libgl1 libegl1 \
    libxkbcommon0 libxkbcommon-x11-0 libx11-6 libx11-xcb1 libxcursor1 \
    libxrandr2 libxi6 libwayland-client0 libwayland-egl1 \
    && rm -rf /var/lib/apt/lists/* \
    && (userdel -r ubuntu 2>/dev/null || true) \
    && useradd -m -u 1000 -s /bin/bash tester
