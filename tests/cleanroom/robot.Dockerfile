# A lab machine to manage: OpenSSH server, user "robot" with a password
# (used once by `lablink copy-id`), fixed host keys baked into the image.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /bin/bash robot && echo 'robot:robot-pass-1' | chpasswd \
    && mkdir -p /run/sshd && ssh-keygen -A \
    && echo 'robot-bench' > /etc/hostname
CMD ["/usr/sbin/sshd", "-D", "-e"]
