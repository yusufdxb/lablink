# A lab machine to manage: OpenSSH server, user "robot" with a password
# (used once by `lablink copy-id`), fixed synthetic host keys (hostkeys/, see
# its README: the GUI test's layout depends on the fingerprints).
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /bin/bash robot && echo 'robot:robot-pass-1' | chpasswd \
    && mkdir -p /run/sshd \
    && echo 'robot-bench' > /etc/hostname
COPY hostkeys/ssh_host_* /etc/ssh/
RUN chmod 600 /etc/ssh/ssh_host_*_key && chmod 644 /etc/ssh/ssh_host_*.pub
CMD ["/usr/sbin/sshd", "-D", "-e"]
