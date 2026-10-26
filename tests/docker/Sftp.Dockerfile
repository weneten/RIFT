FROM debian:bookworm-slim
# Test-only account: passwords are disabled by sshd; public-key login needs an unlocked account.
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/sh rift-sftp \
    && passwd -d rift-sftp \
    && install -d -m 0755 /run/sshd \
    && rm -f /etc/ssh/ssh_host_*
COPY sftp-entrypoint.sh /usr/local/sbin/rift-sftp-entrypoint
RUN chmod 0755 /usr/local/sbin/rift-sftp-entrypoint
ENTRYPOINT ["/usr/local/sbin/rift-sftp-entrypoint"]
