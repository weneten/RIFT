#!/bin/sh
set -eu
# Keep directories root-owned until setup finishes; DAC_OVERRIDE is disabled.
install -d -m 0750 /home/rift-sftp
install -d -m 0700 /home/rift-sftp/.ssh
install -m 0600 /run/test_authorized_keys /home/rift-sftp/.ssh/authorized_keys
chown rift-sftp:rift-sftp /home/rift-sftp/.ssh/authorized_keys
chown rift-sftp:rift-sftp /home/rift-sftp/.ssh
chown rift-sftp:rift-sftp /home/rift-sftp
install -d -m 0755 /run/sshd
ssh-keygen -q -t ed25519 -N '' -f /run/sshd/ssh_host_ed25519_key
exec /usr/sbin/sshd -D -e \
  -o HostKey=/run/sshd/ssh_host_ed25519_key \
  -o Port=2222 \
  -o PidFile=/run/sshd.pid \
  -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no \
  -o PubkeyAuthentication=yes \
  -o PermitRootLogin=no \
  -o StrictModes=yes \
  -o UsePAM=no \
  -o LogLevel=VERBOSE
