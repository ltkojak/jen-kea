#!/bin/sh
# Q84 — boot a Kea "host": host keys, Jen's SSH key, sshd, then kea-dhcp4.
# PID 1 stays alive on its own so the scenarios can stop/start sshd and the
# daemon independently, the way they are independent services on a real host.
set -e

ssh-keygen -A >/dev/null
if [ -f /keys/jen_rsa.pub ]; then
  cp /keys/jen_rsa.pub /home/keaadmin/.ssh/authorized_keys
  chown keaadmin:keaadmin /home/keaadmin/.ssh/authorized_keys
  chmod 600 /home/keaadmin/.ssh/authorized_keys
fi

mkdir -p /var/log/kea /var/lib/kea /var/run/kea
# helper build 18 (Q170): the helper takes a control-socket credential only from a file root (or the daemon's account) owns, as the packages leave it on a real host. The bind-mounted
# /etc/kea is written by the CI user, so this node makes the two files root's - the stand-in for the ownership an install gives them.
chown root:root /etc/kea/jen-api.user /etc/kea/jen-api.pw 2>/dev/null || true
/usr/sbin/sshd
/usr/local/bin/keactl start || echo "entrypoint: kea-dhcp4 did not start (see /var/log/kea/kea-dhcp4.stdout)" >&2

exec tail -f /dev/null
