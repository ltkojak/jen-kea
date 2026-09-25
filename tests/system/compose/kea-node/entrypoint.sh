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
/usr/sbin/sshd
/usr/local/bin/keactl start || echo "entrypoint: kea-dhcp4 did not start (see /var/log/kea/kea-dhcp4.stdout)" >&2

exec tail -f /dev/null
