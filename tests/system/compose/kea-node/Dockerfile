# Q84 — a Kea host as Jen sees one: kea-dhcp4 (ISC's own image, so the real
# daemon), sshd, sudo, python3 for the root helper, and a systemctl stand-in
# (there is no systemd in a container). The helper itself is NOT baked in:
# the harness installs it through Jen's own install_helper path, the one an
# operator's "Install helper" button uses.
ARG KEA_IMAGE=docker.cloudsmith.io/isc/docker/kea-dhcp4:3.0.3
FROM ${KEA_IMAGE}

USER root

# v5.68.0-beta.6 (Q141) - the Kea binary keeps the ownership ISC's image gives it, ON PURPOSE.
# Until now this file chowned /usr/sbin/kea-dhcp4 to root:root so the helper's "every binary it runs is
# root-owned" check would pass, asserting that "a real Ubuntu/apt install puts the BINARY under root:root".
# That was never checked against ISC's packages - the ones Jen targets (Kea 3.0+) - and it is not what
# they ship: ISC's deb installs /usr/sbin/kea-dhcp4 as _kea:_kea 0750 (the maintainer's Kea 3.0.4 host),
# and this image's own service account owns it the same way. The test host was altered to fit the check,
# so the suite never saw that every config push through the helper failed on such a host
# ("kea-dhcp4 is not installed") from helper build 7 (v5.66.0-beta.2) until build 10 runs `kea-dhcpX -t`
# as the daemon's own account. When a fixture has to be changed for a check to pass, the change is a claim
# about production: verify it against a real target first. tests/kea_compat records the owner and run-as
# user per ISC image (`binary_facts`) so the suite goes red the day ISC changes it.

# openssh-keygen: v5.66.0 (Q103) - the helper's own signed `update` op runs
# `ssh-keygen -Y verify` on this host; Alpine's `openssh` meta-package doesn't
# always pull in the keygen binary on its own, so it's named explicitly.
RUN apk add --no-cache openssh openssh-keygen sudo python3 bash

# The SSH account Jen logs in as. A locked account (`!` in shadow) is
# refused by sshd even for key auth, so give it a throwaway unusable password.
RUN adduser -D -s /bin/sh keaadmin \
 && echo "keaadmin:$(head -c 24 /dev/urandom | base64)" | chpasswd \
 && mkdir -p /home/keaadmin/.ssh /run/sshd /var/log/kea /var/lib/kea /var/run/kea /usr/local/sbin \
 && chown -R keaadmin:keaadmin /home/keaadmin/.ssh \
 && chmod 700 /home/keaadmin/.ssh

# sudo: the ONLY grant a Kea host needs for the helper is added by the helper
# installer itself. The legacy `python3` grant below is the one the installer
# rides on the first time (exactly like a host that hasn't been migrated yet);
# the harness removes it again after the install, the way Settings -> Kea does.
RUN printf '%s\n' 'Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"' >> /etc/sudoers \
 && { grep -q 'includedir /etc/sudoers.d' /etc/sudoers || echo '@includedir /etc/sudoers.d' >> /etc/sudoers; } \
 && mkdir -p /etc/sudoers.d \
 && printf '%s\n' 'keaadmin ALL=(root) NOPASSWD: /usr/bin/python3' > /etc/sudoers.d/jen-kea \
 && chmod 440 /etc/sudoers.d/jen-kea

RUN printf '%s\n' \
      'PasswordAuthentication no' \
      'PubkeyAuthentication yes' \
      'PermitRootLogin no' \
      'AllowUsers keaadmin' >> /etc/ssh/sshd_config

COPY systemctl /usr/local/bin/systemctl
COPY keactl /usr/local/bin/keactl
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /usr/local/bin/systemctl /usr/local/bin/keactl /entrypoint.sh

EXPOSE 22 8004
ENTRYPOINT ["/entrypoint.sh"]
