# Q84 — a Kea host as Jen sees one: kea-dhcp4 (ISC's own image, so the real
# daemon), sshd, sudo, python3 for the root helper, and a systemctl stand-in
# (there is no systemd in a container). The helper itself is NOT baked in:
# the harness installs it through Jen's own install_helper path, the one an
# operator's "Install helper" button uses.
ARG KEA_IMAGE=docker.cloudsmith.io/isc/docker/kea-dhcp4:3.0.3
FROM ${KEA_IMAGE}

USER root

# v5.66.0-beta.2 (Q104) - jen-kea-helper resolves EVERY binary it runs, including
# kea-dhcp4 itself for config-test, through a root-owned _BIN_DIRS allowlist, never
# $PATH. ISC's own image ships kea-dhcp4 owned by a dedicated "kea" service account
# (0754 - no execute for "other"), defense-in-depth for the daemon's OWN running
# process; a real Ubuntu/apt install puts the BINARY under root:root like any other
# package-installed file (dpkg extracts as root; it's the daemon's RUNTIME data
# directories that get a service-account owner, not /usr/sbin/kea-dhcp4 itself).
# Match that here rather than weakening the helper's own trust check to fit one
# container image's particular packaging choice.
RUN chown root:root /usr/sbin/kea-dhcp4 && chmod 755 /usr/sbin/kea-dhcp4

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
