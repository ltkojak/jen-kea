# The stand-ins for the steps docs/manual-install.md tells a HUMAN to do — v5.67.0-beta.10 (Q122).
#
# tools/doc_commands.py turns the page's runnable blocks into one script and puts
# `ci_hook NAME` wherever the page says to do something by hand. This file defines
# those. Each one does what the page says, with this job's own values, and nothing
# the page does not say: a hook that quietly did MORE would let the page be wrong.
# The names are checked against the page's by tests/test_doc_commands.py.

ci_hook() {
    case "$1" in
        enter-tree)
            # "tar xzf jen-vX.Y.Z.tar.gz && cd jen" — the checkout IS the extracted tree.
            cd "$GITHUB_WORKSPACE"
            ;;
        edit-config)
            # "Edit it … only the [jen_db] values have to be real: leave the Kea values blank."
            # Edits the copy the page just made (the example's own sections stay), so the page's
            # claim is tested against the real file shape, not a hand-written minimal one.
            sudo sed -i \
                -e 's|^host     = YOUR-DB-SERVER|host     = 127.0.0.1|' \
                -e 's|^password = your-jen-db-password|password = jen_pw|' \
                -e 's|^api_url  = http://YOUR-KEA-SERVER:8000|api_url  =|' \
                -e 's|^api_pass = your-kea-api-password|api_pass =|' \
                -e 's|^host     = YOUR-KEA-SERVER|host     =|' \
                -e 's|^password = your-kea-db-password|password =|' \
                -e 's|^user     = your-ssh-user|user     =|' \
                -e 's|^dns_provider = technitium|dns_provider = none|' \
                -e 's|^api_url      = https://your-technitium-server/api|api_url      =|' \
                -e 's|^api_token    = your-technitium-api-token|api_token    =|' \
                -e 's|^forward_zone = your.domain.com|forward_zone =|' \
                /etc/jen/jen.config
            # a placeholder left behind (outside a comment) is a hook that quietly did less than the page
            # tells a human to do
            if grep -q '^[^#]*\(YOUR-\|your-\|your\.\)' /etc/jen/jen.config; then
                echo "::error::the stand-in left a placeholder in jen.config:"
                grep -n '^[^#]*\(YOUR-\|your-\|your\.\)' /etc/jen/jen.config
                exit 1
            fi
            ;;
        create-db)
            # The page's SQL block, with this job's password.
            mysql -h 127.0.0.1 -u root -pci_root_pw -e "
                CREATE DATABASE jen;
                CREATE USER 'jen'@'%' IDENTIFIED BY 'jen_pw';
                GRANT ALL PRIVILEGES ON jen.* TO 'jen'@'%';
                FLUSH PRIVILEGES;"
            ;;
        *)
            echo "::error::no stand-in for the page's hook '$1'"
            exit 1
            ;;
    esac
}
