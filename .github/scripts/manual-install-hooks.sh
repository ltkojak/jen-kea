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
            # "Edit it … only [jen_db] has to be right to start."
            sudo tee /etc/jen/jen.config > /dev/null <<'CONF'
[jen_db]
host     = 127.0.0.1
user     = jen
password = jen_pw
database = jen
[server]
http_port  = 5050
https_port = 8443
CONF
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
