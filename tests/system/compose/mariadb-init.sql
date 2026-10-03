-- Q84 — the two databases the stack needs: Jen's own, and the Kea-side one
-- Jen reads leases/reservations from (the tables Kea's own schema tool
-- would create — trimmed to the columns Jen queries, same as tests/conftest.py).
CREATE DATABASE IF NOT EXISTS jen;
CREATE DATABASE IF NOT EXISTS kea;
CREATE USER IF NOT EXISTS 'jen'@'%' IDENTIFIED BY 'jen_pw';
GRANT ALL PRIVILEGES ON jen.* TO 'jen'@'%';
CREATE USER IF NOT EXISTS 'kea'@'%' IDENTIFIED BY 'kea_pw';
GRANT ALL PRIVILEGES ON kea.* TO 'kea'@'%';
FLUSH PRIVILEGES;

USE kea;

-- v5.67.0-beta.13 (Q127) -- Kea's reservation schema as tests/conftest.py defines it (the same statements,
-- kept identical by tests/test_kea_test_schema.py): the real unique keys, the options' and IPv6
-- reservations' foreign keys to hosts, the lookup tables, schema_version.

CREATE TABLE IF NOT EXISTS host_identifier_type (
        type TINYINT NOT NULL,
        name VARCHAR(32) DEFAULT NULL,
        PRIMARY KEY (type)
    ) ENGINE=InnoDB;

INSERT IGNORE INTO host_identifier_type VALUES (0, 'hw-address'), (1, 'duid'), (2, 'circuit-id'), (3, 'client-id'), (4, 'flex-id');

CREATE TABLE IF NOT EXISTS dhcp_option_scope (
        scope_id TINYINT UNSIGNED NOT NULL,
        scope_name VARCHAR(32) DEFAULT NULL,
        PRIMARY KEY (scope_id)
    ) ENGINE=InnoDB;

INSERT IGNORE INTO dhcp_option_scope VALUES (0, 'global'), (1, 'subnet'), (2, 'client-class'), (3, 'host'), (4, 'shared-network'), (5, 'pool'), (6, 'pd-pool');

CREATE TABLE IF NOT EXISTS schema_version (
        version INT NOT NULL,
        minor INT DEFAULT NULL,
        PRIMARY KEY (version)
    ) ENGINE=InnoDB;

INSERT IGNORE INTO schema_version VALUES (35, 0);

CREATE TABLE IF NOT EXISTS lease4 (
        address INT UNSIGNED PRIMARY KEY NOT NULL,
        hwaddr VARBINARY(20),
        client_id VARBINARY(255),
        valid_lifetime INT UNSIGNED,
        expire TIMESTAMP NULL,
        subnet_id INT UNSIGNED,
        fqdn_fwd TINYINT(1) DEFAULT 0,
        fqdn_rev TINYINT(1) DEFAULT 0,
        hostname VARCHAR(255),
        state INT UNSIGNED DEFAULT 0,
        user_context TEXT
    );

CREATE TABLE IF NOT EXISTS hosts (
        host_id INT UNSIGNED NOT NULL AUTO_INCREMENT,
        dhcp_identifier VARBINARY(255) NOT NULL,
        dhcp_identifier_type TINYINT NOT NULL,
        dhcp4_subnet_id INT UNSIGNED DEFAULT NULL,
        dhcp6_subnet_id INT UNSIGNED DEFAULT NULL,
        ipv4_address INT UNSIGNED DEFAULT NULL,
        hostname VARCHAR(255) DEFAULT NULL,
        dhcp4_client_classes VARCHAR(255) DEFAULT NULL,
        dhcp6_client_classes VARCHAR(255) DEFAULT NULL,
        dhcp4_next_server INT UNSIGNED DEFAULT NULL,
        dhcp4_server_hostname VARCHAR(64) DEFAULT NULL,
        dhcp4_boot_file_name VARCHAR(128) DEFAULT NULL,
        user_context TEXT DEFAULT NULL,
        auth_key VARCHAR(32) DEFAULT NULL,
        PRIMARY KEY (host_id),
        UNIQUE KEY key_dhcp4_identifier_subnet_id (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id),
        UNIQUE KEY key_dhcp6_identifier_subnet_id (dhcp_identifier, dhcp_identifier_type, dhcp6_subnet_id),
        KEY fk_host_identifier_type (dhcp_identifier_type),
        KEY hosts_by_hostname (hostname),
        KEY key_dhcp4_ipv4_address_subnet_id_identifier (ipv4_address, dhcp4_subnet_id),
        CONSTRAINT fk_host_identifier_type FOREIGN KEY (dhcp_identifier_type) REFERENCES host_identifier_type (type)
    ) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS dhcp4_options (
        option_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        code TINYINT UNSIGNED NOT NULL,
        value BLOB DEFAULT NULL,
        formatted_value TEXT DEFAULT NULL,
        space VARCHAR(128) DEFAULT NULL,
        persistent TINYINT(1) NOT NULL DEFAULT 0,
        dhcp_client_class VARCHAR(128) DEFAULT NULL,
        dhcp4_subnet_id INT UNSIGNED DEFAULT NULL,
        host_id INT UNSIGNED DEFAULT NULL,
        scope_id TINYINT UNSIGNED NOT NULL,
        user_context TEXT DEFAULT NULL,
        shared_network_name VARCHAR(128) DEFAULT NULL,
        pool_id BIGINT UNSIGNED DEFAULT NULL,
        modification_ts TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        cancelled TINYINT(1) NOT NULL DEFAULT 0,
        client_classes LONGTEXT NOT NULL,
        PRIMARY KEY (option_id),
        UNIQUE KEY option_id_UNIQUE (option_id),
        KEY fk_options_host1_idx (host_id),
        KEY fk_dhcp4_option_scope (scope_id),
        CONSTRAINT fk_dhcp4_option_scope FOREIGN KEY (scope_id) REFERENCES dhcp_option_scope (scope_id),
        CONSTRAINT fk_dhcp4_options_Host FOREIGN KEY (host_id) REFERENCES hosts (host_id)
            ON DELETE CASCADE ON UPDATE CASCADE,
        CONSTRAINT fk_options_host1 FOREIGN KEY (host_id) REFERENCES hosts (host_id)
            ON DELETE NO ACTION ON UPDATE NO ACTION
    ) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS dhcp6_options (
        option_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        code SMALLINT UNSIGNED NOT NULL,
        value BLOB DEFAULT NULL,
        formatted_value TEXT DEFAULT NULL,
        space VARCHAR(128) DEFAULT NULL,
        persistent TINYINT(1) NOT NULL DEFAULT 0,
        dhcp_client_class VARCHAR(128) DEFAULT NULL,
        dhcp6_subnet_id INT UNSIGNED DEFAULT NULL,
        host_id INT UNSIGNED DEFAULT NULL,
        scope_id TINYINT UNSIGNED NOT NULL,
        user_context TEXT DEFAULT NULL,
        shared_network_name VARCHAR(128) DEFAULT NULL,
        pool_id BIGINT UNSIGNED DEFAULT NULL,
        pd_pool_id BIGINT UNSIGNED DEFAULT NULL,
        modification_ts TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        cancelled TINYINT(1) NOT NULL DEFAULT 0,
        client_classes LONGTEXT NOT NULL,
        PRIMARY KEY (option_id),
        UNIQUE KEY option_id_UNIQUE (option_id),
        KEY fk_options_host1_idx (host_id),
        KEY fk_dhcp6_option_scope (scope_id),
        CONSTRAINT fk_dhcp6_option_scope FOREIGN KEY (scope_id) REFERENCES dhcp_option_scope (scope_id),
        CONSTRAINT fk_dhcp6_options_Host FOREIGN KEY (host_id) REFERENCES hosts (host_id)
            ON DELETE CASCADE ON UPDATE CASCADE,
        CONSTRAINT fk_options_host10 FOREIGN KEY (host_id) REFERENCES hosts (host_id)
            ON DELETE NO ACTION ON UPDATE NO ACTION
    ) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS lease6 (
        address BINARY(16) PRIMARY KEY NOT NULL,
        duid VARBINARY(130),
        valid_lifetime INT UNSIGNED,
        expire TIMESTAMP NULL,
        subnet_id INT UNSIGNED,
        pref_lifetime INT UNSIGNED,
        lease_type TINYINT,
        iaid INT UNSIGNED,
        prefix_len TINYINT UNSIGNED,
        fqdn_fwd TINYINT(1) DEFAULT 0,
        fqdn_rev TINYINT(1) DEFAULT 0,
        hostname VARCHAR(255),
        hwaddr VARBINARY(20),
        hwtype SMALLINT UNSIGNED,
        hwaddr_source INT UNSIGNED,
        state INT UNSIGNED DEFAULT 0,
        user_context TEXT
    );

CREATE TABLE IF NOT EXISTS ipv6_reservations (
        reservation_id INT UNSIGNED NOT NULL AUTO_INCREMENT,
        address BINARY(16) NOT NULL,
        prefix_len TINYINT UNSIGNED NOT NULL DEFAULT 128,
        type TINYINT UNSIGNED NOT NULL DEFAULT 0,
        dhcp6_iaid INT UNSIGNED DEFAULT NULL,
        host_id INT UNSIGNED NOT NULL,
        excluded_prefix BINARY(16) DEFAULT NULL,
        excluded_prefix_len TINYINT UNSIGNED NOT NULL DEFAULT 0,
        PRIMARY KEY (reservation_id),
        KEY fk_ipv6_reservations_host_idx (host_id),
        KEY key_dhcp6_address_prefix_len (address, prefix_len),
        CONSTRAINT fk_ipv6_reservations_Host FOREIGN KEY (host_id) REFERENCES hosts (host_id)
            ON DELETE CASCADE ON UPDATE CASCADE
    ) ENGINE=InnoDB;
