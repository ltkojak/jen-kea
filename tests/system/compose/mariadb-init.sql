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

CREATE TABLE IF NOT EXISTS lease4 (
    address INT UNSIGNED PRIMARY KEY NOT NULL,
    hwaddr VARBINARY(20),
    client_id VARBINARY(128),
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
    host_id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    dhcp_identifier VARBINARY(128) NOT NULL,
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
    user_context TEXT,
    auth_key VARCHAR(16) DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS dhcp4_options (
    option_id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    code SMALLINT UNSIGNED NOT NULL,
    value BLOB,
    formatted_value TEXT,
    space VARCHAR(128),
    persistent TINYINT(1) NOT NULL DEFAULT 0,
    dhcp_client_class VARCHAR(128) DEFAULT NULL,
    dhcp4_subnet_id INT UNSIGNED DEFAULT NULL,
    host_id INT UNSIGNED DEFAULT NULL,
    scope_id TINYINT UNSIGNED NOT NULL DEFAULT 0
);
