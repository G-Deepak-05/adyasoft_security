-- dashboard/db/schema.sql
-- Run this once against a fresh MySQL database on the dashboard's own
-- hosting account before deploying dashboard/public/.

CREATE TABLE accounts (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    name          VARCHAR(255) NOT NULL,
    api_key_hash  CHAR(64) NOT NULL,
    revoked_at    DATETIME NULL,
    created_at    DATETIME NOT NULL
);

CREATE TABLE users (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    username       VARCHAR(255) NOT NULL UNIQUE,
    password_hash  VARCHAR(255) NOT NULL,
    created_at     DATETIME NOT NULL
);

CREATE TABLE findings (
    id               BIGINT AUTO_INCREMENT PRIMARY KEY,
    account_id       INT NOT NULL,
    site_id          VARCHAR(12) NOT NULL,
    site_label       VARCHAR(255) NULL,
    scan_id          VARCHAR(64) NOT NULL,
    subject          VARCHAR(512) NOT NULL,
    severity         ENUM('CRITICAL','HIGH','MEDIUM','LOW') NOT NULL,
    composite_score  INT NOT NULL,
    finding_type     VARCHAR(64) NOT NULL,
    details          JSON NOT NULL,
    scanned_at       DATETIME NOT NULL,
    ingested_at      DATETIME NOT NULL,
    FOREIGN KEY (account_id) REFERENCES accounts(id),
    INDEX idx_account_severity (account_id, severity),
    INDEX idx_site (site_id),
    INDEX idx_type (finding_type),
    INDEX idx_scanned_at (scanned_at),
    UNIQUE INDEX idx_dedupe (account_id, scan_id, subject, finding_type)
);
