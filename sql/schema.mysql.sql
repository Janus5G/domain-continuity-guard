CREATE TABLE dcg_domains (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(253) NOT NULL,
    status ENUM('active','pending_reverification','continuity_failed','transferred_or_new_owner','locked') NOT NULL DEFAULT 'active',
    current_epoch BIGINT UNSIGNED NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_domain (domain)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE dcg_domain_epochs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    domain_id BIGINT UNSIGNED NOT NULL,
    epoch BIGINT UNSIGNED NOT NULL,
    public_key_base64 TEXT NOT NULL,
    public_key_fingerprint CHAR(64) NOT NULL,
    verification_method ENUM('dns_txt','dnssec_dns_txt','manual','imported') NOT NULL DEFAULT 'dns_txt',
    first_verified_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_continuity_check_at DATETIME NULL,
    status ENUM('active','superseded','locked') NOT NULL DEFAULT 'active',
    UNIQUE KEY uniq_domain_epoch (domain_id, epoch),
    UNIQUE KEY uniq_domain_fingerprint (domain_id, public_key_fingerprint),
    CONSTRAINT fk_dcg_epoch_domain FOREIGN KEY (domain_id) REFERENCES dcg_domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE dcg_challenges (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(253) NOT NULL,
    purpose ENUM('dns_verify','continuity_proof') NOT NULL,
    token_hash CHAR(64) NOT NULL,
    expires_at DATETIME NOT NULL,
    consumed_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_domain_purpose (domain, purpose),
    KEY idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Example mapping table for your own users/mailboxes/accounts.
-- Your application may already have something similar.
CREATE TABLE dcg_account_bindings (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    external_account_id VARCHAR(191) NOT NULL,
    email VARCHAR(320) NOT NULL,
    domain VARCHAR(253) NOT NULL,
    domain_epoch BIGINT UNSIGNED NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_external_account (external_account_id),
    KEY idx_email (email),
    KEY idx_domain_epoch (domain, domain_epoch)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
