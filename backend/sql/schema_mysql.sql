-- =============================================================================
-- MÓDULO 6: CONTROL DE ACCESO EN PUERTAS (VALIDATOR APP) Y REGISTRO DE AUDITORÍA
-- Esquema para MySQL 8.0+
-- =============================================================================

CREATE DATABASE IF NOT EXISTS stc_modulo6 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE stc_modulo6;

CREATE TABLE IF NOT EXISTS pki_keys (
    id VARCHAR(64) PRIMARY KEY,
    curve VARCHAR(32) NOT NULL DEFAULT 'prime256v1',
    public_key_pem TEXT NOT NULL,
    private_key_pem TEXT NOT NULL,
    certificate_fingerprint VARCHAR(128) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS events (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    venue VARCHAR(255) NOT NULL,
    event_date VARCHAR(64) NOT NULL,
    total_capacity INT NOT NULL DEFAULT 500,
    key_id VARCHAR(64),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (key_id) REFERENCES pki_keys(id)
);

CREATE TABLE IF NOT EXISTS tickets (
    ticket_id VARCHAR(64) PRIMARY KEY,
    event_id VARCHAR(64) NOT NULL,
    section VARCHAR(64) NOT NULL,
    seat_row VARCHAR(16) NOT NULL,
    seat_number VARCHAR(16) NOT NULL,
    buyer_name VARCHAR(120) NOT NULL,
    buyer_hash VARCHAR(64) NOT NULL,
    session_secret VARCHAR(128) NOT NULL,
    payload_json TEXT NOT NULL,
    ecdsa_signature TEXT NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ISSUED',
    used_at VARCHAR(64) NULL,
    used_gate VARCHAR(64) NULL,
    last_totp_step BIGINT NULL,
    issued_at VARCHAR(64) NOT NULL,
    FOREIGN KEY (event_id) REFERENCES events(id)
);

CREATE TABLE IF NOT EXISTS audit_ledger (
    block_index INT AUTO_INCREMENT PRIMARY KEY,
    timestamp_iso VARCHAR(64) NOT NULL,
    gate_id VARCHAR(64) NOT NULL,
    scanner_id VARCHAR(64) NOT NULL,
    ticket_id VARCHAR(64) NOT NULL,
    event_id VARCHAR(64) NOT NULL,
    section VARCHAR(64) NULL,
    seat_label VARCHAR(32) NULL,
    validation_result VARCHAR(32) NOT NULL,
    reason TEXT NOT NULL,
    ecdsa_valid BOOLEAN NOT NULL,
    hmac_valid BOOLEAN NOT NULL,
    totp_step BIGINT NULL,
    latency_ms DECIMAL(8, 2) NOT NULL,
    prev_hash CHAR(64) NOT NULL,
    block_hash CHAR(64) NOT NULL UNIQUE
);

