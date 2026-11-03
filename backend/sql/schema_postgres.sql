-- =============================================================================
-- MÓDULO 6: CONTROL DE ACCESO EN PUERTAS (VALIDATOR APP) Y REGISTRO DE AUDITORÍA
-- Esquema para PostgreSQL
-- =============================================================================

CREATE TABLE IF NOT EXISTS pki_keys (
    id VARCHAR(64) PRIMARY KEY,
    curve VARCHAR(32) NOT NULL DEFAULT 'prime256v1', -- secp256r1 (NIST P-256)
    public_key_pem TEXT NOT NULL,
    private_key_pem TEXT NOT NULL,
    certificate_fingerprint VARCHAR(128) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS events (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    venue VARCHAR(255) NOT NULL,
    event_date TIMESTAMP WITH TIME ZONE NOT NULL,
    total_capacity INT NOT NULL DEFAULT 500,
    key_id VARCHAR(64) REFERENCES pki_keys(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tickets (
    ticket_id VARCHAR(64) PRIMARY KEY,
    event_id VARCHAR(64) NOT NULL REFERENCES events(id),
    section VARCHAR(64) NOT NULL,
    seat_row VARCHAR(16) NOT NULL,
    seat_number VARCHAR(16) NOT NULL,
    buyer_name VARCHAR(120) NOT NULL,
    buyer_hash VARCHAR(64) NOT NULL,          -- SHA-256(Identidad del comprador)
    session_secret VARCHAR(128) NOT NULL,     -- SK_session (256-bit hex) para QR Dinámico HMAC-SHA256
    payload_json TEXT NOT NULL,               -- JSON canónico firmado
    ecdsa_signature TEXT NOT NULL,            -- Firma ECDSA (secp256r1) en Base64URL
    status VARCHAR(32) NOT NULL DEFAULT 'ISSUED', -- ISSUED | USED | REVOKED
    used_at TIMESTAMP WITH TIME ZONE NULL,
    used_gate VARCHAR(64) NULL,
    last_totp_step BIGINT NULL,               -- Última ventana TOTP usada (anti-replay)
    issued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_ledger (
    block_index SERIAL PRIMARY KEY,
    timestamp_iso VARCHAR(64) NOT NULL,
    gate_id VARCHAR(64) NOT NULL,
    scanner_id VARCHAR(64) NOT NULL,
    ticket_id VARCHAR(64) NOT NULL,
    event_id VARCHAR(64) NOT NULL,
    section VARCHAR(64) NULL,
    seat_label VARCHAR(32) NULL,
    validation_result VARCHAR(32) NOT NULL,   -- VALID | REPLAY | FAKE | ALREADY_USED
    reason TEXT NOT NULL,
    ecdsa_valid BOOLEAN NOT NULL,
    hmac_valid BOOLEAN NOT NULL,
    totp_step BIGINT NULL,
    latency_ms NUMERIC(8, 2) NOT NULL,
    prev_hash CHAR(64) NOT NULL,              -- Hash SHA-256 del bloque anterior
    block_hash CHAR(64) NOT NULL UNIQUE       -- SHA-256(block_index || timestamp_iso || gate_id || ticket_id || validation_result || prev_hash)
);

CREATE INDEX IF NOT EXISTS idx_tickets_event_status ON tickets(event_id, status);
CREATE INDEX IF NOT EXISTS idx_audit_ledger_result ON audit_ledger(validation_result);

