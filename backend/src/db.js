const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');
const mysql = require('mysql2/promise');
const {
  GENESIS_HASH,
  generatePkiKeyPair,
  canonicalizeTicketPayload,
  signTicketPayload,
  computeAuditBlockHash,
  hashBuyerIdentity,
} = require('./cryptoEngine');

const DATA_DIR = path.join(__dirname, '..', 'data');
const STORE_PATH = path.join(DATA_DIR, 'ledger_store.json');

class DatabaseManager {
  constructor() {
    this.mode = 'initializing'; // 'postgres' | 'mysql' | 'json-mirror'
    this.dbClientPref = (process.env.DB_CLIENT || 'postgres').toLowerCase();
    this.pgPool = null;
    this.mysqlPool = null;
    this.connectionError = null;
    this.state = {
      pkiKey: null,
      event: null,
      tickets: [],
      auditLedger: [],
      usedTotpNonces: {}, // { `${ticketId}:${totpStep}`: timestampIso }
    };
  }

  async init() {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }

    // 1. Load or initialize local state first so PKI keys & seed data exist consistently
    this.loadOrSeedLocalStore();

    // 2. Attempt connection to PostgreSQL or MySQL according to .env
    const dbHost = process.env.DB_HOST || '127.0.0.1';
    const dbUser = process.env.DB_USER || (this.dbClientPref === 'mysql' ? 'root' : 'postgres');
    const dbPassword = process.env.DB_PASSWORD || '';
    const dbName = process.env.DB_NAME || 'stc_modulo6';
    const dbPort = parseInt(
      process.env.DB_PORT || (this.dbClientPref === 'mysql' ? '3306' : '5432'),
      10
    );

    if (this.dbClientPref === 'mysql') {
      const connected = await this.tryConnectMySQL({ dbHost, dbPort, dbUser, dbPassword, dbName });
      if (!connected) {
        await this.tryConnectPostgres({
          dbHost,
          dbPort: 5432,
          dbUser: 'postgres',
          dbPassword,
          dbName,
        });
      }
    } else {
      const connected = await this.tryConnectPostgres({ dbHost, dbPort, dbUser, dbPassword, dbName });
      if (!connected) {
        await this.tryConnectMySQL({
          dbHost,
          dbPort: 3306,
          dbUser: 'root',
          dbPassword,
          dbName,
        });
      }
    }

    if (this.mode === 'initializing') {
      this.mode = 'sql-ready-mirror';
      console.log(
        `[DB] Ejecutando con persistencia transaccional local sincronizada (${STORE_PATH}). ` +
          `Configura DB_USER/DB_PASSWORD en backend/.env para conectar en vivo al servidor PostgreSQL/MySQL.`
      );
    }
  }

  async tryConnectPostgres({ dbHost, dbPort, dbUser, dbPassword, dbName }) {
    try {
      // Connect to default 'postgres' db first to ensure target database exists
      const adminPool = new Pool({
        host: dbHost,
        port: dbPort,
        user: dbUser,
        password: dbPassword,
        database: 'postgres',
        connectionTimeoutMillis: 2500,
      });
      const client = await adminPool.connect();
      const res = await client.query('SELECT 1 FROM pg_database WHERE datname = $1', [dbName]);
      if (res.rowCount === 0) {
        await client.query(`CREATE DATABASE ${dbName}`);
      }
      client.release();
      await adminPool.end();

      this.pgPool = new Pool({
        host: dbHost,
        port: dbPort,
        user: dbUser,
        password: dbPassword,
        database: dbName,
        connectionTimeoutMillis: 2500,
      });

      const schemaSql = fs.readFileSync(
        path.join(__dirname, '..', 'sql', 'schema_postgres.sql'),
        'utf8'
      );
      await this.pgPool.query(schemaSql);
      this.mode = 'postgres';
      this.connectionError = null;
      console.log(`[DB] Conectado exitosamente a PostgreSQL (${dbHost}:${dbPort}/${dbName})`);
      await this.syncMemoryToSql();
      return true;
    } catch (err) {
      this.connectionError = `PostgreSQL (${dbHost}:${dbPort}): ${err.message}`;
      if (this.pgPool) {
        await this.pgPool.end().catch(() => {});
        this.pgPool = null;
      }
      return false;
    }
  }

  async tryConnectMySQL({ dbHost, dbPort, dbUser, dbPassword, dbName }) {
    try {
      const adminConn = await mysql.createConnection({
        host: dbHost,
        port: dbPort,
        user: dbUser,
        password: dbPassword,
        connectTimeout: 2500,
        multipleStatements: true,
      });
      const schemaSql = fs.readFileSync(
        path.join(__dirname, '..', 'sql', 'schema_mysql.sql'),
        'utf8'
      );
      await adminConn.query(schemaSql);
      await adminConn.end();

      this.mysqlPool = mysql.createPool({
        host: dbHost,
        port: dbPort,
        user: dbUser,
        password: dbPassword,
        database: dbName,
        waitForConnections: true,
        connectionLimit: 10,
      });
      this.mode = 'mysql';
      this.connectionError = null;
      console.log(`[DB] Conectado exitosamente a MySQL (${dbHost}:${dbPort}/${dbName})`);
      await this.syncMemoryToSql();
      return true;
    } catch (err) {
      this.connectionError = `MySQL (${dbHost}:${dbPort}): ${err.message}`;
      if (this.mysqlPool) {
        await this.mysqlPool.end().catch(() => {});
        this.mysqlPool = null;
      }
      return false;
    }
  }

  loadOrSeedLocalStore() {
    if (fs.existsSync(STORE_PATH)) {
      try {
        const raw = fs.readFileSync(STORE_PATH, 'utf8');
        const parsed = JSON.parse(raw);
        if (parsed && parsed.pkiKey && parsed.event && Array.isArray(parsed.tickets)) {
          this.state = {
            usedTotpNonces: {},
            ...parsed,
          };
          return;
        }
      } catch (e) {
        console.warn('[DB] Regenerando store inicial:', e.message);
      }
    }
    this.seedInitialData();
  }

  seedInitialData() {
    const pkiKey = generatePkiKeyPair();
    const event = {
      id: 'EVT-AUD-2026-SYMPHONY',
      name: 'Concierto Magistral Cripto-Sinfónico 2026',
      venue: 'Gran Auditorio Nacional STC',
      eventDate: '2026-11-15T20:30:00-06:00',
      totalCapacity: 120,
      sections: {
        VIP: { capacity: 25, price: 2500 },
        Preferente: { capacity: 35, price: 1600 },
        General: { capacity: 40, price: 950 },
        Palcos: { capacity: 20, price: 3200 },
      },
      keyId: pkiKey.id,
    };

    const sampleBuyers = [
      { name: 'Ana Sofía Mendoza', email: 'ana.mendoza@stc.mx', section: 'VIP', row: 'A', seat: '01' },
      { name: 'Carlos Eduardo Ruiz', email: 'carlos.ruiz@stc.mx', section: 'VIP', row: 'A', seat: '02' },
      { name: 'Mariana Gómez Rivera', email: 'mariana.gomez@stc.mx', section: 'Preferente', row: 'B', seat: '14' },
      { name: 'Diego Alejandro Torres', email: 'diego.torres@stc.mx', section: 'Preferente', row: 'C', seat: '08' },
      { name: 'Valeria Hernández Cruz', email: 'valeria.hc@stc.mx', section: 'General', row: 'F', seat: '21' },
      { name: 'Roberto Sánchez Vega', email: 'roberto.sv@stc.mx', section: 'General', row: 'G', seat: '11' },
      { name: 'Fernanda Castillo Ortiz', email: 'fernanda.co@stc.mx', section: 'Palcos', row: 'P1', seat: '03' },
      { name: 'Luis Fernando Morales', email: 'luis.morales@stc.mx', section: 'VIP', row: 'A', seat: '05' },
    ];

    const issuedAt = new Date().toISOString();
    const tickets = sampleBuyers.map((buyer, idx) => {
      const ticketId = `TKT-2026-${String(idx + 1).padStart(4, '0')}`;
      const buyerHash = hashBuyerIdentity(buyer.email);
      const sessionSecret = crypto.randomBytes(32).toString('hex'); // 256-bit SK_session
      const payload = {
        ticketId,
        eventId: event.id,
        section: buyer.section,
        row: buyer.row,
        seat: buyer.seat,
        buyerHash,
        issuedAt,
      };
      const ecdsaSignature = signTicketPayload(payload, pkiKey.privateKeyPem);

      return {
        ticketId,
        eventId: event.id,
        section: buyer.section,
        row: buyer.row,
        seat: buyer.seat,
        buyerName: buyer.name,
        buyerEmail: buyer.email,
        buyerHash,
        sessionSecret,
        payloadJson: canonicalizeTicketPayload(payload),
        ecdsaSignature,
        status: 'ISSUED', // ISSUED | USED | REVOKED
        usedAt: null,
        usedGate: null,
        lastTotpStep: null,
        issuedAt,
      };
    });

    // Mark 1 ticket as already entered so the Audit Ledger starts with a Genesis + 1 real block
    const firstTicket = tickets[7]; // TKT-2026-0008
    const genesisTimestamp = new Date(Date.now() - 1000 * 180).toISOString();
    firstTicket.status = 'USED';
    firstTicket.usedAt = genesisTimestamp;
    firstTicket.usedGate = 'PUERTA-VIP-01';

    const firstBlock = {
      blockIndex: 1,
      timestampIso: genesisTimestamp,
      gateId: 'PUERTA-VIP-01',
      scannerId: 'SCANNER-TURNSTILE-01',
      ticketId: firstTicket.ticketId,
      eventId: event.id,
      section: firstTicket.section,
      seatLabel: `${firstTicket.row}-${firstTicket.seat}`,
      validationResult: 'VALID',
      reason: 'Firma ECDSA (secp256r1) verificada y ventana HMAC-SHA256 válida. Acceso concedido.',
      ecdsaValid: true,
      hmacValid: true,
      totpStep: Math.floor(Date.now() / 15000) - 12,
      latencyMs: 1.42,
      prevHash: GENESIS_HASH,
    };
    firstBlock.blockHash = computeAuditBlockHash(firstBlock);

    this.state = {
      pkiKey,
      event,
      tickets,
      auditLedger: [firstBlock],
      usedTotpNonces: {},
    };

    this.persistLocalStore();
  }

  persistLocalStore() {
    try {
      fs.writeFileSync(STORE_PATH, JSON.stringify(this.state, null, 2), 'utf8');
    } catch (e) {
      console.error('[DB] Error guardando store local:', e.message);
    }
  }

  async syncMemoryToSql() {
    try {
      const { pkiKey, event, tickets, auditLedger } = this.state;
      if (this.mode === 'postgres' && this.pgPool) {
        await this.pgPool.query(
          `INSERT INTO pki_keys (id, curve, public_key_pem, private_key_pem, certificate_fingerprint)
           VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO NOTHING`,
          [
            pkiKey.id,
            pkiKey.curve,
            pkiKey.publicKeyPem,
            pkiKey.privateKeyPem,
            pkiKey.certificateFingerprint,
          ]
        );
        await this.pgPool.query(
          `INSERT INTO events (id, name, venue, event_date, total_capacity, key_id)
           VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (id) DO NOTHING`,
          [event.id, event.name, event.venue, event.eventDate, event.totalCapacity, pkiKey.id]
        );
        for (const t of tickets) {
          await this.pgPool.query(
            `INSERT INTO tickets (ticket_id, event_id, section, seat_row, seat_number, buyer_name, buyer_hash, session_secret, payload_json, ecdsa_signature, status, used_at, used_gate, last_totp_step, issued_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
             ON CONFLICT (ticket_id) DO UPDATE SET status = EXCLUDED.status, used_at = EXCLUDED.used_at, used_gate = EXCLUDED.used_gate, last_totp_step = EXCLUDED.last_totp_step`,
            [
              t.ticketId,
              t.eventId,
              t.section,
              t.row,
              t.seat,
              t.buyerName,
              t.buyerHash,
              t.sessionSecret,
              t.payloadJson,
              t.ecdsaSignature,
              t.status,
              t.usedAt,
              t.usedGate,
              t.lastTotpStep,
              t.issuedAt,
            ]
          );
        }
        for (const b of auditLedger) {
          await this.pgPool.query(
            `INSERT INTO audit_ledger (block_index, timestamp_iso, gate_id, scanner_id, ticket_id, event_id, section, seat_label, validation_result, reason, ecdsa_valid, hmac_valid, totp_step, latency_ms, prev_hash, block_hash)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
             ON CONFLICT (block_hash) DO NOTHING`,
            [
              b.blockIndex,
              b.timestampIso,
              b.gateId,
              b.scannerId,
              b.ticketId,
              b.eventId,
              b.section,
              b.seatLabel,
              b.validationResult,
              b.reason,
              b.ecdsaValid,
              b.hmacValid,
              b.totpStep,
              b.latencyMs,
              b.prevHash,
              b.blockHash,
            ]
          );
        }
      } else if (this.mode === 'mysql' && this.mysqlPool) {
        await this.mysqlPool.query(
          `INSERT IGNORE INTO pki_keys (id, curve, public_key_pem, private_key_pem, certificate_fingerprint)
           VALUES (?, ?, ?, ?, ?)`,
          [
            pkiKey.id,
            pkiKey.curve,
            pkiKey.publicKeyPem,
            pkiKey.privateKeyPem,
            pkiKey.certificateFingerprint,
          ]
        );
        await this.mysqlPool.query(
          `INSERT IGNORE INTO events (id, name, venue, event_date, total_capacity, key_id)
           VALUES (?, ?, ?, ?, ?, ?)`,
          [event.id, event.name, event.venue, event.eventDate, event.totalCapacity, pkiKey.id]
        );
        for (const t of tickets) {
          await this.mysqlPool.query(
            `INSERT INTO tickets (ticket_id, event_id, section, seat_row, seat_number, buyer_name, buyer_hash, session_secret, payload_json, ecdsa_signature, status, used_at, used_gate, last_totp_step, issued_at)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
             ON DUPLICATE KEY UPDATE status = VALUES(status), used_at = VALUES(used_at), used_gate = VALUES(used_gate), last_totp_step = VALUES(last_totp_step)`,
            [
              t.ticketId,
              t.eventId,
              t.section,
              t.row,
              t.seat,
              t.buyerName,
              t.buyerHash,
              t.sessionSecret,
              t.payloadJson,
              t.ecdsaSignature,
              t.status,
              t.usedAt,
              t.usedGate,
              t.lastTotpStep,
              t.issuedAt,
            ]
          );
        }
        for (const b of auditLedger) {
          await this.mysqlPool.query(
            `INSERT IGNORE INTO audit_ledger (block_index, timestamp_iso, gate_id, scanner_id, ticket_id, event_id, section, seat_label, validation_result, reason, ecdsa_valid, hmac_valid, totp_step, latency_ms, prev_hash, block_hash)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
            [
              b.blockIndex,
              b.timestampIso,
              b.gateId,
              b.scannerId,
              b.ticketId,
              b.eventId,
              b.section,
              b.seatLabel,
              b.validationResult,
              b.reason,
              b.ecdsaValid,
              b.hmacValid,
              b.totpStep,
              b.latencyMs,
              b.prevHash,
              b.blockHash,
            ]
          );
        }
      }
    } catch (err) {
      console.error('[DB] Error sincronizando SQL:', err.message);
    }
  }

  getPkiInfo() {
    const { pkiKey } = this.state;
    return {
      id: pkiKey.id,
      curve: pkiKey.curve,
      publicKeyPem: pkiKey.publicKeyPem,
      certificateFingerprint: pkiKey.certificateFingerprint,
      dbEngine: this.mode,
      dbClientConfigured: this.dbClientPref,
      dbConnectionNotice: this.connectionError,
    };
  }

  getEvent() {
    return this.state.event;
  }

  getAllTickets() {
    return this.state.tickets;
  }

  getTicketById(ticketId) {
    return this.state.tickets.find((t) => t.ticketId === ticketId) || null;
  }

  async createTicket({ buyerName, buyerEmail, section = 'VIP', row = 'B', seat = '10' }) {
    const { pkiKey, event, tickets } = this.state;
    const nextNum = tickets.length + 1;
    const ticketId = `TKT-2026-${String(nextNum).padStart(4, '0')}`;
    const issuedAt = new Date().toISOString();
    const buyerHash = hashBuyerIdentity(buyerEmail || buyerName);
    const sessionSecret = crypto.randomBytes(32).toString('hex');

    const payload = {
      ticketId,
      eventId: event.id,
      section,
      row,
      seat,
      buyerHash,
      issuedAt,
    };
    const ecdsaSignature = signTicketPayload(payload, pkiKey.privateKeyPem);

    const newTicket = {
      ticketId,
      eventId: event.id,
      section,
      row,
      seat,
      buyerName,
      buyerEmail: buyerEmail || `${buyerName.toLowerCase().replace(/\s+/g, '.')}@stc.mx`,
      buyerHash,
      sessionSecret,
      payloadJson: canonicalizeTicketPayload(payload),
      ecdsaSignature,
      status: 'ISSUED',
      usedAt: null,
      usedGate: null,
      lastTotpStep: null,
      issuedAt,
    };

    this.state.tickets.unshift(newTicket);
    this.persistLocalStore();
    await this.syncMemoryToSql();
    return newTicket;
  }

  async markTicketUsed(ticketId, gateId, totpStep) {
    const ticket = this.getTicketById(ticketId);
    if (!ticket) return null;
    ticket.status = 'USED';
    ticket.usedAt = new Date().toISOString();
    ticket.usedGate = gateId;
    ticket.lastTotpStep = totpStep;
    this.state.usedTotpNonces[`${ticketId}:${totpStep}`] = ticket.usedAt;
    this.persistLocalStore();
    await this.syncMemoryToSql();
    return ticket;
  }

  async resetTicketStatus(ticketId) {
    const ticket = this.getTicketById(ticketId);
    if (!ticket) return null;
    ticket.status = 'ISSUED';
    ticket.usedAt = null;
    ticket.usedGate = null;
    ticket.lastTotpStep = null;
    this.persistLocalStore();
    await this.syncMemoryToSql();
    return ticket;
  }

  async resetAllTickets() {
    for (const t of this.state.tickets) {
      t.status = 'ISSUED';
      t.usedAt = null;
      t.usedGate = null;
      t.lastTotpStep = null;
    }
    this.state.usedTotpNonces = {};
    this.persistLocalStore();
    await this.syncMemoryToSql();
  }

  isTotpNonceUsed(ticketId, totpStep) {
    return Boolean(this.state.usedTotpNonces[`${ticketId}:${totpStep}`]);
  }

  async appendAuditBlock({
    gateId,
    scannerId,
    ticketId,
    eventId,
    section,
    seatLabel,
    validationResult,
    reason,
    ecdsaValid,
    hmacValid,
    totpStep,
    latencyMs,
  }) {
    const ledger = this.state.auditLedger;
    const prevBlock = ledger.length > 0 ? ledger[ledger.length - 1] : null;
    const blockIndex = prevBlock ? Number(prevBlock.blockIndex) + 1 : 1;
    const prevHash = prevBlock ? prevBlock.blockHash : GENESIS_HASH;
    const timestampIso = new Date().toISOString();

    const blockData = {
      blockIndex,
      timestampIso,
      gateId: gateId || 'PUERTA-NORTE-01',
      scannerId: scannerId || 'SCANNER-MOBILE-01',
      ticketId: ticketId || 'UNKNOWN',
      eventId: eventId || this.state.event.id,
      section: section || 'N/A',
      seatLabel: seatLabel || 'N/A',
      validationResult, // VALID | REPLAY | FAKE | ALREADY_USED
      reason,
      ecdsaValid: Boolean(ecdsaValid),
      hmacValid: Boolean(hmacValid),
      totpStep: totpStep !== undefined ? totpStep : null,
      latencyMs: Number(Number(latencyMs || 0).toFixed(2)),
      prevHash,
    };

    blockData.blockHash = computeAuditBlockHash(blockData);
    this.state.auditLedger.push(blockData);
    this.persistLocalStore();
    await this.syncMemoryToSql();
    return blockData;
  }

  getAuditLedger(limit = 100) {
    return [...this.state.auditLedger].reverse().slice(0, limit);
  }

  getRawLedgerChronological() {
    return [...this.state.auditLedger].sort((a, b) => a.blockIndex - b.blockIndex);
  }
}

module.exports = new DatabaseManager();

