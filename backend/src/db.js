const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');
const mysql = require('mysql2/promise');
const {
  GENESIS_HASH,
  generatePkiKeyPair,
  exportPublicKeyJwk,
  importPublicKeyJwkToPem,
  canonicalizeTicketPayload,
  signTicketPayload,
  verifyTicketSignature,
  computeAuditBlockHash,
  hashBuyerIdentity,
} = require('./cryptoEngine');

const DATA_DIR = path.join(__dirname, '..', 'data');
const STORE_PATH = path.join(DATA_DIR, 'ledger_store.json');

class DatabaseManager {
  constructor() {
    this.mode = 'initializing'; // 'postgres' | 'mysql' | 'sql-ready-mirror'
    this.dbClientPref = (process.env.DB_CLIENT || 'postgres').toLowerCase();
    this.pgPool = null;
    this.mysqlPool = null;
    this.connectionError = null;
    this.state = {
      pkiKey: null,
      event: null,
      tickets: [],
      auditLedger: [],
      usedTotpNonces: {},
    };
  }

  async init() {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }

    this.loadOrSeedLocalStore();

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
        `[DB] Ejecutando con persistencia transaccional local sincronizada (${STORE_PATH}).`
      );
    }
  }

  async tryConnectPostgres({ dbHost, dbPort, dbUser, dbPassword, dbName }) {
    try {
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
          this.ensureM5CompatibilityMigration();
          return;
        }
      } catch (e) {
        console.warn('[DB] Regenerando store inicial:', e.message);
      }
    }
    this.seedInitialData();
  }

  /**
   * Asegura que la llave pública tenga su representación JWK y que todos los boletos
   * cuenten con skSession en Base64URL y firma ECDSA IEEE P1363 compatible con Módulo 5,
   * además de incluir el boleto de referencia BOL-001 del contrato de Módulo 5.
   */
  ensureM5CompatibilityMigration() {
    let changed = false;
    const { pkiKey, event, tickets } = this.state;

    if (!pkiKey.publicKeyJwk) {
      pkiKey.publicKeyJwk = exportPublicKeyJwk(pkiKey.publicKeyPem);
      changed = true;
    }

    const eventDateFormatted = '15/11/2026';

    for (const t of tickets) {
      // Convertir sessionSecret hex antiguo a Base64URL si aplica
      if (/^[0-9a-f]{64}$/i.test(t.sessionSecret)) {
        t.sessionSecret = Buffer.from(t.sessionSecret, 'hex').toString('base64url');
        changed = true;
      }
      // Verificar que el payload y la firma usen el contrato canónico IEEE P1363 (64 bytes)
      let parsedPayload = null;
      try {
        parsedPayload = JSON.parse(t.payloadJson);
      } catch (e) {}

      const sigBuf = Buffer.from(String(t.ecdsaSignature || ''), 'base64url');
      const validCurrent =
        parsedPayload &&
        sigBuf.length === 64 &&
        verifyTicketSignature(parsedPayload, t.ecdsaSignature, pkiKey.publicKeyPem);

      if (!validCurrent) {
        const walletPayload = {
          ticketId: t.ticketId,
          event: event.name,
          date: eventDateFormatted,
          seat: `${t.row}${t.seat}`,
          titular: t.buyerName,
        };
        t.payloadJson = canonicalizeTicketPayload(walletPayload);
        t.ecdsaSignature = signTicketPayload(walletPayload, pkiKey.privateKeyPem);
        changed = true;
      }
    }

    // Asegurar que exista BOL-001 (el ejemplo exacto del equipo de Módulo 5)
    if (!tickets.some((t) => t.ticketId === 'BOL-001')) {
      const issuedAt = new Date().toISOString();
      const bolPayload = {
        ticketId: 'BOL-001',
        event: event.name,
        date: eventDateFormatted,
        seat: 'A12',
        titular: 'Usuario de prueba (Módulo 5)',
      };
      tickets.unshift({
        ticketId: 'BOL-001',
        eventId: event.id,
        section: 'VIP',
        row: 'A',
        seat: '12',
        buyerName: 'Usuario de prueba (Módulo 5)',
        buyerEmail: 'wallet.m5@stc.mx',
        buyerHash: hashBuyerIdentity('wallet.m5@stc.mx'),
        sessionSecret: crypto.randomBytes(32).toString('base64url'),
        payloadJson: canonicalizeTicketPayload(bolPayload),
        ecdsaSignature: signTicketPayload(bolPayload, pkiKey.privateKeyPem),
        status: 'ISSUED',
        usedAt: null,
        usedGate: null,
        lastTotpStep: null,
        issuedAt,
      });
      changed = true;
    }

    if (changed) {
      this.persistLocalStore();
    }
  }

  seedInitialData() {
    const pkiKey = generatePkiKeyPair();
    const event = {
      id: 'EVT-AUD-2026-SYMPHONY',
      name: 'Concierto Magistral Cripto-Sinfónico 2026',
      venue: 'Gran Auditorio Nacional STC',
      eventDate: '2026-11-15T20:30:00-06:00',
      eventDateShort: '15/11/2026',
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
      { id: 'BOL-001', name: 'Usuario de prueba (Módulo 5)', email: 'wallet.m5@stc.mx', section: 'VIP', row: 'A', seat: '12' },
      { id: 'TKT-2026-0001', name: 'Ana Sofía Mendoza', email: 'ana.mendoza@stc.mx', section: 'VIP', row: 'A', seat: '01' },
      { id: 'TKT-2026-0002', name: 'Carlos Eduardo Ruiz', email: 'carlos.ruiz@stc.mx', section: 'VIP', row: 'A', seat: '02' },
      { id: 'TKT-2026-0003', name: 'Mariana Gómez Rivera', email: 'mariana.gomez@stc.mx', section: 'Preferente', row: 'B', seat: '14' },
      { id: 'TKT-2026-0004', name: 'Diego Alejandro Torres', email: 'diego.torres@stc.mx', section: 'Preferente', row: 'C', seat: '08' },
      { id: 'TKT-2026-0005', name: 'Valeria Hernández Cruz', email: 'valeria.hc@stc.mx', section: 'General', row: 'F', seat: '21' },
      { id: 'TKT-2026-0006', name: 'Roberto Sánchez Vega', email: 'roberto.sv@stc.mx', section: 'General', row: 'G', seat: '11' },
      { id: 'TKT-2026-0007', name: 'Fernanda Castillo Ortiz', email: 'fernanda.co@stc.mx', section: 'Palcos', row: 'P1', seat: '03' },
      { id: 'TKT-2026-0008', name: 'Luis Fernando Morales', email: 'luis.morales@stc.mx', section: 'VIP', row: 'A', seat: '05' },
    ];

    const issuedAt = new Date().toISOString();
    const tickets = sampleBuyers.map((buyer) => {
      const ticketId = buyer.id;
      const buyerHash = hashBuyerIdentity(buyer.email);
      const sessionSecret = crypto.randomBytes(32).toString('base64url'); // Base64URL SK_session (Módulo 5)
      const walletPayload = {
        ticketId,
        event: event.name,
        date: '15/11/2026',
        seat: `${buyer.row}${buyer.seat}`,
        titular: buyer.name,
      };
      const ecdsaSignature = signTicketPayload(walletPayload, pkiKey.privateKeyPem);

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
        payloadJson: canonicalizeTicketPayload(walletPayload),
        ecdsaSignature,
        status: 'ISSUED',
        usedAt: null,
        usedGate: null,
        lastTotpStep: null,
        issuedAt,
      };
    });

    this.state = {
      pkiKey,
      event,
      tickets,
      auditLedger: [],
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
             ON CONFLICT (ticket_id) DO UPDATE SET
               session_secret = EXCLUDED.session_secret,
               payload_json = EXCLUDED.payload_json,
               ecdsa_signature = EXCLUDED.ecdsa_signature,
               status = EXCLUDED.status,
               used_at = EXCLUDED.used_at,
               used_gate = EXCLUDED.used_gate,
               last_totp_step = EXCLUDED.last_totp_step`,
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
             ON DUPLICATE KEY UPDATE
               session_secret = VALUES(session_secret),
               payload_json = VALUES(payload_json),
               ecdsa_signature = VALUES(ecdsa_signature),
               status = VALUES(status),
               used_at = VALUES(used_at),
               used_gate = VALUES(used_gate),
               last_totp_step = VALUES(last_totp_step)`,
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
    const publicKeyJwk = pkiKey.publicKeyJwk || exportPublicKeyJwk(pkiKey.publicKeyPem);
    return {
      id: pkiKey.id,
      curve: pkiKey.curve,
      publicKeyPem: pkiKey.publicKeyPem,
      publicKeyJwk,
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

  /**
   * Exporta el catálogo de boletos y la llave pública en el formato JSON exacto
   * utilizado por la Wallet del Módulo 5 ({ tickets: [...], publicKeyJwk: {...} }).
   */
  exportForModule5Wallet() {
    const pki = this.getPkiInfo();
    const event = this.state.event;
    const walletTickets = this.state.tickets.map((t) => {
      let parsed = {};
      try {
        parsed = JSON.parse(t.payloadJson);
      } catch (e) {}
      return {
        ticketId: t.ticketId,
        event: parsed.event || event.name,
        date: parsed.date || '15/11/2026',
        seat: parsed.seat || `${t.row}${t.seat}`,
        titular: parsed.titular || t.buyerName,
        status: t.status === 'ISSUED' ? 'ACTIVO' : t.status,
        skSession: t.sessionSecret,
        signatureECDSA: t.ecdsaSignature,
      };
    });

    return {
      tickets: walletTickets,
      publicKeyJwk: pki.publicKeyJwk,
    };
  }

  /**
   * Permite sincronizar/registrar boletos generados externamente por Módulo 4 o el prototipo de Módulo 5.
   */
  async syncExternalWalletBundle({ tickets = [], publicKeyJwk = null }) {
    const externalPubPem = publicKeyJwk ? importPublicKeyJwkToPem(publicKeyJwk) : null;
    const synced = [];

    for (const wt of tickets) {
      if (!wt.ticketId || String(wt.ticketId).includes('.')) {
        throw new Error(`ticketId inválido (${wt.ticketId}): no puede contener puntos (.)`);
      }
      const seatStr = String(wt.seat || 'A01');
      const rowMatch = seatStr.match(/^([A-Za-z0-9]+?)(\d+)$/);
      const row = rowMatch ? rowMatch[1] : 'A';
      const seatNum = rowMatch ? rowMatch[2] : seatStr;

      const walletPayload = {
        ticketId: wt.ticketId,
        event: wt.event || this.state.event.name,
        date: wt.date || '15/11/2026',
        seat: seatStr,
        titular: wt.titular || 'Titular Wallet M5',
      };

      const record = {
        ticketId: wt.ticketId,
        eventId: this.state.event.id,
        section: wt.section || 'VIP',
        row,
        seat: seatNum,
        buyerName: walletPayload.titular,
        buyerEmail: `${wt.ticketId.toLowerCase()}@wallet.stc.mx`,
        buyerHash: hashBuyerIdentity(walletPayload.titular),
        sessionSecret: wt.skSession || crypto.randomBytes(32).toString('base64url'),
        payloadJson: canonicalizeTicketPayload(walletPayload),
        ecdsaSignature:
          wt.signatureECDSA || signTicketPayload(walletPayload, this.state.pkiKey.privateKeyPem),
        issuerPublicKeyPem: externalPubPem || null,
        status: wt.status === 'USADO' || wt.status === 'USED' ? 'USED' : 'ISSUED',
        usedAt: null,
        usedGate: null,
        lastTotpStep: null,
        issuedAt: new Date().toISOString(),
      };

      const existingIdx = this.state.tickets.findIndex((x) => x.ticketId === wt.ticketId);
      if (existingIdx >= 0) {
        this.state.tickets[existingIdx] = record;
      } else {
        this.state.tickets.unshift(record);
      }
      synced.push(record.ticketId);
    }

    this.persistLocalStore();
    await this.syncMemoryToSql();
    return synced;
  }

  async createTicket({ buyerName, buyerEmail, section = 'VIP', row = 'B', seat = '10' }) {
    const { pkiKey, event, tickets } = this.state;
    const nextNum = tickets.length + 1;
    const ticketId = `TKT-2026-${String(nextNum).padStart(4, '0')}`;
    const issuedAt = new Date().toISOString();
    const buyerHash = hashBuyerIdentity(buyerEmail || buyerName);
    const sessionSecret = crypto.randomBytes(32).toString('base64url');

    const walletPayload = {
      ticketId,
      event: event.name,
      date: '15/11/2026',
      seat: `${row}${seat}`,
      titular: buyerName,
    };
    const ecdsaSignature = signTicketPayload(walletPayload, pkiKey.privateKeyPem);

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
      payloadJson: canonicalizeTicketPayload(walletPayload),
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

  /**
   * Transición atómica condicional ISSUED -> USED (Anti-Passback y protección contra escaneos simultáneos).
   */
  async markTicketUsedAtomic(ticketId, gateId, totpStep) {
    const ticket = this.getTicketById(ticketId);
    if (!ticket) return { acquired: false, ticket: null };
    if (ticket.status !== 'ISSUED') {
      return { acquired: false, ticket };
    }

    const usedAtIso = new Date().toISOString();

    if (this.mode === 'postgres' && this.pgPool) {
      const res = await this.pgPool.query(
        `UPDATE tickets
         SET status = 'USED', used_at = $2, used_gate = $3, last_totp_step = $4
         WHERE ticket_id = $1 AND status = 'ISSUED'
         RETURNING ticket_id`,
        [ticketId, usedAtIso, gateId, totpStep]
      );
      if (res.rowCount === 0) {
        return { acquired: false, ticket };
      }
    } else if (this.mode === 'mysql' && this.mysqlPool) {
      const [res] = await this.mysqlPool.query(
        `UPDATE tickets
         SET status = 'USED', used_at = ?, used_gate = ?, last_totp_step = ?
         WHERE ticket_id = ? AND status = 'ISSUED'`,
        [usedAtIso, gateId, totpStep, ticketId]
      );
      if (res.affectedRows === 0) {
        return { acquired: false, ticket };
      }
    }

    ticket.status = 'USED';
    ticket.usedAt = usedAtIso;
    ticket.usedGate = gateId;
    ticket.lastTotpStep = totpStep;
    this.state.usedTotpNonces[`${ticketId}:${totpStep}`] = usedAtIso;
    this.persistLocalStore();
    return { acquired: true, ticket };
  }

  async markTicketUsed(ticketId, gateId, totpStep) {
    const res = await this.markTicketUsedAtomic(ticketId, gateId, totpStep);
    return res.ticket;
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
      validationResult,
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
