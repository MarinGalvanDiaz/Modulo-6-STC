require('dotenv').config();
const express = require('express');
const http = require('http');
const path = require('path');
const os = require('os');
const cors = require('cors');
const { Server } = require('socket.io');

const db = require('./db');
const authService = require('./authService');
const { signScannerJwt, verifyAuditHashChain, TOTP_WINDOW_SECONDS } = require('./cryptoEngine');
const {
  buildDynamicQrForTicket,
  validateAccessQr,
  getAuditoriumStatsAndAuditSummary,
  clearBurstCache,
} = require('./validatorService');

const PORT = parseInt(process.env.PORT || '4000', 10);

function getLocalLanIp() {
  const interfaces = os.networkInterfaces();
  const candidates = [];
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name] || []) {
      if (
        iface.family === 'IPv4' &&
        !iface.internal &&
        !iface.address.startsWith('169.254.') &&
        !iface.address.startsWith('192.168.56.')
      ) {
        candidates.push({ name, address: iface.address });
      }
    }
  }
  const wifi = candidates.find((c) => /wi-?fi|wlan/i.test(c.name));
  if (wifi) return wifi.address;
  const ethernet = candidates.find(
    (c) => /ethernet|en0/i.test(c.name) && !/hamachi|tailscale|vbox|vmware/i.test(c.name)
  );
  return (ethernet || candidates[0])?.address || '127.0.0.1';
}

async function startServer() {
  await db.init();
  authService.init();

  const app = express();
  const server = http.createServer(app);
  const io = new Server(server, {
    cors: {
      origin: '*',
      methods: ['GET', 'POST'],
    },
  });

  app.use(cors());
  app.use(express.json({ limit: '1mb' }));
  app.use(express.static(path.join(__dirname, '..', 'public')));

  const lanIp = getLocalLanIp();

  // 0. OpenAPI 3.0 Contract Specification
  app.get('/api/openapi.yaml', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'openapi.yaml'));
  });

  // 1. Health & Network Info
  app.get('/api/health', (req, res) => {
    const pki = db.getPkiInfo();
    res.json({
      ok: true,
      module: 'Módulo 6: Control de Acceso en Puertas (Validator App) y Registro de Auditoría',
      serverTime: new Date().toISOString(),
      totpWindowSeconds: TOTP_WINDOW_SECONDS,
      network: {
        lanIp,
        port: PORT,
        recommendedMobileApiUrl: `http://${lanIp}:${PORT}`,
      },
      database: {
        activeEngine: pki.dbEngine,
        configuredClient: pki.dbClientConfigured,
        notice: pki.dbConnectionNotice,
      },
      pki: {
        keyId: pki.id,
        curve: pki.curve,
        certificateFingerprint: pki.certificateFingerprint,
      },
    });
  });

  // 2. PKI Public Key & Scanner Authentication (Módulo 1 -> Módulo 5 & 6)
  app.get('/api/pki/public-key', (req, res) => {
    const pki = db.getPkiInfo();
    res.json({
      keyId: pki.id,
      curve: pki.curve,
      publicKeyJwk: pki.publicKeyJwk,
      publicKeyPem: pki.publicKeyPem,
      certificateFingerprint: pki.certificateFingerprint,
    });
  });

  // Endpoints de integración directa con la Wallet del Módulo 5 ({ tickets, publicKeyJwk })
  app.get('/api/wallet/export', (req, res) => {
    res.json(db.exportForModule5Wallet());
  });

  app.post('/api/wallet/sync', async (req, res) => {
    try {
      const { tickets, publicKeyJwk } = req.body || {};
      if (!Array.isArray(tickets) || tickets.length === 0) {
        return res.status(400).json({ error: 'Se requiere un arreglo tickets[] no vacío' });
      }
      const syncedIds = await db.syncExternalWalletBundle({ tickets, publicKeyJwk });
      const stats = getAuditoriumStatsAndAuditSummary();
      io.emit('stats:updated', stats);
      res.json({
        ok: true,
        syncedTickets: syncedIds,
        message: `${syncedIds.length} boleto(s) sincronizados con el Módulo 6`,
      });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  // Inicio de sesión seguro para operadores de escáner (PBKDF2-HMAC-SHA512 + PIN 2FA + JWT ES256 secp256r1 + Bloqueo de Sesión Única)
  app.post('/api/auth/login', (req, res) => {
    const { username, password, pin, gateId, scannerId, forceRelease } = req.body || {};

    // Si forceRelease=true, notificamos por WebSocket al dispositivo anterior antes de revocar su JTI
    const prevCheck = authService.isOperatorAlreadyLoggedIn(username, scannerId);
    const authResult = authService.authenticateOperator({
      username,
      password,
      pin,
      gateId,
      scannerId,
      forceRelease: Boolean(forceRelease),
    });

    if (!authResult.ok) {
      return res.status(authResult.status || 401).json({
        ok: false,
        code: authResult.code || 'AUTH_FAILED',
        activeSession: authResult.activeSession || null,
        error: authResult.error,
      });
    }

    if (forceRelease && prevCheck.loggedIn && prevCheck.session?.jti) {
      io.emit('auth:session_revoked', {
        revokedJti: prevCheck.session.jti,
        operatorId: prevCheck.session.operatorId,
        newScannerId: scannerId,
      });
    }

    res.json(authResult);
  });

  // Consulta si un usuario/operador ya tiene sesión activa en otro dispositivo
  app.get('/api/auth/session-status/:username', (req, res) => {
    const status = authService.isOperatorAlreadyLoggedIn(
      req.params.username,
      req.query.scannerId
    );
    res.json({
      ok: true,
      loggedIn: status.loggedIn,
      sameDevice: status.sameDevice || false,
      activeSession: status.session,
    });
  });

  app.get('/api/auth/me', (req, res) => {
    const verification = authService.verifySessionToken(req.headers.authorization);
    if (!verification.valid) {
      return res.status(401).json({ ok: false, error: verification.reason });
    }
    res.json({ ok: true, session: verification.payload });
  });

  app.post('/api/auth/logout', (req, res) => {
    authService.revokeSessionToken(req.headers.authorization);
    res.json({ ok: true, message: 'Sesión revocada criptográficamente' });
  });

  app.post('/api/pki/scanner-session', (req, res) => {
    const { gateId = 'PUERTA-NORTE-01', scannerId = 'SCANNER-EXPO-01', operator = 'Operador de Puerta' } =
      req.body || {};
    const token = signScannerJwt(
      { gateId, scannerId, operator, role: 'DOOR_VALIDATOR' },
      db.state.pkiKey.privateKeyPem
    );
    res.json({
      ok: true,
      gateId,
      scannerId,
      operator,
      jwtToken: token,
      signedWith: 'ECDSA secp256r1 (ES256)',
    });
  });

  // 3. Tickets Management & Simulation (Módulo 4 -> Módulo 6)
  app.get('/api/tickets', (req, res) => {
    const tickets = db.getAllTickets().map((t) => ({
      ticketId: t.ticketId,
      eventId: t.eventId,
      section: t.section,
      row: t.row,
      seat: t.seat,
      buyerName: t.buyerName,
      buyerEmail: t.buyerEmail,
      buyerHash: t.buyerHash,
      ecdsaSignature: t.ecdsaSignature,
      status: t.status,
      usedAt: t.usedAt,
      usedGate: t.usedGate,
      issuedAt: t.issuedAt,
    }));
    res.json({ tickets });
  });

  app.post('/api/tickets', async (req, res) => {
    try {
      const { buyerName, buyerEmail, section, row, seat } = req.body || {};
      if (!buyerName) {
        return res.status(400).json({ error: 'buyerName es obligatorio' });
      }
      const newTicket = await db.createTicket({ buyerName, buyerEmail, section, row, seat });
      const stats = getAuditoriumStatsAndAuditSummary();
      io.emit('stats:updated', stats);
      res.status(201).json({ ticket: newTicket });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/tickets/:ticketId/reset', async (req, res) => {
    try {
      const updated = await db.resetTicketStatus(req.params.ticketId);
      if (!updated) {
        return res.status(404).json({ error: 'Boleto no encontrado' });
      }
      clearBurstCache();
      const stats = getAuditoriumStatsAndAuditSummary();
      io.emit('stats:updated', stats);
      res.json({ ok: true, ticket: updated });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/tickets/reset-all', async (req, res) => {
    try {
      await db.resetAllTickets();
      clearBurstCache();
      const stats = getAuditoriumStatsAndAuditSummary();
      io.emit('stats:updated', stats);
      res.json({ ok: true, message: 'Todos los boletos han sido restaurados al estado ISSUED' });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // 4. Dynamic QR Generator / Simulator (Módulo 5 -> Módulo 6)
  // Modos soportados: VALID | REPLAY | FAKE_SIGNATURE | FAKE_HMAC
  app.get('/api/simulator/qr/:ticketId', async (req, res) => {
    try {
      const mode = (req.query.mode || 'VALID').toUpperCase();
      const qrBundle = await buildDynamicQrForTicket(req.params.ticketId, mode);
      res.json(qrBundle);
    } catch (err) {
      res.status(404).json({ error: err.message });
    }
  });

  // 5. Door Access Validator Endpoint (Módulo 6 Core - Respuesta en sub-segundo)
  app.post('/api/access/validate', async (req, res) => {
    try {
      const { qrData, gateId, scannerId } = req.body || {};
      if (!qrData) {
        return res.status(400).json({ error: 'Se requiere qrData para validar el acceso' });
      }

      // Si el escáner envía su JWT ES256, verificamos criptográficamente la firma ECDSA secp256r1
      let verifiedScannerId = scannerId;
      let verifiedGateId = gateId;
      if (req.headers.authorization) {
        const tokenCheck = authService.verifySessionToken(req.headers.authorization);
        if (!tokenCheck.valid) {
          return res.status(401).json({
            status: 'FAKE',
            title: 'SESIÓN DE ESCÁNER NO AUTORIZADA',
            message: tokenCheck.reason,
          });
        }
        verifiedGateId = gateId || tokenCheck.payload.gateId;
        verifiedScannerId = `${tokenCheck.payload.operatorId}@${scannerId || tokenCheck.payload.scannerId}`;
      }

      const result = await validateAccessQr({
        qrData,
        gateId: verifiedGateId,
        scannerId: verifiedScannerId,
      });
      const stats = getAuditoriumStatsAndAuditSummary();

      // Emitir eventos en tiempo real a todos los paneles de auditoría y apps móviles
      io.emit('audit:new_scan', result);
      io.emit('stats:updated', stats);

      res.json(result);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // 6. Real-Time Audit Ledger & Auditorium Occupancy Dashboard (Módulo 6)
  app.get('/api/audit/dashboard', (req, res) => {
    const dashboard = getAuditoriumStatsAndAuditSummary();
    res.json(dashboard);
  });

  app.get('/api/audit/verify-chain', (req, res) => {
    const rawLedger = db.getRawLedgerChronological();
    const verification = verifyAuditHashChain(rawLedger);
    res.json(verification);
  });

  io.on('connection', (socket) => {
    socket.emit('stats:updated', getAuditoriumStatsAndAuditSummary());
  });

  server.listen(PORT, '0.0.0.0', () => {
    console.log('======================================================================');
    console.log('  MÓDULO 6: CONTROL DE ACCESO EN PUERTAS & LIBRO MAYOR DE AUDITORÍA');
    console.log('======================================================================');
    console.log(`  Panel Web & Simulador QR (PC): http://localhost:${PORT}`);
    console.log(`  API para App Móvil Expo (LAN): http://${lanIp}:${PORT}`);
    console.log(`  Curva PKI Activa:              ECDSA secp256r1 (prime256v1)`);
    console.log(`  Rotación QR Dinámico HMAC:     Cada ${TOTP_WINDOW_SECONDS} segundos`);
    console.log('======================================================================');
  });
}

startServer().catch((err) => {
  console.error('Error fatal al iniciar el servidor:', err);
  process.exit(1);
});
