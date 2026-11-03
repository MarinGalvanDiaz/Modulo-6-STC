const QRCode = require('qrcode');
const crypto = require('crypto');
const db = require('./db');
const {
  TOTP_WINDOW_SECONDS,
  verifyTicketSignature,
  getTotpStep,
  computeDynamicQrHmac,
  verifyDynamicQrHmac,
  verifyAuditHashChain,
} = require('./cryptoEngine');

/**
 * Construye el payload del QR Dinámico (Módulo 5 -> Módulo 6)
 * Permite simular tanto QRs legítimos rotando cada 15s como vectores de ataque
 * (REPLAY, FAKE_SIGNATURE, FAKE_HMAC) para demostración en vivo con el celular.
 */
async function buildDynamicQrForTicket(ticketId, mode = 'VALID') {
  const ticket = db.getTicketById(ticketId);
  if (!ticket) {
    throw new Error(`Boleto ${ticketId} no encontrado`);
  }

  const nowMs = Date.now();
  const currentStep = getTotpStep(nowMs, TOTP_WINDOW_SECONDS);
  const secondsIntoWindow = Math.floor((nowMs / 1000) % TOTP_WINDOW_SECONDS);
  const secondsRemaining = TOTP_WINDOW_SECONDS - secondsIntoWindow;

  const basePayload = JSON.parse(ticket.payloadJson);
  let qrPayload = { ...basePayload };
  let signature = ticket.ecdsaSignature;
  let totpStep = currentStep;
  let hmac = computeDynamicQrHmac(ticket.sessionSecret, ticket.ticketId, totpStep);
  let modeDescription = 'QR Dinámico legítimo (ECDSA secp256r1 + HMAC-SHA256 activo de 15s)';

  if (mode === 'REPLAY') {
    // Ventana de tiempo expirada (hace 2 minutos = 8 ventanas de 15s atrás)
    totpStep = currentStep - 8;
    hmac = computeDynamicQrHmac(ticket.sessionSecret, ticket.ticketId, totpStep);
    modeDescription =
      'Ataque Replay: Captura de pantalla de un QR cuya ventana TOTP de 15s expiró hace 120 segundos';
  } else if (mode === 'FAKE_SIGNATURE') {
    // Boleto adulterado (cambio de sección a VIP-DIAMANTE sin llave privada de la PKI)
    qrPayload = {
      ...basePayload,
      section: 'VIP-ADULTERADO',
      seat: '99',
    };
    modeDescription =
      'Boleto Falso (Firma ECDSA Inválida): Payload alterado sin llave privada SK_event de la PKI';
  } else if (mode === 'FAKE_HMAC') {
    // Firma ECDSA legítima del boleto, pero sin llave secreta de sesión SK_session
    const fakeSessionSecret = crypto.randomBytes(32).toString('hex');
    hmac = computeDynamicQrHmac(fakeSessionSecret, ticket.ticketId, currentStep);
    modeDescription =
      'Boleto Falso (HMAC Inválido): Intento de generar QR dinámico sin la llave SK_session del dispositivo';
  }

  // Paquete compacto codificado dentro del QR
  const qrEnvelope = {
    v: 1,
    p: qrPayload,
    sig: signature,
    ts: totpStep,
    hmac,
  };

  const qrRawString = JSON.stringify(qrEnvelope);
  const qrDataUrl = await QRCode.toDataURL(qrRawString, {
    errorCorrectionLevel: 'M',
    margin: 2,
    width: 340,
    color: {
      dark: '#0F172A',
      light: '#FFFFFF',
    },
  });

  return {
    ticket: {
      ticketId: ticket.ticketId,
      buyerName: ticket.buyerName,
      section: ticket.section,
      row: ticket.row,
      seat: ticket.seat,
      status: ticket.status,
      usedAt: ticket.usedAt,
      usedGate: ticket.usedGate,
      buyerHash: ticket.buyerHash,
    },
    simulationMode: mode,
    modeDescription,
    totp: {
      currentStep,
      qrStep: totpStep,
      windowSeconds: TOTP_WINDOW_SECONDS,
      secondsRemaining,
      expiresAtMs: (currentStep + 1) * TOTP_WINDOW_SECONDS * 1000,
    },
    cryptoDetails: {
      curve: 'secp256r1 (NIST P-256)',
      ecdsaSignaturePreview: `${signature.slice(0, 24)}...${signature.slice(-12)}`,
      hmacSha256: hmac,
    },
    qrEnvelope,
    qrRawString,
    qrDataUrl,
  };
}

/**
 * Motor principal del Módulo 6:
 * Verifica en sub-segundo:
 * 1) Firma digital ECDSA (secp256r1) con llave pública de la PKI
 * 2) Ventana de tiempo TOTP (15s) y recálculo de HMAC-SHA256 (anti-replay)
 * 3) Estado de ingreso único en el auditorio
 * 4) Registro en el Libro Mayor de Auditoría con Hashes Encadenados (SHA-256 Hash Chain)
 */
async function validateAccessQr({ qrData, gateId = 'PUERTA-NORTE-01', scannerId = 'SCANNER-EXPO-01' }) {
  const startHr = process.hrtime.bigint();
  const pkiInfo = db.getPkiInfo();
  const event = db.getEvent();

  let parsed;
  try {
    parsed = typeof qrData === 'string' ? JSON.parse(qrData) : qrData;
  } catch (err) {
    const latencyMs = Number(process.hrtime.bigint() - startHr) / 1e6;
    const auditBlock = await db.appendAuditBlock({
      gateId,
      scannerId,
      ticketId: 'MALFORMED-QR',
      eventId: event.id,
      section: 'N/A',
      seatLabel: 'N/A',
      validationResult: 'FAKE',
      reason: 'Formato de QR irreconocible o corrupto (no es un paquete criptográfico STC válido).',
      ecdsaValid: false,
      hmacValid: false,
      totpStep: null,
      latencyMs,
    });

    return {
      status: 'FAKE',
      title: 'BOLETO FALSO / QR INVÁLIDO',
      message: 'El código QR escaneado no contiene una estructura criptográfica STC válida.',
      latencyMs: Number(latencyMs.toFixed(2)),
      cryptoChecks: {
        ecdsaVerified: false,
        hmacVerified: false,
        totpWindowValid: false,
        curve: 'secp256r1',
      },
      ticket: null,
      auditBlock,
    };
  }

  const payload = parsed?.p || parsed?.payload;
  const signature = parsed?.sig || parsed?.signature;
  const scannedTotpStep = Number(parsed?.ts ?? parsed?.totpStep);
  const scannedHmac = parsed?.hmac;

  const ticketId = payload?.ticketId || 'UNKNOWN-TICKET';
  const section = payload?.section || 'N/A';
  const seatLabel = payload?.row && payload?.seat ? `${payload.row}-${payload.seat}` : 'N/A';

  // PASO 1: Verificación instantánea de firma ECDSA (secp256r1) con llave pública de la PKI
  const isEcdsaValid = verifyTicketSignature(payload, signature, pkiInfo.publicKeyPem);
  const storedTicket = db.getTicketById(ticketId);

  if (!isEcdsaValid || !storedTicket) {
    const latencyMs = Number(process.hrtime.bigint() - startHr) / 1e6;
    const reason = !isEcdsaValid
      ? 'Fallo en verificación de firma ECDSA (secp256r1) con PK_event: el payload fue adulterado o firmado por una entidad apócrifa.'
      : 'El identificador del boleto no existe en el padrón de emisión de la PKI.';

    const auditBlock = await db.appendAuditBlock({
      gateId,
      scannerId,
      ticketId,
      eventId: event.id,
      section,
      seatLabel,
      validationResult: 'FAKE',
      reason,
      ecdsaValid: false,
      hmacValid: false,
      totpStep: isNaN(scannedTotpStep) ? null : scannedTotpStep,
      latencyMs,
    });

    return {
      status: 'FAKE',
      title: 'BOLETO FALSO (FIRMA ECDSA INVÁLIDA)',
      message: reason,
      latencyMs: Number(latencyMs.toFixed(2)),
      cryptoChecks: {
        ecdsaVerified: false,
        hmacVerified: false,
        totpWindowValid: false,
        curve: 'secp256r1',
      },
      ticket: {
        ticketId,
        section,
        seatLabel,
      },
      auditBlock,
    };
  }

  // PASO 2: Recálculo de HMAC-SHA256(SK_session, TicketID || Timestamp_TOTP) y validación de ventana de 15s
  const currentStep = getTotpStep(Date.now(), TOTP_WINDOW_SECONDS);
  const isHmacAuthenticForStep = verifyDynamicQrHmac(
    storedTicket.sessionSecret,
    storedTicket.ticketId,
    scannedTotpStep,
    scannedHmac
  );

  // Si el HMAC no coincide ni siquiera para el timestamp que dice traer el QR -> Intento de falsificación sin SK_session
  if (!isHmacAuthenticForStep) {
    const latencyMs = Number(process.hrtime.bigint() - startHr) / 1e6;
    const reason =
      'Firma ECDSA válida, pero el código dinámico HMAC-SHA256 es inválido. El emisor no posee la llave secreta de sesión (SK_session).';

    const auditBlock = await db.appendAuditBlock({
      gateId,
      scannerId,
      ticketId: storedTicket.ticketId,
      eventId: storedTicket.eventId,
      section: storedTicket.section,
      seatLabel: `${storedTicket.row}-${storedTicket.seat}`,
      validationResult: 'FAKE',
      reason,
      ecdsaValid: true,
      hmacValid: false,
      totpStep: isNaN(scannedTotpStep) ? null : scannedTotpStep,
      latencyMs,
    });

    return {
      status: 'FAKE',
      title: 'BOLETO FALSO (HMAC DINÁMICO INVÁLIDO)',
      message: reason,
      latencyMs: Number(latencyMs.toFixed(2)),
      cryptoChecks: {
        ecdsaVerified: true,
        hmacVerified: false,
        totpWindowValid: false,
        curve: 'secp256r1',
      },
      ticket: {
        ticketId: storedTicket.ticketId,
        buyerName: storedTicket.buyerName,
        section: storedTicket.section,
        row: storedTicket.row,
        seat: storedTicket.seat,
      },
      auditBlock,
    };
  }

  // Verificar si la ventana TOTP de 15 segundos ya expiró (tolerancia de 1 escalón = 15s por desfase de red)
  const stepDrift = currentStep - scannedTotpStep;
  const isWindowActive = stepDrift >= -1 && stepDrift <= 1;

  if (!isWindowActive) {
    const latencyMs = Number(process.hrtime.bigint() - startHr) / 1e6;
    const expiredSeconds = Math.max(15, Math.abs(stepDrift) * TOTP_WINDOW_SECONDS);
    const reason = `Ataque Replay detectado: El token TOTP (#${scannedTotpStep}) expiró hace ~${expiredSeconds}s (ventana máxima: ${TOTP_WINDOW_SECONDS}s). Captura de pantalla o QR pregrabado rechazado.`;

    const auditBlock = await db.appendAuditBlock({
      gateId,
      scannerId,
      ticketId: storedTicket.ticketId,
      eventId: storedTicket.eventId,
      section: storedTicket.section,
      seatLabel: `${storedTicket.row}-${storedTicket.seat}`,
      validationResult: 'REPLAY',
      reason,
      ecdsaValid: true,
      hmacValid: true,
      totpStep: scannedTotpStep,
      latencyMs,
    });

    return {
      status: 'REPLAY',
      title: 'ATAQUE REPLAY DETECTADO (QR EXPIRADO)',
      message: reason,
      latencyMs: Number(latencyMs.toFixed(2)),
      cryptoChecks: {
        ecdsaVerified: true,
        hmacVerified: true,
        totpWindowValid: false,
        curve: 'secp256r1',
        stepDrift,
      },
      ticket: {
        ticketId: storedTicket.ticketId,
        buyerName: storedTicket.buyerName,
        section: storedTicket.section,
        row: storedTicket.row,
        seat: storedTicket.seat,
      },
      auditBlock,
    };
  }

  // PASO 3: Verificar si el boleto ya ingresó previamente al recinto
  if (storedTicket.status === 'USED') {
    const latencyMs = Number(process.hrtime.bigint() - startHr) / 1e6;
    const reason = `Doble ingreso rechazado (Anti-Passback): Este boleto ya registró entrada en ${storedTicket.usedGate} a las ${new Date(storedTicket.usedAt).toLocaleTimeString('es-MX')}.`;

    const auditBlock = await db.appendAuditBlock({
      gateId,
      scannerId,
      ticketId: storedTicket.ticketId,
      eventId: storedTicket.eventId,
      section: storedTicket.section,
      seatLabel: `${storedTicket.row}-${storedTicket.seat}`,
      validationResult: 'ALREADY_USED',
      reason,
      ecdsaValid: true,
      hmacValid: true,
      totpStep: scannedTotpStep,
      latencyMs,
    });

    return {
      status: 'ALREADY_USED',
      title: 'YA INGRESÓ (BOLETO UTILIZADO)',
      message: reason,
      latencyMs: Number(latencyMs.toFixed(2)),
      cryptoChecks: {
        ecdsaVerified: true,
        hmacVerified: true,
        totpWindowValid: true,
        curve: 'secp256r1',
      },
      ticket: {
        ticketId: storedTicket.ticketId,
        buyerName: storedTicket.buyerName,
        section: storedTicket.section,
        row: storedTicket.row,
        seat: storedTicket.seat,
        usedAt: storedTicket.usedAt,
        usedGate: storedTicket.usedGate,
      },
      auditBlock,
    };
  }

  // PASO 4: Boleto 100% VÁLIDO -> Marcar ingreso atómico y anexar al Libro Mayor de Auditoría
  const updatedTicket = await db.markTicketUsed(storedTicket.ticketId, gateId, scannedTotpStep);
  const latencyMs = Number(process.hrtime.bigint() - startHr) / 1e6;
  const reason = `Acceso autorizado en ${gateId}. Firma ECDSA (secp256r1) y ventana HMAC-SHA256 (#${scannedTotpStep}) verificadas con éxito.`;

  const auditBlock = await db.appendAuditBlock({
    gateId,
    scannerId,
    ticketId: updatedTicket.ticketId,
    eventId: updatedTicket.eventId,
    section: updatedTicket.section,
    seatLabel: `${updatedTicket.row}-${updatedTicket.seat}`,
    validationResult: 'VALID',
    reason,
    ecdsaValid: true,
    hmacValid: true,
    totpStep: scannedTotpStep,
    latencyMs,
  });

  return {
    status: 'VALID',
    title: 'ACCESO VÁLIDO — ADELANTE',
    message: reason,
    latencyMs: Number(latencyMs.toFixed(2)),
    cryptoChecks: {
      ecdsaVerified: true,
      hmacVerified: true,
      totpWindowValid: true,
      curve: 'secp256r1',
    },
    ticket: {
      ticketId: updatedTicket.ticketId,
      buyerName: updatedTicket.buyerName,
      section: updatedTicket.section,
      row: updatedTicket.row,
      seat: updatedTicket.seat,
      usedAt: updatedTicket.usedAt,
      usedGate: updatedTicket.usedGate,
      buyerHash: updatedTicket.buyerHash,
    },
    auditBlock,
  };
}

/**
 * Calcula estadísticas de aforo en tiempo real y resumen de seguridad del Libro Mayor
 */
function getAuditoriumStatsAndAuditSummary() {
  const event = db.getEvent();
  const tickets = db.getAllTickets();
  const rawLedger = db.getRawLedgerChronological();
  const recentLedger = db.getAuditLedger(60);
  const chainIntegrity = verifyAuditHashChain(rawLedger);

  const issuedCount = tickets.length;
  const insideCount = tickets.filter((t) => t.status === 'USED').length;

  const sectionBreakdown = {};
  for (const [secName, secMeta] of Object.entries(event.sections)) {
    const secIssued = tickets.filter((t) => t.section === secName).length;
    const secInside = tickets.filter((t) => t.section === secName && t.status === 'USED').length;
    sectionBreakdown[secName] = {
      section: secName,
      capacity: secMeta.capacity,
      issued: secIssued,
      inside: secInside,
      occupancyPercent:
        secMeta.capacity > 0 ? Number(((secInside / secMeta.capacity) * 100).toFixed(1)) : 0,
    };
  }

  const securityCounters = {
    totalScans: rawLedger.length,
    validEntries: rawLedger.filter((b) => b.validationResult === 'VALID').length,
    replayBlocked: rawLedger.filter((b) => b.validationResult === 'REPLAY').length,
    fakeRejected: rawLedger.filter((b) => b.validationResult === 'FAKE').length,
    alreadyUsedBlocked: rawLedger.filter((b) => b.validationResult === 'ALREADY_USED').length,
    avgLatencyMs:
      rawLedger.length > 0
        ? Number(
            (
              rawLedger.reduce((acc, b) => acc + Number(b.latencyMs || 0), 0) / rawLedger.length
            ).toFixed(2)
          )
        : 0,
  };

  return {
    event,
    occupancy: {
      totalCapacity: event.totalCapacity,
      ticketsIssued: issuedCount,
      checkedInCount: insideCount,
      remainingIssuedToEnter: Math.max(0, issuedCount - insideCount),
      capacityOccupancyPercent: Number(((insideCount / event.totalCapacity) * 100).toFixed(1)),
      checkInRatePercent:
        issuedCount > 0 ? Number(((insideCount / issuedCount) * 100).toFixed(1)) : 0,
      sections: Object.values(sectionBreakdown),
    },
    securityCounters,
    chainIntegrity,
    recentLedger,
  };
}

module.exports = {
  buildDynamicQrForTicket,
  validateAccessQr,
  getAuditoriumStatsAndAuditSummary,
};
