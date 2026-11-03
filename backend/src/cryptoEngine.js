const crypto = require('crypto');

const TOTP_WINDOW_SECONDS = parseInt(process.env.TOTP_WINDOW_SECONDS || '15', 10);
const GENESIS_HASH = '0'.repeat(64);

/**
 * Genera un par de llaves ECDSA en la curva secp256r1 (prime256v1 / NIST P-256)
 * cumpliendo los requerimientos de los Módulos 1, 4 y 6.
 */
function generatePkiKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1', // secp256r1
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });

  const certificateFingerprint = crypto
    .createHash('sha256')
    .update(publicKey)
    .digest('hex')
    .match(/.{1,2}/g)
    .join(':')
    .toUpperCase();

  return {
    id: 'PKI-CA-EVENT-2026-01',
    curve: 'secp256r1 (prime256v1)',
    publicKeyPem: publicKey,
    privateKeyPem: privateKey,
    certificateFingerprint,
  };
}

/**
 * Serializa de forma determinista (canónica) el payload del boleto
 * para garantizar que el hash SHA-256 sea idéntico al firmar y verificar.
 */
function canonicalizeTicketPayload(payload) {
  const canonicalObj = {
    ticketId: String(payload.ticketId || ''),
    eventId: String(payload.eventId || ''),
    section: String(payload.section || ''),
    row: String(payload.row || ''),
    seat: String(payload.seat || ''),
    buyerHash: String(payload.buyerHash || ''),
    issuedAt: String(payload.issuedAt || ''),
  };
  return JSON.stringify(canonicalObj);
}

/**
 * Firma digitalmente el payload del boleto usando ECDSA (secp256r1) + SHA-256:
 * S = Sign_SK(H(TicketPayload))
 */
function signTicketPayload(payload, privateKeyPem) {
  const canonical = canonicalizeTicketPayload(payload);
  const sign = crypto.createSign('SHA256');
  sign.update(canonical);
  sign.end();
  const signatureBuffer = sign.sign(privateKeyPem);
  return signatureBuffer.toString('base64url');
}

/**
 * Verifica instantáneamente la firma ECDSA (secp256r1) con la llave pública de la PKI:
 * Verify_PK(H(TicketPayload), S)
 */
function verifyTicketSignature(payload, signatureBase64Url, publicKeyPem) {
  try {
    if (!payload || !signatureBase64Url || !publicKeyPem) return false;
    const canonical = canonicalizeTicketPayload(payload);
    const verify = crypto.createVerify('SHA256');
    verify.update(canonical);
    verify.end();
    const sigBuf = Buffer.from(signatureBase64Url, 'base64url');
    return verify.verify(publicKeyPem, sigBuf);
  } catch (err) {
    return false;
  }
}

/**
 * Obtiene el escalón de tiempo (TOTP step) para ventanas de 15 segundos.
 */
function getTotpStep(timestampMs = Date.now(), windowSeconds = TOTP_WINDOW_SECONDS) {
  return Math.floor(timestampMs / (windowSeconds * 1000));
}

/**
 * Calcula el HMAC-SHA256 para el QR Dinámico Anticopia (Módulo 5 y 6):
 * HMAC-SHA256(SK_session, TicketID || Timestamp_TOTP)
 */
function computeDynamicQrHmac(sessionSecret, ticketId, totpStep) {
  const message = `${ticketId}||${totpStep}`;
  return crypto
    .createHmac('sha256', Buffer.from(sessionSecret, 'hex'))
    .update(message, 'utf8')
    .digest('hex');
}

/**
 * Verifica en tiempo constante (timingSafeEqual) el HMAC del QR dinámico.
 */
function verifyDynamicQrHmac(sessionSecret, ticketId, totpStep, providedHmacHex) {
  try {
    if (!sessionSecret || !ticketId || totpStep === undefined || !providedHmacHex) {
      return false;
    }
    const expectedHmacHex = computeDynamicQrHmac(sessionSecret, ticketId, totpStep);
    const expectedBuf = Buffer.from(expectedHmacHex, 'hex');
    const providedBuf = Buffer.from(String(providedHmacHex), 'hex');
    if (expectedBuf.length !== providedBuf.length || expectedBuf.length === 0) {
      return false;
    }
    return crypto.timingSafeEqual(expectedBuf, providedBuf);
  } catch (err) {
    return false;
  }
}

/**
 * Genera un token JWT firmado con ECDSA (ES256 / secp256r1) para autenticar
 * los escáneres/torniquetes de las puertas (Módulo 1 & 6).
 */
function signScannerJwt(scannerPayload, privateKeyPem) {
  const header = { alg: 'ES256', typ: 'JWT', crv: 'secp256r1' };
  const body = {
    ...scannerPayload,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 86400,
  };
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedBody = Buffer.from(JSON.stringify(body)).toString('base64url');
  const signingInput = `${encodedHeader}.${encodedBody}`;

  const sign = crypto.createSign('SHA256');
  sign.update(signingInput);
  sign.end();
  // IEEE P1363 format is standard for JWS ES256
  const signature = sign.sign({ key: privateKeyPem, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  return `${signingInput}.${signature}`;
}

/**
 * Calcula el Hash SHA-256 encadenado (Hash-Chain / Libro Mayor de Auditoría Inmutable)
 */
function computeAuditBlockHash({
  blockIndex,
  timestampIso,
  gateId,
  scannerId,
  ticketId,
  validationResult,
  ecdsaValid,
  hmacValid,
  prevHash,
}) {
  const rawRecord = [
    String(blockIndex),
    String(timestampIso),
    String(gateId),
    String(scannerId),
    String(ticketId),
    String(validationResult),
    Boolean(ecdsaValid) ? '1' : '0',
    Boolean(hmacValid) ? '1' : '0',
    String(prevHash),
  ].join('||');

  return crypto.createHash('sha256').update(rawRecord, 'utf8').digest('hex');
}

/**
 * Verifica la integridad completa de la cadena de hashes del Libro Mayor de Auditoría.
 */
function verifyAuditHashChain(ledgerBlocks) {
  const sorted = [...ledgerBlocks].sort((a, b) => Number(a.blockIndex) - Number(b.blockIndex));
  let expectedPrevHash = GENESIS_HASH;

  for (let i = 0; i < sorted.length; i++) {
    const block = sorted[i];
    if (block.prevHash !== expectedPrevHash) {
      return {
        intact: false,
        totalBlocks: sorted.length,
        corruptedAtBlock: block.blockIndex,
        reason: `Ruptura de cadena en bloque #${block.blockIndex}: prevHash no coincide con el hash del bloque anterior.`,
      };
    }

    const recalculatedHash = computeAuditBlockHash({
      blockIndex: block.blockIndex,
      timestampIso: block.timestampIso,
      gateId: block.gateId,
      scannerId: block.scannerId,
      ticketId: block.ticketId,
      validationResult: block.validationResult,
      ecdsaValid: block.ecdsaValid,
      hmacValid: block.hmacValid,
      prevHash: block.prevHash,
    });

    if (recalculatedHash !== block.blockHash) {
      return {
        intact: false,
        totalBlocks: sorted.length,
        corruptedAtBlock: block.blockIndex,
        reason: `Alteración detectada en bloque #${block.blockIndex}: el hash SHA-256 recalculado (${recalculatedHash.slice(0, 12)}...) difiere del registrado (${block.blockHash.slice(0, 12)}...).`,
      };
    }

    expectedPrevHash = block.blockHash;
  }

  return {
    intact: true,
    totalBlocks: sorted.length,
    genesisHash: GENESIS_HASH,
    latestHash: sorted.length > 0 ? expectedPrevHash : GENESIS_HASH,
    verifiedAt: new Date().toISOString(),
  };
}

/**
 * Genera el hash de identidad del comprador SHA-256(email/documento)
 */
function hashBuyerIdentity(identityString) {
  return crypto.createHash('sha256').update(String(identityString).trim().toLowerCase(), 'utf8').digest('hex');
}

module.exports = {
  TOTP_WINDOW_SECONDS,
  GENESIS_HASH,
  generatePkiKeyPair,
  canonicalizeTicketPayload,
  signTicketPayload,
  verifyTicketSignature,
  getTotpStep,
  computeDynamicQrHmac,
  verifyDynamicQrHmac,
  signScannerJwt,
  computeAuditBlockHash,
  verifyAuditHashChain,
  hashBuyerIdentity,
};

