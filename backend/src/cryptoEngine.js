const crypto = require('crypto');

const TOTP_WINDOW_SECONDS = parseInt(process.env.TOTP_WINDOW_SECONDS || '15', 10);
const TOTP_TOLERANCE_STEPS = 1; // Tolerancia +/-1 ventana acordada con Módulo 5
const GENESIS_HASH = '0'.repeat(64);

/**
 * Genera un par de llaves ECDSA en la curva P-256 (secp256r1 / prime256v1)
 * y exporta también la llave pública en formato JWK compatible con Web Crypto API (Módulo 5).
 */
function generatePkiKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1', // P-256 / secp256r1
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });

  const publicKeyJwk = exportPublicKeyJwk(publicKey);

  const certificateFingerprint = crypto
    .createHash('sha256')
    .update(publicKey)
    .digest('hex')
    .match(/.{1,2}/g)
    .join(':')
    .toUpperCase();

  return {
    id: 'PKI-CA-EVENT-2026-01',
    curve: 'P-256 (secp256r1)',
    publicKeyPem: publicKey,
    publicKeyJwk,
    privateKeyPem: privateKey,
    certificateFingerprint,
  };
}

/**
 * Convierte una llave pública PEM a formato JWK estándar { kty: "EC", crv: "P-256", x, y }
 * idéntico al esperado por subtle.importKey("jwk", ...) en el Módulo 5.
 */
function exportPublicKeyJwk(publicKeyPem) {
  const jwk = crypto.createPublicKey(publicKeyPem).export({ format: 'jwk' });
  return {
    kty: jwk.kty,
    crv: jwk.crv, // "P-256"
    x: jwk.x,
    y: jwk.y,
  };
}

/**
 * Importa una llave pública JWK { kty: "EC", crv: "P-256", x, y } a PEM para verificar en Node.js.
 */
function importPublicKeyJwkToPem(jwk) {
  return crypto
    .createPublicKey({ key: jwk, format: 'jwk' })
    .export({ type: 'spki', format: 'pem' });
}

/**
 * JSON canónico recursivo con llaves ordenadas alfabéticamente.
 * Idéntico byte a byte a la función canonicalize(obj) de src/js/cripto.js (Módulo 5).
 */
function canonicalize(obj) {
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalize).join(',') + ']';
  }
  if (obj && typeof obj === 'object') {
    return (
      '{' +
      Object.keys(obj)
        .sort()
        .map((k) => JSON.stringify(k) + ':' + canonicalize(obj[k]))
        .join(',') +
      '}'
    );
  }
  return JSON.stringify(obj);
}

/**
 * Extrae únicamente los campos inmutables del boleto que deben entrar a la firma ECDSA,
 * excluyendo metadatos mutables o secretos (skSession, signatureECDSA, status, etc.).
 */
function extractSignableTicketFields(ticketObj) {
  if (!ticketObj || typeof ticketObj !== 'object') return {};
  // Si el boleto viene con la estructura de Wallet del Módulo 5 ({ ticketId, event, date, seat, titular })
  if ('titular' in ticketObj || ('event' in ticketObj && 'date' in ticketObj)) {
    return {
      date: String(ticketObj.date || ''),
      event: String(ticketObj.event || ''),
      seat: String(ticketObj.seat || ''),
      ticketId: String(ticketObj.ticketId || ''),
      titular: String(ticketObj.titular || ''),
    };
  }
  // Estructura extendida M4/M6
  return {
    buyerHash: String(ticketObj.buyerHash || ''),
    eventId: String(ticketObj.eventId || ''),
    issuedAt: String(ticketObj.issuedAt || ''),
    row: String(ticketObj.row || ''),
    seat: String(ticketObj.seat || ''),
    section: String(ticketObj.section || ''),
    ticketId: String(ticketObj.ticketId || ''),
  };
}

function canonicalizeTicketPayload(payload) {
  return canonicalize(extractSignableTicketFields(payload));
}

/**
 * Firma digitalmente el boleto usando ECDSA P-256 + SHA-256 en formato IEEE P1363 (r || s, 64 bytes)
 * codificado en Base64URL sin relleno (=), 100% compatible con Web Crypto API (Módulo 5).
 */
function signTicketPayload(payload, privateKeyPem) {
  const canonical = canonicalizeTicketPayload(payload);
  const sign = crypto.createSign('SHA256');
  sign.update(canonical, 'utf8');
  sign.end();
  const signatureBuffer = sign.sign({
    key: privateKeyPem,
    dsaEncoding: 'ieee-p1363',
  });
  return signatureBuffer.toString('base64url');
}

/**
 * Verifica instantáneamente la firma ECDSA P-256 (formato IEEE P1363 de Módulo 5 o DER legacy)
 * usando la llave pública PK_event de la PKI.
 */
function verifyTicketSignature(payload, signatureBase64Url, publicKeyPem) {
  try {
    if (!payload || !signatureBase64Url || !publicKeyPem) return false;
    const canonical = canonicalizeTicketPayload(payload);
    const sigBuf = Buffer.from(String(signatureBase64Url), 'base64url');
    if (sigBuf.length === 0) return false;

    const verifyP1363 = crypto.createVerify('SHA256');
    verifyP1363.update(canonical, 'utf8');
    verifyP1363.end();

    if (sigBuf.length === 64) {
      return verifyP1363.verify(
        { key: publicKeyPem, dsaEncoding: 'ieee-p1363' },
        sigBuf
      );
    }

    // Fallback por si un boleto antiguo tiene firma ASN.1 DER
    return verifyP1363.verify(publicKeyPem, sigBuf);
  } catch (err) {
    return false;
  }
}

/**
 * Obtiene el escalón de tiempo (ventana = floor(Date.now() / 15000)) de 15 segundos.
 */
function getTotpStep(timestampMs = Date.now(), windowSeconds = TOTP_WINDOW_SECONDS) {
  return Math.floor(timestampMs / (windowSeconds * 1000));
}

/**
 * Decodifica SK_session desde Base64URL (estándar Módulo 5) o Hex (compatibilidad interna).
 */
function decodeSessionKeyBytes(skSession) {
  const str = String(skSession || '').trim();
  if (/^[0-9a-f]{64}$/i.test(str)) {
    return Buffer.from(str, 'hex');
  }
  return Buffer.from(str, 'base64url');
}

/**
 * Calcula el MAC del QR Dinámico conforme al Contrato Oficial Módulo 5 -> Módulo 6:
 *   mensaje = ticketId + "|" + ventana
 *   mac = Base64URL(HMAC-SHA256(SK_session, UTF-8(mensaje)))
 */
function computeDynamicQrHmac(skSession, ticketId, windowStep) {
  const keyBytes = decodeSessionKeyBytes(skSession);
  const message = `${ticketId}|${windowStep}`;
  return crypto
    .createHmac('sha256', keyBytes)
    .update(message, 'utf8')
    .digest('base64url');
}

/**
 * Construye la cadena exacta del QR Dinámico de Módulo 5:
 *   ticketId.ventana.mac
 */
function buildM5QrPayloadString(ticketId, skSession, timestampMs = Date.now()) {
  const win = getTotpStep(timestampMs, TOTP_WINDOW_SECONDS);
  const mac = computeDynamicQrHmac(skSession, ticketId, win);
  return `${ticketId}.${win}.${mac}`;
}

/**
 * Verifica en tiempo constante (timingSafeEqual) el MAC en Base64URL del QR dinámico.
 */
function verifyDynamicQrHmac(skSession, ticketId, windowStep, providedMac) {
  try {
    if (!skSession || !ticketId || windowStep === undefined || !providedMac) {
      return false;
    }
    const expectedMacB64u = computeDynamicQrHmac(skSession, ticketId, windowStep);
    const expectedBuf = Buffer.from(expectedMacB64u, 'base64url');
    const providedStr = String(providedMac).trim();

    // Soportar Base64URL (32 bytes = 43 chars sin '=')
    const providedBuf = Buffer.from(providedStr, 'base64url');
    if (expectedBuf.length === providedBuf.length && expectedBuf.length === 32) {
      return crypto.timingSafeEqual(expectedBuf, providedBuf);
    }
    return false;
  } catch (err) {
    return false;
  }
}

const PBKDF2_ITERATIONS = 210000;
const PBKDF2_KEYLEN = 64;
const PBKDF2_DIGEST = 'sha512';

/**
 * Deriva un hash seguro de contraseña usando PBKDF2-HMAC-SHA512 (210,000 iteraciones)
 * con salt criptográfico único de 128 bits (Módulo 1 & 6).
 */
function hashPasswordPbkdf2(password, saltHex = crypto.randomBytes(16).toString('hex')) {
  const derivedKey = crypto
    .pbkdf2Sync(
      String(password),
      Buffer.from(saltHex, 'hex'),
      PBKDF2_ITERATIONS,
      PBKDF2_KEYLEN,
      PBKDF2_DIGEST
    )
    .toString('hex');
  return {
    algorithm: `PBKDF2-HMAC-SHA512:${PBKDF2_ITERATIONS}`,
    saltHex,
    hashHex: derivedKey,
  };
}

/**
 * Verifica una contraseña en tiempo constante (timingSafeEqual) contra su hash PBKDF2-HMAC-SHA512.
 */
function verifyPasswordPbkdf2(password, saltHex, expectedHashHex) {
  try {
    if (!password || !saltHex || !expectedHashHex) return false;
    const { hashHex } = hashPasswordPbkdf2(password, saltHex);
    const actualBuf = Buffer.from(hashHex, 'hex');
    const expectedBuf = Buffer.from(expectedHashHex, 'hex');
    if (actualBuf.length !== expectedBuf.length) return false;
    return crypto.timingSafeEqual(actualBuf, expectedBuf);
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
  const nowSec = Math.floor(Date.now() / 1000);
  const body = {
    ...scannerPayload,
    jti: crypto.randomBytes(12).toString('hex'),
    iat: nowSec,
    exp: nowSec + 28800, // Sesión de turno de 8 horas
  };
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedBody = Buffer.from(JSON.stringify(body)).toString('base64url');
  const signingInput = `${encodedHeader}.${encodedBody}`;

  const sign = crypto.createSign('SHA256');
  sign.update(signingInput);
  sign.end();
  const signature = sign
    .sign({ key: privateKeyPem, dsaEncoding: 'ieee-p1363' })
    .toString('base64url');
  return `${signingInput}.${signature}`;
}

/**
 * Verifica criptográficamente un token JWT ES256 (ECDSA secp256r1) emitido para un escáner.
 */
function verifyScannerJwt(token, publicKeyPem) {
  try {
    if (!token || typeof token !== 'string') return { valid: false, reason: 'Token ausente' };
    const parts = token.split('.');
    if (parts.length !== 3) return { valid: false, reason: 'Estructura JWT inválida' };

    const [encodedHeader, encodedBody, encodedSig] = parts;
    const signingInput = `${encodedHeader}.${encodedBody}`;

    const verify = crypto.createVerify('SHA256');
    verify.update(signingInput);
    verify.end();

    const sigBuf = Buffer.from(encodedSig, 'base64url');
    const isSigValid = verify.verify(
      { key: publicKeyPem, dsaEncoding: 'ieee-p1363' },
      sigBuf
    );
    if (!isSigValid) {
      return { valid: false, reason: 'Firma ECDSA secp256r1 del token JWT inválida' };
    }

    const payload = JSON.parse(Buffer.from(encodedBody, 'base64url').toString('utf8'));
    const nowSec = Math.floor(Date.now() / 1000);
    if (payload.exp && nowSec > payload.exp) {
      return { valid: false, reason: 'El token JWT del operador ha expirado' };
    }

    return { valid: true, payload };
  } catch (err) {
    return { valid: false, reason: 'Token JWT corrupto o malformado' };
  }
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
  return crypto
    .createHash('sha256')
    .update(String(identityString).trim().toLowerCase(), 'utf8')
    .digest('hex');
}

module.exports = {
  TOTP_WINDOW_SECONDS,
  TOTP_TOLERANCE_STEPS,
  GENESIS_HASH,
  PBKDF2_ITERATIONS,
  generatePkiKeyPair,
  exportPublicKeyJwk,
  importPublicKeyJwkToPem,
  canonicalize,
  extractSignableTicketFields,
  canonicalizeTicketPayload,
  signTicketPayload,
  verifyTicketSignature,
  getTotpStep,
  decodeSessionKeyBytes,
  computeDynamicQrHmac,
  buildM5QrPayloadString,
  verifyDynamicQrHmac,
  hashPasswordPbkdf2,
  verifyPasswordPbkdf2,
  signScannerJwt,
  verifyScannerJwt,
  computeAuditBlockHash,
  verifyAuditHashChain,
  hashBuyerIdentity,
};
