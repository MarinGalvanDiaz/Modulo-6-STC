/**
 * Pruebas Automatizadas End-to-End del Módulo 6 + Integración Real con Código Web Crypto de Módulo 5:
 * - Login de operador (PBKDF2-HMAC-SHA512 210k iter + PIN 2FA + Bloqueo Multi-Dispositivo + JWT ES256)
 * - Exportación de Wallet JSON ({ tickets, publicKeyJwk }) y verificación Web Crypto P-256 (IEEE P1363) idéntica a cripto.js de M5
 * - Generación de QR con la fórmula exacta de Módulo 5: ticketId.ventana.mac (ticketId|ventana en Base64URL)
 * - Validación en sub-segundo de FAKE, REPLAY, VALID, ALREADY_USED y verificación SHA-256 Hash-Chain
 */

const BASE_URL = 'http://localhost:4000';
const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();

// --- Funciones exactas de src/js/cripto.js (Módulo 5) para probar interoperabilidad 1:1 ---
function toB64u(buf) {
  const bytes = new Uint8Array(buf);
  return Buffer.from(bytes).toString('base64url');
}
function fromB64u(str) {
  return new Uint8Array(Buffer.from(str, 'base64url'));
}
function canonicalizeM5(obj) {
  if (Array.isArray(obj)) return '[' + obj.map(canonicalizeM5).join(',') + ']';
  if (obj && typeof obj === 'object') {
    return (
      '{' +
      Object.keys(obj)
        .sort()
        .map((k) => JSON.stringify(k) + ':' + canonicalizeM5(obj[k]))
        .join(',') +
      '}'
    );
  }
  return JSON.stringify(obj);
}
async function generateQRPayloadM5(ticketId, skSessionB64u, now = Date.now()) {
  const key = await subtle.importKey(
    'raw',
    fromB64u(skSessionB64u),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
  const win = Math.floor(now / 15000);
  const mac = toB64u(await subtle.sign('HMAC', key, enc.encode(`${ticketId}|${win}`)));
  return `${ticketId}.${win}.${mac}`;
}

async function runTests() {
  console.log('=== PRUEBAS END-TO-END: MÓDULO 5 (WEB CRYPTO) ➔ MÓDULO 6 (VALIDATOR) ===\n');

  // 0. Login Operador Dispositivo A
  const loginRes = await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: 'operador@ticketmaster.mx',
      password: 'Ticketmaster#2026',
      pin: '2026',
      gateId: 'PUERTA-NORTE-01',
      scannerId: 'TEST-RUNNER',
      forceRelease: true,
    }),
  }).then((r) => r.json());
  if (!loginRes.ok) throw new Error(`Fallo en login: ${loginRes.error}`);
  console.log(`[0] Login Operador Seguro      -> ${loginRes.operator.name} (JWT ES256 activo)`);

  // 0.b Bloqueo Multi-Dispositivo
  const secondDeviceRes = await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: 'operador@ticketmaster.mx',
      password: 'Ticketmaster#2026',
      pin: '2026',
      gateId: 'ACCESO-SUR-03',
      scannerId: 'SECOND-DEVICE',
    }),
  });
  if (secondDeviceRes.status !== 409) {
    throw new Error('Se esperaba HTTP 409 en segundo dispositivo');
  }
  console.log(`[0.b] Bloqueo Multi-Dispositivo -> HTTP 409 confirmado`);

  const authHeaders = {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${loginRes.security.jwtToken}`,
  };

  await fetch(`${BASE_URL}/api/tickets/reset-all`, { method: 'POST' });

  // 1. Obtener paquete Wallet JSON (/api/wallet/export) y verificar firma offline con Web Crypto igual que M5
  const walletBundle = await fetch(`${BASE_URL}/api/wallet/export`).then((r) => r.json());
  const bol001 = walletBundle.tickets.find((t) => t.ticketId === 'BOL-001');
  if (!bol001) throw new Error('No se encontró BOL-001 en /api/wallet/export');

  const pubKeyWebCrypto = await subtle.importKey(
    'jwk',
    walletBundle.publicKeyJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify']
  );
  const signableBoleto = {
    date: bol001.date,
    event: bol001.event,
    seat: bol001.seat,
    ticketId: bol001.ticketId,
    titular: bol001.titular,
  };
  const offlineVerified = await subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    pubKeyWebCrypto,
    fromB64u(bol001.signatureECDSA),
    enc.encode(canonicalizeM5(signableBoleto))
  );
  console.log(
    `[1] Interoperabilidad JWK/P1363 -> Web Crypto verifyTicket(BOL-001) = ${offlineVerified}`
  );
  if (!offlineVerified) throw new Error('Web Crypto de M5 no pudo verificar la firma P1363 de M6');

  // 2. Generar QR en formato exacto M5 (BOL-001.ventana.mac) usando Web Crypto y validarlo en M6
  const m5QrValid = await generateQRPayloadM5(bol001.ticketId, bol001.skSession, Date.now());
  console.log(`    QR generado por M5: "${m5QrValid}"`);

  const resValid = await fetch(`${BASE_URL}/api/access/validate`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({
      qrData: m5QrValid,
      gateId: 'PUERTA-NORTE-01',
      scannerId: 'TEST-RUNNER',
    }),
  }).then((r) => r.json());
  console.log(
    `[2] Escaneo QR M5 Válido       -> ${resValid.status} (${resValid.latencyMs} ms) | ECDSA=${resValid.cryptoChecks.ecdsaVerified}, HMAC=${resValid.cryptoChecks.hmacVerified}`
  );
  if (resValid.status !== 'VALID') throw new Error(`Se esperaba VALID, llegó ${resValid.status}`);

  // 3. Re-escanear el mismo QR M5 -> ALREADY_USED
  const resUsed = await fetch(`${BASE_URL}/api/access/validate`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({
      qrData: m5QrValid,
      gateId: 'TORNIQUETE-VIP-02',
      scannerId: 'TEST-RUNNER',
    }),
  }).then((r) => r.json());
  console.log(`[3] Escaneo QR M5 Ya Ingresó   -> ${resUsed.status} (${resUsed.latencyMs} ms)`);
  if (resUsed.status !== 'ALREADY_USED') throw new Error('Se esperaba ALREADY_USED');

  // 4. Generar QR M5 Expirado (hace 120s) -> REPLAY
  const m5QrExpired = await generateQRPayloadM5(
    'TKT-2026-0001',
    walletBundle.tickets.find((t) => t.ticketId === 'TKT-2026-0001').skSession,
    Date.now() - 120000
  );
  const resReplay = await fetch(`${BASE_URL}/api/access/validate`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({
      qrData: m5QrExpired,
      gateId: 'PUERTA-NORTE-01',
      scannerId: 'TEST-RUNNER',
    }),
  }).then((r) => r.json());
  console.log(`[4] Escaneo QR M5 Expirado     -> ${resReplay.status} (${resReplay.latencyMs} ms)`);
  if (resReplay.status !== 'REPLAY') throw new Error('Se esperaba REPLAY');

  // 5. Generar QR M5 con SK_session falsa -> FAKE
  const fakeSkB64u = Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(32))).toString(
    'base64url'
  );
  const m5QrFakeMac = await generateQRPayloadM5('TKT-2026-0001', fakeSkB64u, Date.now());
  const resFakeMac = await fetch(`${BASE_URL}/api/access/validate`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({
      qrData: m5QrFakeMac,
      gateId: 'PUERTA-NORTE-01',
      scannerId: 'TEST-RUNNER',
    }),
  }).then((r) => r.json());
  console.log(`[5] Escaneo QR M5 Sin Llave    -> ${resFakeMac.status} (${resFakeMac.latencyMs} ms)`);
  if (resFakeMac.status !== 'FAKE') throw new Error('Se esperaba FAKE');

  // 6. Verificar cadena de hashes SHA-256
  const chainReport = await fetch(`${BASE_URL}/api/audit/verify-chain`).then((r) => r.json());
  console.log(
    `[6] Integridad Hash-Chain      -> Íntegra: ${chainReport.intact} (${chainReport.totalBlocks} bloques)`
  );
  if (!chainReport.intact) throw new Error('Fallo en integridad de Hash-Chain');

  // Dejar todos los boletos listos como ISSUED y cerrar sesión del TEST-RUNNER
  await fetch(`${BASE_URL}/api/tickets/reset-all`, { method: 'POST' });
  await fetch(`${BASE_URL}/api/auth/logout`, { method: 'POST', headers: authHeaders });

  console.log('\n✅ INTEGRACIÓN EXTREMO A EXTREMO MÓDULO 5 ➔ MÓDULO 6 VERIFICADA AL 100%.');
}

runTests().catch((err) => {
  console.error('❌ Error en pruebas:', err);
  process.exit(1);
});
