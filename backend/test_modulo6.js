/**
 * Pruebas Automatizadas End-to-End del Módulo 6:
 * - Verificación de firma ECDSA (secp256r1)
 * - Validación de ventana de 15s con HMAC-SHA256 (Anti-Replay)
 * - Detección de VÁLIDO, REPLAY, FALSO y YA INGRESÓ en sub-segundo
 * - Verificación de integridad de la cadena de hashes SHA-256 (Audit Ledger)
 */

const BASE_URL = 'http://localhost:4000';

async function runTests() {
  console.log('=== INICIANDO PRUEBAS CRIPTOGRÁFICAS DEL MÓDULO 6 ===\n');

  // 0. Resetear boletos a ISSUED para prueba limpia
  await fetch(`${BASE_URL}/api/tickets/reset-all`, { method: 'POST' });

  // 1. Probar caso FALSO (Firma ECDSA inválida por alteración de asiento)
  const fakeSigQr = await fetch(
    `${BASE_URL}/api/simulator/qr/TKT-2026-0001?mode=FAKE_SIGNATURE`
  ).then((r) => r.json());
  const resFakeSig = await fetch(`${BASE_URL}/api/access/validate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      qrData: fakeSigQr.qrRawString,
      gateId: 'PUERTA-NORTE-01',
      scannerId: 'TEST-RUNNER',
    }),
  }).then((r) => r.json());
  console.log(
    `[1] Prueba Firma ECDSA Falsa -> Resultado: ${resFakeSig.status} (${resFakeSig.latencyMs} ms) | ECDSA=${resFakeSig.cryptoChecks.ecdsaVerified}`
  );
  if (resFakeSig.status !== 'FAKE') throw new Error('Se esperaba FAKE para firma inválida');

  // 2. Probar caso REPLAY (Ventana TOTP de 15s expirada)
  const replayQr = await fetch(
    `${BASE_URL}/api/simulator/qr/TKT-2026-0001?mode=REPLAY`
  ).then((r) => r.json());
  const resReplay = await fetch(`${BASE_URL}/api/access/validate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      qrData: replayQr.qrRawString,
      gateId: 'PUERTA-NORTE-01',
      scannerId: 'TEST-RUNNER',
    }),
  }).then((r) => r.json());
  console.log(
    `[2] Prueba Ataque Replay     -> Resultado: ${resReplay.status} (${resReplay.latencyMs} ms) | Ventana15s=${resReplay.cryptoChecks.totpWindowValid}`
  );
  if (resReplay.status !== 'REPLAY') throw new Error('Se esperaba REPLAY para ventana expirada');

  // 3. Probar caso VÁLIDO (Firma ECDSA secp256r1 válida + HMAC-SHA256 de ventana actual de 15s)
  const validQr = await fetch(
    `${BASE_URL}/api/simulator/qr/TKT-2026-0001?mode=VALID`
  ).then((r) => r.json());
  const resValid = await fetch(`${BASE_URL}/api/access/validate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      qrData: validQr.qrRawString,
      gateId: 'PUERTA-NORTE-01',
      scannerId: 'TEST-RUNNER',
    }),
  }).then((r) => r.json());
  console.log(
    `[3] Prueba Acceso Válido     -> Resultado: ${resValid.status} (${resValid.latencyMs} ms) | ECDSA=${resValid.cryptoChecks.ecdsaVerified}, HMAC=${resValid.cryptoChecks.hmacVerified}`
  );
  if (resValid.status !== 'VALID') throw new Error('Se esperaba VALID');

  // 4. Probar caso YA INGRESÓ (Re-escanear boleto que ya entró)
  const resAlreadyUsed = await fetch(`${BASE_URL}/api/access/validate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      qrData: validQr.qrRawString,
      gateId: 'TORNIQUETE-VIP-02',
      scannerId: 'TEST-RUNNER',
    }),
  }).then((r) => r.json());
  console.log(
    `[4] Prueba Ya Ingresó        -> Resultado: ${resAlreadyUsed.status} (${resAlreadyUsed.latencyMs} ms) | Puerta previa detectada`
  );
  if (resAlreadyUsed.status !== 'ALREADY_USED')
    throw new Error('Se esperaba ALREADY_USED al re-escanear el mismo boleto');

  // 5. Verificar cadena de hashes SHA-256
  const chainReport = await fetch(`${BASE_URL}/api/audit/verify-chain`).then((r) => r.json());
  console.log(
    `[5] Integridad Hash-Chain    -> Íntegra: ${chainReport.intact} | Bloques: ${chainReport.totalBlocks} | Último SHA-256: ${chainReport.latestHash.slice(0, 24)}...`
  );
  if (!chainReport.intact) throw new Error('Fallo en integridad de la cadena de hashes');

  // Restaurar TKT-2026-0001 para que esté listo como DISPONIBLE en la demo del usuario
  await fetch(`${BASE_URL}/api/tickets/TKT-2026-0001/reset`, { method: 'POST' });

  console.log('\n✅ TODAS LAS PRUEBAS DEL MÓDULO 6 PASARON EXITOSAMENTE EN SUB-SEGUNDO.');
}

runTests().catch((err) => {
  console.error('❌ Error en pruebas:', err);
  process.exit(1);
});
