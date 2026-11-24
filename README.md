# Módulo 6: Control de Acceso en Puertas (Validator App) y Registro de Auditoría

Implementación del **Módulo 6** con **Backend en Node.js** y **App Móvil en Expo (React Native)** con diseño minimalista inspirado en **Ticketmaster (`SafeTix™`)**, lista para escanear códigos QR dinámicos desde la cámara del celular (iOS / Android), más un **Simulador de Módulos 1, 4 y 5** integrado.

---

## 📦 Contrato y Estructura del Payload de un QR Válido (Módulos 4 y 5 ➔ Módulo 6)

Cuando la **App Wallet (Módulo 5)** renderiza el código QR dinámico que rota cada **15 segundos**, codifica en el QR una cadena JSON compacta llamada **`QrEnvelope`**.

### 1. Ejemplo Real de Payload dentro de un QR Válido

```json
{
  "v": 1,
  "p": {
    "ticketId": "TKT-2026-0001",
    "eventId": "EVT-AUD-2026-SYMPHONY",
    "section": "VIP",
    "row": "A",
    "seat": "01",
    "buyerHash": "6dc63dd818621f0d2ba1b5b1ea1d12d9bb9615579bb34b5f1f74f8d022b31d35",
    "issuedAt": "2026-11-03T20:02:57.854Z"
  },
  "sig": "MEUCIFQi9ipsSB1F-dCOjH_PoPeQ9sWuvPyd7xgEuTZYyQAkAiEA5m8lwDQS2YGBNZMPC3DMHSqOykjsT6-aB5Gxt-BhsAc",
  "ts": 119616943,
  "hmac": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
}
```

---

### 2. Descripción Detallada de cada Campo del QR

| Campo | Tipo | Origen | Descripción y Regla Criptográfica |
| :--- | :--- | :--- | :--- |
| **`v`** | `number` | Módulo 5 | Versión del esquema del contenedor QR (`1`). |
| **`p`** | `object` | Módulo 4 | **`TicketPayload` inmutable** emitido al confirmar la compra del boleto. |
| **`p.ticketId`** | `string` | Módulo 4 | Identificador único del boleto (ej. `"TKT-2026-0001"`). |
| **`p.eventId`** | `string` | Módulo 4 | Identificador del evento en el auditorio (ej. `"EVT-AUD-2026-SYMPHONY"`). |
| **`p.section`** | `string` | Módulo 4 | Sección asignada (`"VIP"`, `"Preferente"`, `"General"`, `"Palcos"`). |
| **`p.row`** | `string` | Módulo 4 | Fila del asiento (ej. `"A"`). |
| **`p.seat`** | `string` | Módulo 4 | Número de asiento (ej. `"01"`). |
| **`p.buyerHash`** | `string` (hex) | Módulo 4 | Hash `SHA-256` (64 caracteres hex) del correo/identidad del comprador: `SHA256(email.trim().toLowerCase())`. |
| **`p.issuedAt`** | `string` (ISO) | Módulo 4 | Timestamp ISO 8601 de emisión del boleto. |
| **`sig`** | `string` (base64url) | Módulo 4 | **Firma Digital ECDSA (`secp256r1` / `prime256v1`)** con `SHA-256` sobre el JSON canónico de `p`, codificada en `base64url`: $$S = \text{Sign}_{SK_{\text{event}}}(\text{SHA-256}(\text{canonical}(p)))$$ |
| **`ts`** | `number` (int) | Módulo 5 | **Escalón de tiempo TOTP de 15 segundos**: $$\text{ts} = \lfloor \text{Date.now()} / 15000 \rfloor$$ |
| **`hmac`** | `string` (hex) | Módulo 5 | **HMAC Dinámico Anticopia** (64 caracteres hex) calculado con la llave secreta de sesión del boleto (`SK_session` de 256 bits en hex): $$\text{hmac} = \text{HMAC-SHA256}(SK_{\text{session}}, \text{ticketId} \parallel \text{"||"} \parallel \text{ts})$$ |

---

### 3. Reglas Exactas para Generar y Verificar el QR (Integración entre Módulos)

#### A. Serialización Canónica del `TicketPayload` (`p`) — Módulo 4 y 6
Para que la firma ECDSA `secp256r1` coincida siempre al verificar, el objeto `p` se serializa con `JSON.stringify` respetando **exactamente este orden de llaves**:

```javascript
function canonicalizeTicketPayload(payload) {
  return JSON.stringify({
    ticketId: String(payload.ticketId || ''),
    eventId: String(payload.eventId || ''),
    section: String(payload.section || ''),
    row: String(payload.row || ''),
    seat: String(payload.seat || ''),
    buyerHash: String(payload.buyerHash || ''),
    issuedAt: String(payload.issuedAt || ''),
  });
}
```

#### B. Firma y Verificación ECDSA (`secp256r1`) — Módulo 4 y 6
```javascript
// Módulo 4: Emisión de la firma S = Sign_SK(H(TicketPayload))
const sign = crypto.createSign('SHA256');
sign.update(canonicalizeTicketPayload(p));
sign.end();
const sig = sign.sign(privateKeyPem).toString('base64url');

// Módulo 6: Verificación instantánea con la llave pública de la PKI (PK_event)
const verify = crypto.createVerify('SHA256');
verify.update(canonicalizeTicketPayload(p));
verify.end();
const isEcdsaValid = verify.verify(publicKeyPem, Buffer.from(sig, 'base64url'));
```

#### C. Cálculo del QR Dinámico cada 15 segundos (`HMAC-SHA256`) — Módulo 5 y 6
```javascript
// Escalón TOTP actual (ventana de 15 segundos)
const ts = Math.floor(Date.now() / 15000);

// HMAC-SHA256(SK_session, TicketID || Timestamp_TOTP)
const hmac = crypto
  .createHmac('sha256', Buffer.from(sessionSecretHex, 'hex'))
  .update(`${p.ticketId}||${ts}`, 'utf8')
  .digest('hex');
```

#### D. Matriz de Decisión en Puerta (Módulo 6)

| Paso | Verificación Realizada por el Módulo 6 | Si Falla / Condición | Respuesta |
| :---: | :--- | :--- | :--- |
| **1** | `verifyTicketSignature(p, sig, PK_event)` (ECDSA `secp256r1`) | Payload adulterado o firma apócrifa | 🚨 **`FAKE`** (*Boleto Falso — Firma ECDSA Inválida*) |
| **2** | `verifyDynamicQrHmac(SK_session, ticketId, ts, hmac)` (`timingSafeEqual`) | El emisor del QR no posee `SK_session` | 🚨 **`FAKE`** (*Boleto Falso — HMAC Dinámico Inválido*) |
| **3** | Ventana de tiempo activa: `Math.abs(currentStep - ts) <= 1` (15s) | QR expirado (captura de pantalla / replay) | ⏱️ **`REPLAY`** (*Ataque Replay — QR Expirado*) |
| **4** | Estado del boleto en BD (`ticket.status === 'ISSUED'`) | `ticket.status === 'USED'` | 🔵 **`ALREADY_USED`** (*Ya Ingresó — Anti-Passback*) |
| **5** | Todas las validaciones anteriores exitosas | Marca `status = 'USED'` y agrega bloque `SHA-256` | ✅ **`VALID`** (*Boleto Válido — Adelante*) |

---

## 📄 Contrato OpenAPI 3.0

El contrato completo de la API en formato **OpenAPI 3.0.3** se encuentra en:
- Archivo local: [`backend/openapi.yaml`](file:///c:/Users/chang/OneDrive/Documentos/STC/Proyecto/backend/openapi.yaml)
- Endpoint en vivo: `GET http://localhost:4000/api/openapi.yaml`

Puedes importarlo directamente en **Swagger Editor**, **Postman** o **Insomnia** para probar todos los endpoints (`POST /api/access/validate`, `GET /api/audit/dashboard`, `GET /api/audit/verify-chain`, `GET /api/pki/public-key`, `GET /api/simulator/qr/{ticketId}`).

---

## 🚀 Cómo Ejecutar el Proyecto

### 1. Iniciar el Backend (Node.js)

```bash
cd backend
npm install
npm start
```

- **Panel Web SafeTix™ & Auditoría (en tu PC)**: `http://localhost:4000`
- **Contrato OpenAPI 3.0**: `http://localhost:4000/api/openapi.yaml`
- **API para tu iPhone / Celular (en la misma red Wi-Fi)**: detectada automáticamente al arrancar.

### 2. Iniciar la App Móvil (Expo) en tu iPhone o Android

En una segunda terminal:

```bash
cd mobile-validator
npx expo start
```

1. Abre **Expo Go** en tu iPhone/Android (conectado a la misma red Wi-Fi que tu PC).
2. Apunta la cámara al QR de `http://localhost:4000` o usa las pestañas **Escáner**, **Boletos QR** y **Auditoría**.
