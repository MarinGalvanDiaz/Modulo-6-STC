# Módulo 6: Control de Acceso en Puertas (Validator App) y Registro de Auditoría

Implementación completa del **Módulo 6** con **Backend en Node.js** y **App Móvil en Expo (React Native)** lista para escanear códigos QR dinámicos desde la cámara del celular, más un **Simulador de Módulos 1, 4 y 5** integrado para pruebas en vivo.

---

## 🔐 Componentes Criptográficos Implementados

1. **Verificación Instantánea de Firma Digital ECDSA (`secp256r1` / `prime256v1`)**:
   - Cada boleto emitido tiene su payload canónico firmado con la llave privada del evento:
     $$S = \text{Sign}_{SK_{\text{event}}}(\text{SHA-256}(\text{TicketPayload}))$$
   - En la puerta/torniquete, el validador verifica la firma en sub-segundo (`~1 ms`) usando la llave pública de la PKI:
     $$\text{Verify}_{PK_{\text{event}}}(\text{SHA-256}(\text{TicketPayload}), S)$$
   - Si el payload fue alterado o firmado por una llave apócrifa, se rechaza inmediatamente como **`FAKE` (Boleto Falso)**.

2. **Validación de QR Dinámico Rotativo (Ventana TOTP de 15s con `HMAC-SHA256`) — Anti-Replay**:
   - El QR rota cada **15 segundos** calculando:
     $$\text{HMAC} = \text{HMAC-SHA256}(SK_{\text{session}}, \text{TicketID} \parallel \text{Timestamp\_TOTP})$$
   - El validador recalcula el HMAC en tiempo constante (`crypto.timingSafeEqual`) y verifica que el escalón de tiempo `Timestamp_TOTP` corresponda a la ventana activa de 15 segundos.
   - Si se presenta una captura de pantalla o un QR cuya ventana expiró, se bloquea como **`REPLAY` (Ataque Replay)**.

3. **Control Anti-Passback (`ALREADY_USED` / Ya Ingresó)**:
   - Garantiza que un boleto legítimo solo pueda ingresar una vez al auditorio, reportando la puerta y hora exacta del primer acceso en caso de reintento.

4. **Libro Mayor de Auditoría Inmutable (SHA-256 Hash-Chain)**:
   - Cada intento de acceso (`VALID`, `REPLAY`, `FAKE`, `ALREADY_USED`) genera un bloque eslabonado criptográficamente con el hash `SHA-256` del bloque anterior:
     $$H_i = \text{SHA-256}(\text{index} \parallel \text{timestamp} \parallel \text{gateId} \parallel \text{scannerId} \parallel \text{ticketId} \parallel \text{result} \parallel \text{ecdsaValid} \parallel \text{hmacValid} \parallel H_{i-1})$$
   - Incluye el endpoint y botón en vivo `GET /api/audit/verify-chain` que recalcula toda la cadena desde el bloque Génesis (`0000...0000`) para demostrar que ningún registro ha sido alterado.

---

## 📁 Estructura del Proyecto

- `backend/` — Servidor Node.js + Express + Socket.io + Motor Criptográfico + Soporte PostgreSQL y MySQL:
  - `src/cryptoEngine.js`: Primitivas ECDSA `secp256r1`, JWT `ES256`, `HMAC-SHA256` TOTP 15s y cadena de hashes `SHA-256`.
  - `src/validatorService.js`: Motor de validación en sub-segundo y generador de QRs de prueba.
  - `src/db.js`: Adaptador de base de datos con soporte para **PostgreSQL** (`pg`), **MySQL** (`mysql2`) y sincronización automática.
  - `sql/schema_postgres.sql` y `sql/schema_mysql.sql`: Scripts DDL para PostgreSQL y MySQL.
  - `public/index.html`: Panel Web de Auditoría en Tiempo Real + Simulador de Wallet QR Dinámico para mostrar en la pantalla de la PC y escanear con el celular.
  - `test_modulo6.js`: Suite de pruebas criptográficas end-to-end.
- `mobile-validator/` — Aplicación móvil multiplataforma en **Expo (React Native)**:
  - `App.js`: Escáner de cámara QR (`expo-camera`), respuesta visual y háptica (`expo-haptics`) en sub-segundo, panel de auditoría y aforo en tiempo real vía WebSockets (`socket.io-client`), y generador QR integrado.

---

## 🚀 Cómo Ejecutar el Proyecto

### 1. Iniciar el Backend (Node.js)

```bash
cd backend
npm install
npm start
```

- El servidor quedará activo en:
  - **Panel Web & Simulador QR (en tu PC)**: `http://localhost:4000`
  - **API para tu Celular (en la misma red Wi-Fi)**: `http://10.100.67.223:4000` *(o la IP LAN que muestre la consola al arrancar)*
- Para conectar a tu instancia local de **PostgreSQL** o **MySQL**, edita `backend/.env` (`DB_CLIENT=postgres` o `DB_CLIENT=mysql`, `DB_USER`, `DB_PASSWORD`). El servidor creará automáticamente la base de datos `stc_modulo6` y todas las tablas al iniciar.

### 2. Iniciar la App Móvil (Expo) para usarla en el Celular

En una segunda terminal:

```bash
cd mobile-validator
npx expo start
```

1. Instala la app **Expo Go** en tu celular (Android o iOS).
2. Asegúrate de que tu celular y tu computadora estén en la **misma red Wi-Fi**.
3. Escanea el código QR de la terminal de Expo para abrir **STC Validator — Módulo 6** en tu celular.
4. Abre `http://localhost:4000` en el navegador de tu computadora: ahí verás el **Simulador de Wallet con el QR Dinámico rotando cada 15 segundos** y podrás apuntar con la cámara de tu celular para probar los 4 escenarios en tiempo real:
   - **✅ QR Válido (En Vivo 15s)** ➔ Respuesta en sub-segundo: **`VALID` (Acceso Válido)**
   - **🔵 Re-escanear el mismo boleto** ➔ Respuesta en sub-segundo: **`ALREADY_USED` (Ya Ingresó)**
   - **⏱️ Ataque Replay (QR Expirado)** ➔ Respuesta en sub-segundo: **`REPLAY` (Ataque Replay Detectado)**
   - **🚨 Falso (Firma ECDSA / HMAC Inválido)** ➔ Respuesta en sub-segundo: **`FAKE` (Boleto Falso)**

