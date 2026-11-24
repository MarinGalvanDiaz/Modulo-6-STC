const crypto = require('crypto');
const db = require('./db');
const {
  PBKDF2_ITERATIONS,
  hashPasswordPbkdf2,
  verifyPasswordPbkdf2,
  signScannerJwt,
  verifyScannerJwt,
} = require('./cryptoEngine');

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 60 * 1000; // 60 segundos de bloqueo anti-fuerza bruta

class ScannerAuthService {
  constructor() {
    this.operators = [];
    this.failedAttempts = new Map(); // key -> { count, lockedUntil }
    this.revokedTokens = new Set(); // jti revocados al cerrar sesión
    this.activeSessions = new Map(); // operatorId -> { operatorId, name, jti, scannerId, gateId, loginAtIso, expiresAtSec }
    this.initialized = false;
  }

  init() {
    if (this.initialized) return;
    // Pre-hashear credenciales de personal de acceso con PBKDF2-HMAC-SHA512 (210,000 iteraciones) y salts únicos
    const op1Pass = hashPasswordPbkdf2('Ticketmaster#2026');
    const op1Pin = hashPasswordPbkdf2('2026');

    const op2Pass = hashPasswordPbkdf2('AccesoVIP#2026');
    const op2Pin = hashPasswordPbkdf2('2026');

    this.operators = [
      {
        operatorId: 'STAFF-01',
        email: 'operador@ticketmaster.mx',
        name: 'Carlos Mendoza',
        badgeRole: 'Supervisor de Puertas',
        role: 'DOOR_VALIDATOR',
        passwordSalt: op1Pass.saltHex,
        passwordHash: op1Pass.hashHex,
        pinSalt: op1Pin.saltHex,
        pinHash: op1Pin.hashHex,
        hashAlgorithm: op1Pass.algorithm,
      },
      {
        operatorId: 'STAFF-VIP',
        email: 'vip@ticketmaster.mx',
        name: 'Elena Torres',
        badgeRole: 'Control Acceso VIP',
        role: 'DOOR_VALIDATOR',
        passwordSalt: op2Pass.saltHex,
        passwordHash: op2Pass.hashHex,
        pinSalt: op2Pin.saltHex,
        pinHash: op2Pin.hashHex,
        hashAlgorithm: op2Pass.algorithm,
      },
    ];
    this.initialized = true;
  }

  findOperator(usernameOrId) {
    this.init();
    const clean = String(usernameOrId || '').trim().toLowerCase();
    return (
      this.operators.find(
        (op) => op.email.toLowerCase() === clean || op.operatorId.toLowerCase() === clean
      ) || null
    );
  }

  /**
   * Valida si el operador ya tiene una sesión activa en algún dispositivo.
   * Si existe una sesión activa y no ha expirado ni ha sido revocada, devuelve loggedIn: true
   * junto con los metadatos del dispositivo actual (scannerId, gateId, loginAtIso).
   */
  isOperatorAlreadyLoggedIn(usernameOrId, requestingScannerId = null) {
    const operator = this.findOperator(usernameOrId);
    if (!operator) {
      return { loggedIn: false, operator: null, session: null };
    }

    const activeSession = this.activeSessions.get(operator.operatorId);
    if (!activeSession) {
      return { loggedIn: false, operator, session: null };
    }

    const nowSec = Math.floor(Date.now() / 1000);
    const isExpired = activeSession.expiresAtSec && nowSec > activeSession.expiresAtSec;
    const isRevoked = activeSession.jti && this.revokedTokens.has(activeSession.jti);

    if (isExpired || isRevoked) {
      this.activeSessions.delete(operator.operatorId);
      return { loggedIn: false, operator, session: null };
    }

    const sameDevice =
      Boolean(requestingScannerId) && activeSession.scannerId === requestingScannerId;

    return {
      loggedIn: true,
      sameDevice,
      operator,
      session: activeSession,
    };
  }

  checkLockout(identifier) {
    const record = this.failedAttempts.get(identifier);
    if (!record) return { locked: false };
    if (record.lockedUntil && Date.now() < record.lockedUntil) {
      const remainingSec = Math.ceil((record.lockedUntil - Date.now()) / 1000);
      return {
        locked: true,
        remainingSec,
        reason: `Cuenta protegida temporalmente por múltiples intentos fallidos. Intenta de nuevo en ${remainingSec}s.`,
      };
    }
    if (record.lockedUntil && Date.now() >= record.lockedUntil) {
      this.failedAttempts.delete(identifier);
    }
    return { locked: false };
  }

  recordFailure(identifier) {
    const current = this.failedAttempts.get(identifier) || { count: 0, lockedUntil: null };
    current.count += 1;
    if (current.count >= MAX_FAILED_ATTEMPTS) {
      current.lockedUntil = Date.now() + LOCKOUT_DURATION_MS;
    }
    this.failedAttempts.set(identifier, current);
    return {
      attemptsRemaining: Math.max(0, MAX_FAILED_ATTEMPTS - current.count),
      locked: Boolean(current.lockedUntil),
    };
  }

  clearFailures(identifier) {
    this.failedAttempts.delete(identifier);
  }

  authenticateOperator({
    username,
    password,
    pin,
    gateId = 'PUERTA-NORTE-01',
    scannerId = 'IPHONE-IOS',
    forceRelease = false,
  }) {
    this.init();
    const startHr = process.hrtime.bigint();
    const cleanUser = String(username || '').trim().toLowerCase();

    const lockStatus = this.checkLockout(cleanUser);
    if (lockStatus.locked) {
      return {
        ok: false,
        status: 429,
        error: lockStatus.reason,
      };
    }

    const operator = this.findOperator(cleanUser);

    // Si el usuario no existe, realizamos un cálculo PBKDF2 dummy para evitar ataques de enumeración por tiempo (Timing Attack)
    if (!operator) {
      hashPasswordPbkdf2(String(password || 'dummy'));
      const failInfo = this.recordFailure(cleanUser);
      return {
        ok: false,
        status: 401,
        error: `Credenciales inválidas. Intentos restantes antes de bloqueo: ${failInfo.attemptsRemaining}.`,
      };
    }

    const isPasswordValid = verifyPasswordPbkdf2(
      String(password || ''),
      operator.passwordSalt,
      operator.passwordHash
    );
    const isPinValid = verifyPasswordPbkdf2(
      String(pin || ''),
      operator.pinSalt,
      operator.pinHash
    );

    if (!isPasswordValid || !isPinValid) {
      const failInfo = this.recordFailure(cleanUser);
      return {
        ok: false,
        status: 401,
        error: !isPasswordValid
          ? `Contraseña incorrecta. Intentos restantes: ${failInfo.attemptsRemaining}.`
          : `PIN de seguridad 2FA incorrecto. Intentos restantes: ${failInfo.attemptsRemaining}.`,
      };
    }

    this.clearFailures(cleanUser);

    // VALIDACIÓN DE SESIÓN ÚNICA POR DISPOSITIVO (Anti-Sesión Concurrente)
    const activeCheck = this.isOperatorAlreadyLoggedIn(operator.operatorId, scannerId);
    if (activeCheck.loggedIn && !forceRelease) {
      const s = activeCheck.session;
      return {
        ok: false,
        status: 409,
        code: 'ALREADY_LOGGED_IN_OTHER_DEVICE',
        activeSession: s,
        error: `Sesión bloqueada: ${operator.name} (${operator.operatorId}) ya tiene una sesión activa en el dispositivo "${s.scannerId}" (${s.gateId}). Cierra sesión en ese dispositivo antes de ingresar en otro.`,
      };
    }

    // Si se solicitó liberar/revocar la sesión previa explícitamente (con contraseña y PIN 2FA válidos)
    if (activeCheck.loggedIn && forceRelease && activeCheck.session?.jti) {
      this.revokedTokens.add(activeCheck.session.jti);
      this.activeSessions.delete(operator.operatorId);
    }

    const jwtToken = signScannerJwt(
      {
        sub: operator.operatorId,
        operatorId: operator.operatorId,
        operatorName: operator.name,
        email: operator.email,
        badgeRole: operator.badgeRole,
        role: operator.role,
        gateId,
        scannerId,
      },
      db.state.pkiKey.privateKeyPem
    );

    // Decodificar el payload firmado para registrar el JTI activo de este dispositivo
    const pki = db.getPkiInfo();
    const decoded = verifyScannerJwt(jwtToken, pki.publicKeyPem);
    const sessionRecord = {
      operatorId: operator.operatorId,
      name: operator.name,
      jti: decoded.payload?.jti,
      scannerId,
      gateId,
      loginAtIso: new Date().toISOString(),
      expiresAtSec: decoded.payload?.exp,
    };
    this.activeSessions.set(operator.operatorId, sessionRecord);

    const latencyMs = Number(Number(process.hrtime.bigint() - startHr) / 1e6).toFixed(2);

    return {
      ok: true,
      status: 200,
      operator: {
        operatorId: operator.operatorId,
        name: operator.name,
        email: operator.email,
        badgeRole: operator.badgeRole,
        gateId,
        scannerId,
      },
      security: {
        jwtToken,
        jti: sessionRecord.jti,
        singleDeviceLockActive: true,
        tokenType: 'Bearer',
        signatureAlgorithm: 'ES256 (ECDSA secp256r1 / NIST P-256)',
        passwordKdf: `PBKDF2-HMAC-SHA512 (${PBKDF2_ITERATIONS.toLocaleString()} iteraciones + 128-bit Salt)`,
        twoFactorPinVerified: true,
        pkiCertificateFingerprint: pki.certificateFingerprint,
        authComputeMs: Number(latencyMs),
      },
    };
  }

  verifySessionToken(authHeader) {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return { valid: false, reason: 'Encabezado Authorization Bearer requerido' };
    }
    const token = authHeader.slice(7).trim();
    const pki = db.getPkiInfo();
    const verified = verifyScannerJwt(token, pki.publicKeyPem);
    if (!verified.valid) return verified;

    const { jti, operatorId } = verified.payload || {};
    if (jti && this.revokedTokens.has(jti)) {
      return { valid: false, reason: 'La sesión del operador fue revocada o cerrada' };
    }

    // Verificar además que el token corresponda a la sesión única activa del operador
    if (operatorId) {
      const currentActive = this.activeSessions.get(operatorId);
      if (!currentActive || currentActive.jti !== jti) {
        return {
          valid: false,
          reason: 'Este dispositivo ya no posee la sesión activa del operador',
        };
      }
    }

    return verified;
  }

  revokeSessionToken(authHeader) {
    if (!authHeader || !authHeader.startsWith('Bearer ')) return false;
    const token = authHeader.slice(7).trim();
    const pki = db.getPkiInfo();
    const verified = verifyScannerJwt(token, pki.publicKeyPem);
    if (verified.valid && verified.payload) {
      const { jti, operatorId } = verified.payload;
      if (jti) this.revokedTokens.add(jti);
      if (operatorId) {
        const active = this.activeSessions.get(operatorId);
        if (active && active.jti === jti) {
          this.activeSessions.delete(operatorId);
        }
      }
      return true;
    }
    return false;
  }
}

module.exports = new ScannerAuthService();
