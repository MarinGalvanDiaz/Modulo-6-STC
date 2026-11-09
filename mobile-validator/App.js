import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  StyleSheet,
  Text,
  View,
  TouchableOpacity,
  ScrollView,
  TextInput,
  Image,
  ActivityIndicator,
  Platform,
  SafeAreaView,
  StatusBar,
  Alert,
  Modal,
  NativeModules,
} from 'react-native';
import { CameraView, useCameraPermissions } from 'expo-camera';
import * as Haptics from 'expo-haptics';
import { io } from 'socket.io-client';

// Detecta automáticamente la IP de la PC desde el packager de Expo en el iPhone
function getDefaultServerUrl() {
  if (Platform.OS === 'web' && typeof window !== 'undefined') {
    return window.location.origin.includes(':4000')
      ? window.location.origin
      : 'http://localhost:4000';
  }
  try {
    const scriptURL = NativeModules?.SourceCode?.scriptURL;
    if (scriptURL) {
      const match = scriptURL.match(/^https?:\/\/([^:/]+)/);
      if (match && match[1] && match[1] !== 'localhost' && match[1] !== '127.0.0.1') {
        return `http://${match[1]}:4000`;
      }
    }
  } catch (e) {}
  return 'http://10.100.86.55:4000';
}

const GATES = [
  { id: 'PUERTA-NORTE-01', label: 'Puerta Norte' },
  { id: 'TORNIQUETE-VIP-02', label: 'Acceso VIP' },
  { id: 'ACCESO-SUR-03', label: 'Puerta Sur' },
  { id: 'ACCESO-PALCOS-04', label: 'Palcos' },
];

const STATUS_CONFIG = {
  VALID: {
    color: '#00A859',
    lightBg: '#ECFDF5',
    label: 'BOLETO VÁLIDO',
    sub: 'Firma ECDSA y código dinámico verificados',
  },
  ALREADY_USED: {
    color: '#026CDF',
    lightBg: '#EFF6FF',
    label: 'YA INGRESÓ',
    sub: 'Este boleto ya fue utilizado previamente',
  },
  REPLAY: {
    color: '#EA580C',
    lightBg: '#FFF7ED',
    label: 'QR EXPIRADO (REPLAY)',
    sub: 'La ventana de seguridad de 15s ha caducado',
  },
  FAKE: {
    color: '#E11D48',
    lightBg: '#FFF1F2',
    label: 'BOLETO FALSO',
    sub: 'Firma criptográfica o código HMAC inválido',
  },
};

export default function App() {
  const [activeTab, setActiveTab] = useState('SCANNER'); // 'SCANNER' | 'WALLET' | 'AUDIT'
  const [serverUrl, setServerUrl] = useState(getDefaultServerUrl);
  const [tempUrlInput, setTempUrlInput] = useState(getDefaultServerUrl);
  const [showConfigModal, setShowConfigModal] = useState(false);

  const [connected, setConnected] = useState(false);
  const [selectedGate, setSelectedGate] = useState(GATES[0].id);
  const [scannerId] = useState(`IPHONE-${Platform.OS.toUpperCase()}`);
  const [scannerJwt, setScannerJwt] = useState(null);

  // Camera & Scanner state
  const [permission, requestPermission] = useCameraPermissions();
  const [scanLocked, setScanLocked] = useState(false);
  const [lastScanResult, setLastScanResult] = useState(null);

  // Ref sincrónico para evitar dobles lecturas de cámara en iOS y no desmontar el callback nativo
  const scanLockedRef = useRef(false);
  const lastScannedDataRef = useRef({ data: null, time: 0 });

  // Audit & Occupancy state
  const [dashboard, setDashboard] = useState(null);
  const [verifyingChain, setVerifyingChain] = useState(false);

  // SafeTix Wallet state
  const [tickets, setTickets] = useState([]);
  const [selectedTicketId, setSelectedTicketId] = useState(null);
  const [qrMode, setQrMode] = useState('VALID');
  const [qrBundle, setQrBundle] = useState(null);
  const [totpCountdown, setTotpCountdown] = useState(15);

  const socketRef = useRef(null);
  const lastStepRef = useRef(null);

  const setLocked = (val) => {
    scanLockedRef.current = val;
    setScanLocked(val);
  };

  // Conexión al servidor y Socket.io en tiempo real
  const connectToServer = useCallback(
    async (baseUrl = serverUrl) => {
      const cleanUrl = baseUrl.trim().replace(/\/+$/, '');
      try {
        const healthRes = await fetch(`${cleanUrl}/api/health`);
        await healthRes.json();
        setConnected(true);

        const sessionRes = await fetch(`${cleanUrl}/api/pki/scanner-session`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            gateId: selectedGate,
            scannerId,
            operator: 'Staff Ticketmaster',
          }),
        });
        const sessionJson = await sessionRes.json();
        setScannerJwt(sessionJson.jwtToken);

        const [ticketsRes, dashRes] = await Promise.all([
          fetch(`${cleanUrl}/api/tickets`).then((r) => r.json()),
          fetch(`${cleanUrl}/api/audit/dashboard`).then((r) => r.json()),
        ]);

        const list = ticketsRes.tickets || [];
        setTickets(list);
        if (list.length > 0 && !selectedTicketId) {
          setSelectedTicketId(list[0].ticketId);
        }
        setDashboard(dashRes);

        if (socketRef.current) {
          socketRef.current.disconnect();
        }
        const socket = io(cleanUrl, { transports: ['websocket', 'polling'] });
        socket.on('connect', () => setConnected(true));
        socket.on('disconnect', () => setConnected(false));
        socket.on('stats:updated', (newDash) => {
          setDashboard(newDash);
          fetch(`${cleanUrl}/api/tickets`)
            .then((r) => r.json())
            .then((d) => setTickets(d.tickets || []))
            .catch(() => {});
        });
        socketRef.current = socket;
      } catch (err) {
        setConnected(false);
      }
    },
    [serverUrl, selectedGate, scannerId, selectedTicketId]
  );

  useEffect(() => {
    connectToServer(serverUrl);
    return () => {
      if (socketRef.current) socketRef.current.disconnect();
    };
  }, [serverUrl]);

  // Obtener QR dinámico de 15 segundos
  const fetchDynamicQr = useCallback(async () => {
    if (!selectedTicketId || !connected) return;
    try {
      const cleanUrl = serverUrl.trim().replace(/\/+$/, '');
      const res = await fetch(
        `${cleanUrl}/api/simulator/qr/${selectedTicketId}?mode=${qrMode}`
      );
      const data = await res.json();
      if (!data.error) {
        setQrBundle(data);
        lastStepRef.current = data.totp.currentStep;
      }
    } catch (e) {}
  }, [selectedTicketId, qrMode, serverUrl, connected]);

  useEffect(() => {
    fetchDynamicQr();
  }, [fetchDynamicQr]);

  // Temporizador TOTP de 15 segundos
  useEffect(() => {
    const interval = setInterval(() => {
      const nowMs = Date.now();
      const step = Math.floor(nowMs / 15000);
      const secInto = Math.floor((nowMs / 1000) % 15);
      setTotpCountdown(15 - secInto);

      if (lastStepRef.current !== null && step !== lastStepRef.current) {
        lastStepRef.current = step;
        fetchDynamicQr();
      }
    }, 1000);
    return () => clearInterval(interval);
  }, [fetchDynamicQr]);

  const triggerHaptic = async (status) => {
    if (Platform.OS === 'web') return;
    try {
      if (status === 'VALID') {
        await Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
      } else if (status === 'REPLAY' || status === 'ALREADY_USED') {
        await Haptics.notificationAsync(Haptics.NotificationFeedbackType.Warning);
      } else {
        await Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
      }
    } catch (e) {}
  };

  // Validación del QR contra el backend
  const validateQrPayload = useCallback(
    async (rawQrString) => {
      try {
        const cleanUrl = serverUrl.trim().replace(/\/+$/, '');
        const response = await fetch(`${cleanUrl}/api/access/validate`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(scannerJwt ? { Authorization: `Bearer ${scannerJwt}` } : {}),
          },
          body: JSON.stringify({
            qrData: rawQrString,
            gateId: selectedGate,
            scannerId,
          }),
        });
        const result = await response.json();
        setLastScanResult(result);
        await triggerHaptic(result.status);
      } catch (err) {
        setLocked(false);
        Alert.alert(
          'Sin conexión al servidor',
          `Verifica que tu iPhone esté en la misma red Wi-Fi (${serverUrl}).`
        );
      }
    },
    [serverUrl, scannerJwt, selectedGate, scannerId]
  );

  // Callback estable para CameraView en iOS (evita que la cámara se ponga negra)
  const handleBarcodeScanned = useCallback(
    (scanningResult) => {
      if (scanLockedRef.current) return;
      const data = scanningResult?.data;
      if (!data) return;

      const now = Date.now();
      if (
        lastScannedDataRef.current.data === data &&
        now - lastScannedDataRef.current.time < 2000
      ) {
        return;
      }

      scanLockedRef.current = true;
      lastScannedDataRef.current = { data, time: now };
      setScanLocked(true);
      validateQrPayload(data);
    },
    [validateQrPayload]
  );

  const runQuickSimulation = async (mode) => {
    const targetTicket = selectedTicketId || (tickets[0] && tickets[0].ticketId);
    if (!targetTicket) return;
    try {
      setLocked(true);
      const cleanUrl = serverUrl.trim().replace(/\/+$/, '');
      const simRes = await fetch(
        `${cleanUrl}/api/simulator/qr/${targetTicket}?mode=${mode}`
      );
      const simBundle = await simRes.json();
      if (simBundle && simBundle.qrRawString) {
        await validateQrPayload(simBundle.qrRawString);
      } else {
        setLocked(false);
      }
    } catch (e) {
      setLocked(false);
    }
  };

  const handleResetTicket = async (ticketId) => {
    try {
      const cleanUrl = serverUrl.trim().replace(/\/+$/, '');
      await fetch(`${cleanUrl}/api/tickets/${ticketId}/reset`, { method: 'POST' });
      lastScannedDataRef.current = { data: null, time: 0 };
      await fetchDynamicQr();
      setLastScanResult(null);
      setLocked(false);
    } catch (e) {}
  };

  const handleResetAllTickets = async () => {
    try {
      const cleanUrl = serverUrl.trim().replace(/\/+$/, '');
      await fetch(`${cleanUrl}/api/tickets/reset-all`, { method: 'POST' });
      lastScannedDataRef.current = { data: null, time: 0 };
      await fetchDynamicQr();
      setLastScanResult(null);
      setLocked(false);
    } catch (e) {}
  };

  const handleVerifyHashChain = async () => {
    setVerifyingChain(true);
    try {
      const cleanUrl = serverUrl.trim().replace(/\/+$/, '');
      const res = await fetch(`${cleanUrl}/api/audit/verify-chain`);
      const report = await res.json();
      Alert.alert(
        report.intact ? 'Libro Mayor Íntegro' : 'Cadena Alterada',
        report.intact
          ? `${report.totalBlocks} bloques SHA-256 verificados sin alteraciones.`
          : report.reason
      );
    } catch (e) {
      Alert.alert('Error', 'No se pudo verificar la cadena.');
    } finally {
      setVerifyingChain(false);
    }
  };

  // ============================================================================
  // PANTALLA 1: ESCÁNER DE ACCESO (ESTILO TICKETMASTER MINIMALISTA)
  // ============================================================================
  const renderScannerTab = () => {
    const statusCfg = lastScanResult
      ? STATUS_CONFIG[lastScanResult.status] || STATUS_CONFIG.FAKE
      : null;

    return (
      <ScrollView
        style={styles.screenScroll}
        contentContainerStyle={styles.screenContainer}
        showsVerticalScrollIndicator={false}
      >
        {/* Selector minimalista de Puerta */}
        <ScrollView
          horizontal
          showsHorizontalScrollIndicator={false}
          contentContainerStyle={styles.gateRow}
        >
          {GATES.map((g) => {
            const active = selectedGate === g.id;
            return (
              <TouchableOpacity
                key={g.id}
                style={[styles.gatePill, active && styles.gatePillActive]}
                onPress={() => setSelectedGate(g.id)}
              >
                <Text style={[styles.gatePillText, active && styles.gatePillTextActive]}>
                  {g.label}
                </Text>
              </TouchableOpacity>
            );
          })}
        </ScrollView>

        {/* Visor de Cámara iPhone */}
        <View style={styles.scannerWrapper}>
          {!permission ? (
            <View style={styles.cameraEmpty}>
              <ActivityIndicator color="#026CDF" />
            </View>
          ) : !permission.granted ? (
            <View style={styles.cameraEmpty}>
              <Text style={styles.cameraEmptyTitle}>Acceso a Cámara Requerido</Text>
              <Text style={styles.cameraEmptySub}>
                Habilita la cámara para escanear boletos SafeTix™ en puerta.
              </Text>
              <TouchableOpacity style={styles.tmButton} onPress={requestPermission}>
                <Text style={styles.tmButtonText}>Permitir Cámara</Text>
              </TouchableOpacity>
            </View>
          ) : (
            <View style={styles.cameraViewport}>
              <CameraView
                style={styles.cameraViewFull}
                facing="back"
                barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
                onBarcodeScanned={handleBarcodeScanned}
              />
              {/* Esquinas minimalistas de enfoque */}
              <View style={styles.reticleContainer} pointerEvents="none">
                <View
                  style={[
                    styles.reticleFrame,
                    statusCfg && scanLocked && { borderColor: statusCfg.color },
                  ]}
                />
              </View>

              <View style={styles.cameraBottomPill} pointerEvents="none">
                <Text style={styles.cameraBottomText}>
                  {scanLocked ? 'Lectura completada' : 'Apunta al código QR del boleto'}
                </Text>
              </View>
            </View>
          )}
        </View>

        {/* Resultado del Escaneo — Estilo Pase Ticketmaster */}
        {lastScanResult && statusCfg ? (
          <View style={styles.tmResultCard}>
            <View style={[styles.tmResultHeader, { backgroundColor: statusCfg.color }]}>
              <View>
                <Text style={styles.tmResultStatus}>{statusCfg.label}</Text>
                <Text style={styles.tmResultSub}>{statusCfg.sub}</Text>
              </View>
              <View style={styles.tmLatencyBadge}>
                <Text style={styles.tmLatencyText}>{lastScanResult.latencyMs} ms</Text>
              </View>
            </View>

            {lastScanResult.ticket && (
              <View style={styles.tmSeatStrip}>
                <View style={styles.tmSeatCol}>
                  <Text style={styles.tmSeatLabel}>SECCIÓN</Text>
                  <Text style={styles.tmSeatValue}>{lastScanResult.ticket.section || '-'}</Text>
                </View>
                <View style={styles.tmSeatDivider} />
                <View style={styles.tmSeatCol}>
                  <Text style={styles.tmSeatLabel}>FILA</Text>
                  <Text style={styles.tmSeatValue}>
                    {lastScanResult.ticket.row ||
                      (lastScanResult.ticket.seatLabel
                        ? lastScanResult.ticket.seatLabel.split('-')[0]
                        : '-')}
                  </Text>
                </View>
                <View style={styles.tmSeatDivider} />
                <View style={styles.tmSeatCol}>
                  <Text style={styles.tmSeatLabel}>ASIENTO</Text>
                  <Text style={styles.tmSeatValue}>
                    {lastScanResult.ticket.seat ||
                      (lastScanResult.ticket.seatLabel
                        ? lastScanResult.ticket.seatLabel.split('-')[1]
                        : '-')}
                  </Text>
                </View>
              </View>
            )}

            <View style={styles.tmResultBody}>
              {lastScanResult.ticket?.buyerName && (
                <Text style={styles.tmHolderName}>{lastScanResult.ticket.buyerName}</Text>
              )}
              <Text style={styles.tmDetailMessage}>{lastScanResult.message}</Text>

              <View style={styles.tmActionRow}>
                <TouchableOpacity
                  style={[styles.tmButton, { flex: 1 }]}
                  onPress={() => {
                    lastScannedDataRef.current = { data: null, time: 0 };
                    setLocked(false);
                  }}
                >
                  <Text style={styles.tmButtonText}>Escanear Siguiente</Text>
                </TouchableOpacity>

                {lastScanResult.status === 'ALREADY_USED' && lastScanResult.ticket?.ticketId && (
                  <TouchableOpacity
                    style={[styles.tmOutlineButton, { marginLeft: 10 }]}
                    onPress={() => handleResetTicket(lastScanResult.ticket.ticketId)}
                  >
                    <Text style={styles.tmOutlineButtonText}>Restaurar</Text>
                  </TouchableOpacity>
                )}
              </View>
            </View>
          </View>
        ) : (
          <View style={styles.idleCard}>
            <Text style={styles.idleTitle}>Listo para validar</Text>
            <Text style={styles.idleSub}>
              Escanea el código QR desde la pantalla de tu computadora o usa las pruebas rápidas.
            </Text>
          </View>
        )}

        {/* Barra minimalista de simulación rápida */}
        <View style={styles.quickTestSection}>
          <View style={styles.rowBetween}>
            <Text style={styles.quickTestTitle}>PRUEBA RÁPIDA DE ESCENARIOS</Text>
            <TouchableOpacity onPress={handleResetAllTickets}>
              <Text style={styles.resetLink}>Restaurar boletos</Text>
            </TouchableOpacity>
          </View>
          <View style={styles.quickTestRow}>
            <TouchableOpacity
              style={styles.quickPill}
              onPress={() => runQuickSimulation('VALID')}
            >
              <View style={[styles.dot, { backgroundColor: '#00A859' }]} />
              <Text style={styles.quickPillText}>Válido</Text>
            </TouchableOpacity>

            <TouchableOpacity
              style={styles.quickPill}
              onPress={() => runQuickSimulation('REPLAY')}
            >
              <View style={[styles.dot, { backgroundColor: '#EA580C' }]} />
              <Text style={styles.quickPillText}>Replay</Text>
            </TouchableOpacity>

            <TouchableOpacity
              style={styles.quickPill}
              onPress={() => runQuickSimulation('FAKE_SIGNATURE')}
            >
              <View style={[styles.dot, { backgroundColor: '#E11D48' }]} />
              <Text style={styles.quickPillText}>Falso</Text>
            </TouchableOpacity>

            <TouchableOpacity
              style={styles.quickPill}
              onPress={() => runQuickSimulation('FAKE_HMAC')}
            >
              <View style={[styles.dot, { backgroundColor: '#64748B' }]} />
              <Text style={styles.quickPillText}>Sin Llave</Text>
            </TouchableOpacity>
          </View>
        </View>
      </ScrollView>
    );
  };

  // ============================================================================
  // PANTALLA 2: BOLETO DIGITAL (ESTILO TICKETMASTER SAFETIX™)
  // ============================================================================
  const renderWalletTab = () => {
    return (
      <ScrollView
        style={styles.screenScroll}
        contentContainerStyle={styles.screenContainer}
        showsVerticalScrollIndicator={false}
      >
        {/* Selector horizontal de boleto */}
        <ScrollView
          horizontal
          showsHorizontalScrollIndicator={false}
          contentContainerStyle={styles.gateRow}
        >
          {tickets.map((t) => {
            const active = t.ticketId === selectedTicketId;
            return (
              <TouchableOpacity
                key={t.ticketId}
                style={[styles.gatePill, active && styles.gatePillActive]}
                onPress={() => setSelectedTicketId(t.ticketId)}
              >
                <Text style={[styles.gatePillText, active && styles.gatePillTextActive]}>
                  {t.section} {t.row}-{t.seat} {t.status === 'USED' ? '• Usado' : ''}
                </Text>
              </TouchableOpacity>
            );
          })}
        </ScrollView>

        {/* Tarjeta de Boleto Estilo Ticketmaster SafeTix */}
        {qrBundle && (
          <View style={styles.tmTicketPass}>
            {/* Encabezado Azul Ticketmaster */}
            <View style={styles.tmPassTopBar}>
              <Text style={styles.tmPassEventType}>BOLETO SAFETIX™ • ECDSA P-256</Text>
              <Text style={styles.tmPassEventTitle} numberOfLines={1}>
                Concierto Sinfónico STC 2026
              </Text>
              <Text style={styles.tmPassVenue}>Gran Auditorio Nacional</Text>
            </View>

            {/* Franja de Sección / Fila / Asiento */}
            <View style={styles.tmPassSeatBar}>
              <View style={styles.tmSeatCol}>
                <Text style={styles.tmPassSeatLbl}>SECCIÓN</Text>
                <Text style={styles.tmPassSeatVal}>{qrBundle.ticket.section}</Text>
              </View>
              <View style={styles.tmSeatCol}>
                <Text style={styles.tmPassSeatLbl}>FILA</Text>
                <Text style={styles.tmPassSeatVal}>{qrBundle.ticket.row}</Text>
              </View>
              <View style={styles.tmSeatCol}>
                <Text style={styles.tmPassSeatLbl}>ASIENTO</Text>
                <Text style={styles.tmPassSeatVal}>{qrBundle.ticket.seat}</Text>
              </View>
            </View>

            {/* Cuerpo Blanco con QR Rotativo */}
            <View style={styles.tmPassQrSection}>
              <Image
                source={{ uri: qrBundle.qrDataUrl }}
                style={styles.tmQrImage}
                resizeMode="contain"
              />

              {/* Barra animada de 15 segundos estilo SafeTix */}
              <View style={styles.safetixBarWrap}>
                <View style={styles.safetixTrack}>
                  <View
                    style={[
                      styles.safetixFill,
                      { width: `${(totpCountdown / 15) * 100}%` },
                    ]}
                  />
                </View>
                <View style={styles.rowBetween}>
                  <Text style={styles.safetixCaption}>
                    Las capturas de pantalla no son válidas
                  </Text>
                  <Text style={styles.safetixTimer}>{totpCountdown}s</Text>
                </View>
              </View>

              <Text style={styles.tmPassHolder}>
                {qrBundle.ticket.buyerName} • {qrBundle.ticket.ticketId}
              </Text>
            </View>
          </View>
        )}

        {/* Selector de modo de prueba para el QR */}
        <View style={styles.quickTestSection}>
          <View style={styles.rowBetween}>
            <Text style={styles.quickTestTitle}>MODO DEL QR EN PANTALLA</Text>
            {selectedTicketId && (
              <TouchableOpacity onPress={() => handleResetTicket(selectedTicketId)}>
                <Text style={styles.resetLink}>Restaurar este boleto</Text>
              </TouchableOpacity>
            )}
          </View>
          <View style={styles.quickTestRow}>
            {[
              { id: 'VALID', label: 'Válido' },
              { id: 'REPLAY', label: 'Replay' },
              { id: 'FAKE_SIGNATURE', label: 'Firma Falsa' },
              { id: 'FAKE_HMAC', label: 'HMAC Falso' },
            ].map((m) => {
              const active = qrMode === m.id;
              return (
                <TouchableOpacity
                  key={m.id}
                  style={[styles.quickPill, active && styles.quickPillActive]}
                  onPress={() => setQrMode(m.id)}
                >
                  <Text
                    style={[styles.quickPillText, active && styles.quickPillTextActive]}
                  >
                    {m.label}
                  </Text>
                </TouchableOpacity>
              );
            })}
          </View>
        </View>
      </ScrollView>
    );
  };

  // ============================================================================
  // PANTALLA 3: AFORO Y LIBRO MAYOR DE AUDITORÍA (MINIMALISTA)
  // ============================================================================
  const renderAuditTab = () => {
    if (!dashboard) {
      return (
        <View style={styles.centerEmpty}>
          <ActivityIndicator size="large" color="#026CDF" />
        </View>
      );
    }

    const { occupancy, securityCounters, chainIntegrity, recentLedger } = dashboard;

    return (
      <ScrollView
        style={styles.screenScroll}
        contentContainerStyle={styles.screenContainer}
        showsVerticalScrollIndicator={false}
      >
        {/* Tarjeta Principal de Aforo */}
        <View style={styles.whiteCard}>
          <View style={styles.rowBetween}>
            <View>
              <Text style={styles.cardEyebrow}>AFORO DEL AUDITORIO</Text>
              <Text style={styles.bigOccupancyNumber}>
                {occupancy.checkedInCount}{' '}
                <Text style={styles.bigOccupancyTotal}>/ {occupancy.totalCapacity}</Text>
              </Text>
            </View>
            <View style={styles.occupancyBadge}>
              <Text style={styles.occupancyBadgeText}>
                {occupancy.capacityOccupancyPercent}%
              </Text>
            </View>
          </View>

          <View style={styles.mainProgressTrack}>
            <View
              style={[
                styles.mainProgressFill,
                { width: `${Math.min(100, occupancy.capacityOccupancyPercent)}%` },
              ]}
            />
          </View>

          <View style={styles.sectionGrid}>
            {occupancy.sections.map((s) => (
              <View key={s.section} style={styles.sectionMiniCard}>
                <Text style={styles.sectionMiniName}>{s.section}</Text>
                <Text style={styles.sectionMiniVal}>
                  {s.inside}/{s.capacity}
                </Text>
              </View>
            ))}
          </View>
        </View>

        {/* Resumen de Seguridad en 4 Cajas Limpias */}
        <View style={styles.metricsRow}>
          <View style={styles.metricBox}>
            <Text style={[styles.metricNum, { color: '#00A859' }]}>
              {securityCounters.validEntries}
            </Text>
            <Text style={styles.metricLbl}>Válidos</Text>
          </View>
          <View style={styles.metricBox}>
            <Text style={[styles.metricNum, { color: '#EA580C' }]}>
              {securityCounters.replayBlocked}
            </Text>
            <Text style={styles.metricLbl}>Replay</Text>
          </View>
          <View style={styles.metricBox}>
            <Text style={[styles.metricNum, { color: '#E11D48' }]}>
              {securityCounters.fakeRejected}
            </Text>
            <Text style={styles.metricLbl}>Falsos</Text>
          </View>
          <View style={styles.metricBox}>
            <Text style={[styles.metricNum, { color: '#026CDF' }]}>
              {securityCounters.alreadyUsedBlocked}
            </Text>
            <Text style={styles.metricLbl}>Ya Usados</Text>
          </View>
        </View>

        {/* Libro Mayor de Auditoría Hash-Chain */}
        <View style={styles.whiteCard}>
          <View style={styles.rowBetween}>
            <View>
              <Text style={styles.cardEyebrow}>LIBRO MAYOR (SHA-256 HASH-CHAIN)</Text>
              <Text style={styles.chainStatusTitle}>
                {chainIntegrity.intact
                  ? `Cadena Íntegra • ${chainIntegrity.totalBlocks} bloques`
                  : 'Alerta: Cadena Comprometida'}
              </Text>
            </View>
            <TouchableOpacity
              style={styles.verifyPill}
              onPress={handleVerifyHashChain}
              disabled={verifyingChain}
            >
              <Text style={styles.verifyPillText}>
                {verifyingChain ? '...' : 'Verificar'}
              </Text>
            </TouchableOpacity>
          </View>

          <View style={{ marginTop: 12 }}>
            {recentLedger.slice(0, 15).map((block) => {
              const cfg = STATUS_CONFIG[block.validationResult] || STATUS_CONFIG.FAKE;
              return (
                <View key={block.blockIndex} style={styles.logRow}>
                  <View style={[styles.logStatusDot, { backgroundColor: cfg.color }]} />
                  <View style={{ flex: 1 }}>
                    <View style={styles.rowBetween}>
                      <Text style={styles.logMainText}>
                        #{block.blockIndex} • {block.ticketId} ({block.section} {block.seatLabel})
                      </Text>
                      <Text style={[styles.logTag, { color: cfg.color }]}>
                        {block.validationResult}
                      </Text>
                    </View>
                    <Text style={styles.logHashText} numberOfLines={1}>
                      {block.gateId} • {block.latencyMs}ms • SHA256: {block.blockHash.slice(0, 16)}...
                    </Text>
                  </View>
                </View>
              );
            })}
          </View>
        </View>
      </ScrollView>
    );
  };

  return (
    <SafeAreaView style={styles.safeRoot}>
      <StatusBar barStyle="light-content" backgroundColor="#026CDF" />

      {/* Header Estilo Ticketmaster (Con espacio libre a la derecha para el botón de Expo Go en iPhone) */}
      <View style={styles.tmHeader}>
        <View>
          <Text style={styles.tmBrand}>ticketmaster</Text>
          <TouchableOpacity
            style={styles.connectionPill}
            onPress={() => {
              setTempUrlInput(serverUrl);
              setShowConfigModal(true);
            }}
          >
            <View
              style={[
                styles.connDot,
                { backgroundColor: connected ? '#34D399' : '#FB7185' },
              ]}
            />
            <Text style={styles.connText}>
              {connected ? 'Conectado' : 'Sin conexión'} • Ajustar IP
            </Text>
          </TouchableOpacity>
        </View>
      </View>

      {/* Contenido Principal */}
      <View style={styles.body}>{activeTab === 'SCANNER' && renderScannerTab()}
        {activeTab === 'WALLET' && renderWalletTab()}
        {activeTab === 'AUDIT' && renderAuditTab()}
      </View>

      {/* Navegación Inferior Minimalista */}
      <View style={styles.tabBar}>
        <TouchableOpacity
          style={styles.tabItem}
          onPress={() => setActiveTab('SCANNER')}
        >
          <Text style={[styles.tabLabel, activeTab === 'SCANNER' && styles.tabLabelActive]}>
            Escáner
          </Text>
          {activeTab === 'SCANNER' && <View style={styles.tabIndicator} />}
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.tabItem}
          onPress={() => setActiveTab('WALLET')}
        >
          <Text style={[styles.tabLabel, activeTab === 'WALLET' && styles.tabLabelActive]}>
            Boletos QR
          </Text>
          {activeTab === 'WALLET' && <View style={styles.tabIndicator} />}
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.tabItem}
          onPress={() => setActiveTab('AUDIT')}
        >
          <Text style={[styles.tabLabel, activeTab === 'AUDIT' && styles.tabLabelActive]}>
            Auditoría
          </Text>
          {activeTab === 'AUDIT' && <View style={styles.tabIndicator} />}
        </TouchableOpacity>
      </View>

      {/* Modal Minimalista de Configuración de Red */}
      <Modal visible={showConfigModal} transparent animationType="fade">
        <View style={styles.modalOverlay}>
          <View style={styles.modalSheet}>
            <Text style={styles.modalTitle}>Servidor de Validación</Text>
            <Text style={styles.modalSub}>
              Dirección IP local de tu computadora corriendo el backend Node.js:
            </Text>
            <TextInput
              style={styles.modalInput}
              value={tempUrlInput}
              onChangeText={setTempUrlInput}
              autoCapitalize="none"
              autoCorrect={false}
              placeholder="http://10.100.86.55:4000"
              placeholderTextColor="#94A3B8"
            />
            <View style={styles.rowBetween}>
              <TouchableOpacity
                style={[styles.tmOutlineButton, { flex: 1, marginRight: 8 }]}
                onPress={() => setShowConfigModal(false)}
              >
                <Text style={styles.tmOutlineButtonText}>Cancelar</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[styles.tmButton, { flex: 1, marginLeft: 8 }]}
                onPress={() => {
                  setServerUrl(tempUrlInput.trim());
                  setShowConfigModal(false);
                }}
              >
                <Text style={styles.tmButtonText}>Conectar</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safeRoot: {
    flex: 1,
    backgroundColor: '#026CDF',
  },
  tmHeader: {
    backgroundColor: '#026CDF',
    paddingHorizontal: 20,
    paddingTop: 6,
    paddingBottom: 14,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  tmBrand: {
    color: '#FFFFFF',
    fontSize: 22,
    fontWeight: '900',
    fontStyle: 'italic',
    letterSpacing: -0.5,
  },
  connectionPill: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: 'rgba(255,255,255,0.16)',
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 99,
    marginTop: 4,
    alignSelf: 'flex-start',
  },
  connDot: {
    width: 7,
    height: 7,
    borderRadius: 4,
    marginRight: 6,
  },
  connText: {
    color: '#FFFFFF',
    fontSize: 11,
    fontWeight: '600',
  },
  body: {
    flex: 1,
    backgroundColor: '#F4F6F9',
  },
  screenScroll: {
    flex: 1,
  },
  screenContainer: {
    padding: 16,
    paddingBottom: 32,
  },
  gateRow: {
    paddingBottom: 12,
    gap: 8,
  },
  gatePill: {
    backgroundColor: '#FFFFFF',
    paddingHorizontal: 14,
    paddingVertical: 8,
    borderRadius: 99,
    borderWidth: 1,
    borderColor: '#E2E8F0',
    marginRight: 8,
  },
  gatePillActive: {
    backgroundColor: '#026CDF',
    borderColor: '#026CDF',
  },
  gatePillText: {
    color: '#475569',
    fontSize: 13,
    fontWeight: '600',
  },
  gatePillTextActive: {
    color: '#FFFFFF',
    fontWeight: '700',
  },
  scannerWrapper: {
    borderRadius: 16,
    overflow: 'hidden',
    backgroundColor: '#0F172A',
    marginBottom: 14,
    shadowColor: '#0F172A',
    shadowOpacity: 0.08,
    shadowRadius: 12,
    shadowOffset: { width: 0, height: 4 },
    elevation: 3,
  },
  cameraViewport: {
    width: '100%',
    height: 260,
    backgroundColor: '#000000',
    position: 'relative',
    overflow: 'hidden',
  },
  cameraViewFull: {
    flex: 1,
    width: '100%',
    height: 260,
  },
  reticleContainer: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    alignItems: 'center',
    justifyContent: 'center',
  },
  reticleFrame: {
    width: 170,
    height: 170,
    borderWidth: 2,
    borderColor: 'rgba(255,255,255,0.85)',
    borderRadius: 18,
  },
  cameraBottomPill: {
    position: 'absolute',
    bottom: 12,
    alignSelf: 'center',
    backgroundColor: 'rgba(15, 23, 42, 0.75)',
    paddingHorizontal: 14,
    paddingVertical: 5,
    borderRadius: 99,
  },
  cameraBottomText: {
    color: '#FFFFFF',
    fontSize: 12,
    fontWeight: '600',
  },
  cameraEmpty: {
    height: 220,
    alignItems: 'center',
    justifyContent: 'center',
    padding: 24,
    backgroundColor: '#FFFFFF',
  },
  cameraEmptyTitle: {
    color: '#0F172A',
    fontSize: 16,
    fontWeight: '700',
    marginBottom: 4,
  },
  cameraEmptySub: {
    color: '#64748B',
    fontSize: 13,
    textAlign: 'center',
    marginBottom: 16,
  },
  tmResultCard: {
    backgroundColor: '#FFFFFF',
    borderRadius: 16,
    overflow: 'hidden',
    marginBottom: 14,
    shadowColor: '#0F172A',
    shadowOpacity: 0.08,
    shadowRadius: 12,
    shadowOffset: { width: 0, height: 4 },
    elevation: 3,
  },
  tmResultHeader: {
    paddingHorizontal: 18,
    paddingVertical: 14,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  tmResultStatus: {
    color: '#FFFFFF',
    fontSize: 16,
    fontWeight: '900',
    letterSpacing: 0.3,
  },
  tmResultSub: {
    color: 'rgba(255,255,255,0.9)',
    fontSize: 12,
    marginTop: 2,
  },
  tmLatencyBadge: {
    backgroundColor: 'rgba(0,0,0,0.2)',
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 99,
  },
  tmLatencyText: {
    color: '#FFFFFF',
    fontSize: 12,
    fontWeight: '700',
  },
  tmSeatStrip: {
    flexDirection: 'row',
    backgroundColor: '#F8FAFC',
    borderBottomWidth: 1,
    borderBottomColor: '#E2E8F0',
    paddingVertical: 12,
  },
  tmSeatCol: {
    flex: 1,
    alignItems: 'center',
  },
  tmSeatDivider: {
    width: 1,
    backgroundColor: '#E2E8F0',
  },
  tmSeatLabel: {
    color: '#64748B',
    fontSize: 10,
    fontWeight: '700',
    letterSpacing: 0.6,
  },
  tmSeatValue: {
    color: '#0F172A',
    fontSize: 18,
    fontWeight: '900',
    marginTop: 2,
  },
  tmResultBody: {
    padding: 16,
  },
  tmHolderName: {
    color: '#0F172A',
    fontSize: 15,
    fontWeight: '700',
    marginBottom: 4,
  },
  tmDetailMessage: {
    color: '#64748B',
    fontSize: 12,
    lineHeight: 17,
    marginBottom: 14,
  },
  tmActionRow: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  tmButton: {
    backgroundColor: '#026CDF',
    paddingVertical: 12,
    paddingHorizontal: 18,
    borderRadius: 10,
    alignItems: 'center',
    justifyContent: 'center',
  },
  tmButtonText: {
    color: '#FFFFFF',
    fontSize: 14,
    fontWeight: '700',
  },
  tmOutlineButton: {
    backgroundColor: '#FFFFFF',
    borderWidth: 1,
    borderColor: '#CBD5E1',
    paddingVertical: 12,
    paddingHorizontal: 16,
    borderRadius: 10,
    alignItems: 'center',
    justifyContent: 'center',
  },
  tmOutlineButtonText: {
    color: '#334155',
    fontSize: 14,
    fontWeight: '600',
  },
  idleCard: {
    backgroundColor: '#FFFFFF',
    borderRadius: 14,
    padding: 16,
    marginBottom: 14,
    borderWidth: 1,
    borderColor: '#E2E8F0',
  },
  idleTitle: {
    color: '#0F172A',
    fontSize: 14,
    fontWeight: '700',
  },
  idleSub: {
    color: '#64748B',
    fontSize: 12,
    marginTop: 2,
  },
  quickTestSection: {
    marginTop: 4,
  },
  quickTestTitle: {
    color: '#64748B',
    fontSize: 11,
    fontWeight: '700',
    letterSpacing: 0.5,
  },
  resetLink: {
    color: '#026CDF',
    fontSize: 12,
    fontWeight: '600',
  },
  quickTestRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginTop: 8,
    gap: 6,
  },
  quickPill: {
    flex: 1,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#FFFFFF',
    borderWidth: 1,
    borderColor: '#E2E8F0',
    paddingVertical: 10,
    borderRadius: 10,
  },
  quickPillActive: {
    backgroundColor: '#026CDF',
    borderColor: '#026CDF',
  },
  dot: {
    width: 7,
    height: 7,
    borderRadius: 4,
    marginRight: 5,
  },
  quickPillText: {
    color: '#334155',
    fontSize: 12,
    fontWeight: '600',
  },
  quickPillTextActive: {
    color: '#FFFFFF',
    fontWeight: '700',
  },
  // Ticketmaster SafeTix Pass
  tmTicketPass: {
    backgroundColor: '#FFFFFF',
    borderRadius: 18,
    overflow: 'hidden',
    marginBottom: 16,
    shadowColor: '#0F172A',
    shadowOpacity: 0.1,
    shadowRadius: 16,
    shadowOffset: { width: 0, height: 6 },
    elevation: 4,
  },
  tmPassTopBar: {
    backgroundColor: '#026CDF',
    paddingHorizontal: 18,
    paddingTop: 16,
    paddingBottom: 14,
  },
  tmPassEventType: {
    color: 'rgba(255,255,255,0.8)',
    fontSize: 10,
    fontWeight: '700',
    letterSpacing: 0.8,
  },
  tmPassEventTitle: {
    color: '#FFFFFF',
    fontSize: 18,
    fontWeight: '800',
    marginTop: 2,
  },
  tmPassVenue: {
    color: 'rgba(255,255,255,0.9)',
    fontSize: 12,
    marginTop: 2,
  },
  tmPassSeatBar: {
    backgroundColor: '#0153AD',
    flexDirection: 'row',
    paddingVertical: 12,
  },
  tmPassSeatLbl: {
    color: 'rgba(255,255,255,0.75)',
    fontSize: 10,
    fontWeight: '700',
  },
  tmPassSeatVal: {
    color: '#FFFFFF',
    fontSize: 18,
    fontWeight: '900',
    marginTop: 2,
  },
  tmPassQrSection: {
    padding: 20,
    alignItems: 'center',
  },
  tmQrImage: {
    width: 220,
    height: 220,
  },
  safetixBarWrap: {
    width: '100%',
    marginTop: 12,
    marginBottom: 10,
  },
  safetixTrack: {
    height: 5,
    backgroundColor: '#E2E8F0',
    borderRadius: 99,
    overflow: 'hidden',
    marginBottom: 6,
  },
  safetixFill: {
    height: '100%',
    backgroundColor: '#026CDF',
  },
  safetixCaption: {
    color: '#64748B',
    fontSize: 11,
    fontWeight: '500',
  },
  safetixTimer: {
    color: '#026CDF',
    fontSize: 12,
    fontWeight: '800',
  },
  tmPassHolder: {
    color: '#334155',
    fontSize: 12,
    fontWeight: '600',
    marginTop: 4,
  },
  // Audit & Occupancy
  whiteCard: {
    backgroundColor: '#FFFFFF',
    borderRadius: 16,
    padding: 16,
    marginBottom: 14,
    borderWidth: 1,
    borderColor: '#E2E8F0',
  },
  cardEyebrow: {
    color: '#64748B',
    fontSize: 11,
    fontWeight: '700',
    letterSpacing: 0.5,
  },
  bigOccupancyNumber: {
    color: '#0F172A',
    fontSize: 28,
    fontWeight: '900',
    marginTop: 2,
  },
  bigOccupancyTotal: {
    color: '#94A3B8',
    fontSize: 18,
    fontWeight: '600',
  },
  occupancyBadge: {
    backgroundColor: '#EFF6FF',
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderRadius: 99,
  },
  occupancyBadgeText: {
    color: '#026CDF',
    fontSize: 14,
    fontWeight: '800',
  },
  mainProgressTrack: {
    height: 8,
    backgroundColor: '#F1F5F9',
    borderRadius: 99,
    overflow: 'hidden',
    marginVertical: 14,
  },
  mainProgressFill: {
    height: '100%',
    backgroundColor: '#026CDF',
  },
  sectionGrid: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    gap: 8,
  },
  sectionMiniCard: {
    flex: 1,
    backgroundColor: '#F8FAFC',
    padding: 10,
    borderRadius: 10,
    alignItems: 'center',
  },
  sectionMiniName: {
    color: '#64748B',
    fontSize: 11,
    fontWeight: '600',
  },
  sectionMiniVal: {
    color: '#0F172A',
    fontSize: 14,
    fontWeight: '800',
    marginTop: 2,
  },
  metricsRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 14,
    gap: 8,
  },
  metricBox: {
    flex: 1,
    backgroundColor: '#FFFFFF',
    borderRadius: 12,
    paddingVertical: 12,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#E2E8F0',
  },
  metricNum: {
    fontSize: 20,
    fontWeight: '900',
  },
  metricLbl: {
    color: '#64748B',
    fontSize: 11,
    fontWeight: '600',
    marginTop: 2,
  },
  chainStatusTitle: {
    color: '#0F172A',
    fontSize: 15,
    fontWeight: '800',
    marginTop: 2,
  },
  verifyPill: {
    backgroundColor: '#026CDF',
    paddingHorizontal: 14,
    paddingVertical: 7,
    borderRadius: 99,
  },
  verifyPillText: {
    color: '#FFFFFF',
    fontSize: 12,
    fontWeight: '700',
  },
  logRow: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: 10,
    borderTopWidth: 1,
    borderTopColor: '#F1F5F9',
  },
  logStatusDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    marginRight: 10,
  },
  logMainText: {
    color: '#0F172A',
    fontSize: 13,
    fontWeight: '700',
  },
  logTag: {
    fontSize: 11,
    fontWeight: '800',
  },
  logHashText: {
    color: '#64748B',
    fontSize: 11,
    marginTop: 2,
  },
  rowBetween: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  centerEmpty: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  tabBar: {
    flexDirection: 'row',
    backgroundColor: '#FFFFFF',
    borderTopWidth: 1,
    borderTopColor: '#E2E8F0',
    paddingTop: 10,
    paddingBottom: Platform.OS === 'ios' ? 6 : 10,
  },
  tabItem: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  tabLabel: {
    color: '#64748B',
    fontSize: 13,
    fontWeight: '600',
    paddingBottom: 6,
  },
  tabLabelActive: {
    color: '#026CDF',
    fontWeight: '800',
  },
  tabIndicator: {
    width: 28,
    height: 3,
    borderRadius: 2,
    backgroundColor: '#026CDF',
  },
  modalOverlay: {
    flex: 1,
    backgroundColor: 'rgba(15, 23, 42, 0.5)',
    alignItems: 'center',
    justifyContent: 'center',
    padding: 20,
  },
  modalSheet: {
    width: '100%',
    maxWidth: 380,
    backgroundColor: '#FFFFFF',
    borderRadius: 18,
    padding: 20,
  },
  modalTitle: {
    color: '#0F172A',
    fontSize: 17,
    fontWeight: '800',
  },
  modalSub: {
    color: '#64748B',
    fontSize: 13,
    marginTop: 4,
    marginBottom: 14,
  },
  modalInput: {
    backgroundColor: '#F8FAFC',
    borderWidth: 1,
    borderColor: '#CBD5E1',
    borderRadius: 10,
    paddingHorizontal: 14,
    paddingVertical: 11,
    color: '#0F172A',
    fontSize: 14,
    marginBottom: 16,
  },
});
