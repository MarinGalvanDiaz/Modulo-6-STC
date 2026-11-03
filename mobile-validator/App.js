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
} from 'react-native';
import { CameraView, useCameraPermissions } from 'expo-camera';
import * as Haptics from 'expo-haptics';
import { io } from 'socket.io-client';

// IP Wi-Fi detectada automáticamente del servidor Node.js en la red local
const DEFAULT_LAN_URL =
  Platform.OS === 'web' && typeof window !== 'undefined'
    ? window.location.origin.includes(':4000')
      ? window.location.origin
      : 'http://localhost:4000'
    : 'http://10.100.67.223:4000';

const GATES = [
  'PUERTA-NORTE-01',
  'TORNIQUETE-VIP-02',
  'ACCESO-SUR-03',
  'ACCESO-PALCOS-04',
];

const STATUS_THEME = {
  VALID: {
    bg: '#064E3B',
    border: '#10B981',
    badgeBg: '#10B981',
    badgeText: '#022C22',
    icon: '✅',
    shortLabel: 'VÁLIDO',
  },
  REPLAY: {
    bg: '#78350F',
    border: '#F59E0B',
    badgeBg: '#F59E0B',
    badgeText: '#451A03',
    icon: '⏱️',
    shortLabel: 'REPLAY',
  },
  FAKE: {
    bg: '#881337',
    border: '#F43F5E',
    badgeBg: '#F43F5E',
    badgeText: '#FFFFFF',
    icon: '🚨',
    shortLabel: 'FALSO',
  },
  ALREADY_USED: {
    bg: '#0C4A6E',
    border: '#38BDF8',
    badgeBg: '#38BDF8',
    badgeText: '#082F49',
    icon: '🔵',
    shortLabel: 'YA INGRESÓ',
  },
};

export default function App() {
  const [activeTab, setActiveTab] = useState('SCANNER'); // 'SCANNER' | 'AUDIT' | 'WALLET'
  const [serverUrl, setServerUrl] = useState(DEFAULT_LAN_URL);
  const [tempUrlInput, setTempUrlInput] = useState(DEFAULT_LAN_URL);
  const [showConfigModal, setShowConfigModal] = useState(false);

  const [connected, setConnected] = useState(false);
  const [healthInfo, setHealthInfo] = useState(null);
  const [selectedGate, setSelectedGate] = useState(GATES[0]);
  const [scannerId] = useState(`EXPO-${Platform.OS.toUpperCase()}-01`);
  const [scannerJwt, setScannerJwt] = useState(null);

  // Camera & Scanner state
  const [permission, requestPermission] = useCameraPermissions();
  const [cameraEnabled, setCameraEnabled] = useState(true);
  const [scanLocked, setScanLocked] = useState(false);
  const [validating, setValidating] = useState(false);
  const [lastScanResult, setLastScanResult] = useState(null);

  // Audit & Occupancy state
  const [dashboard, setDashboard] = useState(null);
  const [verifyingChain, setVerifyingChain] = useState(false);

  // Wallet / QR Simulator state
  const [tickets, setTickets] = useState([]);
  const [selectedTicketId, setSelectedTicketId] = useState(null);
  const [qrMode, setQrMode] = useState('VALID');
  const [qrBundle, setQrBundle] = useState(null);
  const [totpCountdown, setTotpCountdown] = useState(15);
  const [newBuyerName, setNewBuyerName] = useState('');
  const [newSection, setNewSection] = useState('VIP');

  const socketRef = useRef(null);
  const lastStepRef = useRef(null);

  // Fetch initial data & connect WebSocket
  const connectToServer = useCallback(
    async (baseUrl = serverUrl) => {
      const cleanUrl = baseUrl.trim().replace(/\/+$/, '');
      try {
        const healthRes = await fetch(`${cleanUrl}/api/health`);
        const healthJson = await healthRes.json();
        setHealthInfo(healthJson);
        setConnected(true);

        // Request ECDSA secp256r1 JWT credential for this gate scanner
        const sessionRes = await fetch(`${cleanUrl}/api/pki/scanner-session`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            gateId: selectedGate,
            scannerId,
            operator: 'Personal de Acceso STC',
          }),
        });
        const sessionJson = await sessionRes.json();
        setScannerJwt(sessionJson.jwtToken);

        // Load tickets & audit dashboard
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

        // Setup Socket.io real-time updates
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
        socket.on('audit:new_scan', (scan) => {
          setLastScanResult(scan);
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

  // Load Dynamic QR when ticket or mode changes
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
    } catch (e) {
      // ignore transient error
    }
  }, [selectedTicketId, qrMode, serverUrl, connected]);

  useEffect(() => {
    fetchDynamicQr();
  }, [fetchDynamicQr]);

  // 15-second TOTP countdown timer
  useEffect(() => {
    const interval = setInterval(() => {
      const nowMs = Date.now();
      const step = Math.floor(nowMs / 15000);
      const secInto = Math.floor((nowMs / 1000) % 15);
      const remaining = 15 - secInto;
      setTotpCountdown(remaining);

      if (lastStepRef.current !== null && step !== lastStepRef.current) {
        lastStepRef.current = step;
        fetchDynamicQr();
      }
    }, 1000);
    return () => clearInterval(interval);
  }, [fetchDynamicQr]);

  // Trigger Haptic feedback based on validation status
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

  // Validate scanned QR payload against Node.js backend
  const handleValidateQrPayload = async (rawQrString) => {
    if (validating) return;
    setValidating(true);
    setScanLocked(true);

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
      Alert.alert(
        'Error de Red',
        `No se pudo contactar al backend en ${serverUrl}. Verifica que tu celular y PC estén en la misma red Wi-Fi.`
      );
      setScanLocked(false);
    } finally {
      setValidating(false);
    }
  };

  // Camera barcode handler
  const onBarcodeScanned = ({ data }) => {
    if (scanLocked || validating || !data) return;
    handleValidateQrPayload(data);
  };

  // Quick test simulation directly from the mobile app
  const runQuickSimulation = async (mode) => {
    const targetTicket = selectedTicketId || (tickets[0] && tickets[0].ticketId);
    if (!targetTicket) return;
    try {
      const cleanUrl = serverUrl.trim().replace(/\/+$/, '');
      const simRes = await fetch(
        `${cleanUrl}/api/simulator/qr/${targetTicket}?mode=${mode}`
      );
      const simBundle = await simRes.json();
      if (simBundle && simBundle.qrRawString) {
        await handleValidateQrPayload(simBundle.qrRawString);
      }
    } catch (e) {
      Alert.alert('Error', 'No se pudo generar el QR de prueba.');
    }
  };

  const handleResetTicket = async (ticketId) => {
    try {
      const cleanUrl = serverUrl.trim().replace(/\/+$/, '');
      await fetch(`${cleanUrl}/api/tickets/${ticketId}/reset`, { method: 'POST' });
      await fetchDynamicQr();
      setScanLocked(false);
    } catch (e) {}
  };

  const handleResetAllTickets = async () => {
    try {
      const cleanUrl = serverUrl.trim().replace(/\/+$/, '');
      await fetch(`${cleanUrl}/api/tickets/reset-all`, { method: 'POST' });
      await fetchDynamicQr();
    } catch (e) {}
  };

  const handleVerifyHashChain = async () => {
    setVerifyingChain(true);
    try {
      const cleanUrl = serverUrl.trim().replace(/\/+$/, '');
      const res = await fetch(`${cleanUrl}/api/audit/verify-chain`);
      const report = await res.json();
      Alert.alert(
        report.intact
          ? '✅ Cadena SHA-256 Íntegra'
          : '🚨 Alerta: Ruptura de Cadena',
        report.intact
          ? `Se recalcularon exitosamente los hashes SHA-256 de ${report.totalBlocks} bloques desde el bloque Génesis.\n\nÚltimo Hash:\n${report.latestHash.slice(0, 32)}...`
          : report.reason
      );
    } catch (e) {
      Alert.alert('Error', 'No se pudo verificar la cadena de auditoría.');
    } finally {
      setVerifyingChain(false);
    }
  };

  const handleCreateTicket = async () => {
    if (!newBuyerName.trim()) {
      Alert.alert('Dato requerido', 'Ingresa el nombre del comprador.');
      return;
    }
    try {
      const cleanUrl = serverUrl.trim().replace(/\/+$/, '');
      const randomSeat = String(Math.floor(Math.random() * 30) + 1).padStart(2, '0');
      const res = await fetch(`${cleanUrl}/api/tickets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          buyerName: newBuyerName.trim(),
          section: newSection,
          row: 'D',
          seat: randomSeat,
        }),
      });
      const data = await res.json();
      if (data.ticket) {
        setNewBuyerName('');
        setSelectedTicketId(data.ticket.ticketId);
      }
    } catch (e) {
      Alert.alert('Error', 'No se pudo emitir el boleto.');
    }
  };

  // ============================================================================
  // RENDER TABS
  // ============================================================================

  const renderScannerTab = () => {
    const theme = lastScanResult ? STATUS_THEME[lastScanResult.status] || STATUS_THEME.FAKE : null;

    return (
      <ScrollView style={styles.tabContent} contentContainerStyle={{ paddingBottom: 32 }}>
        {/* Selector de Puerta / Torniquete */}
        <View style={styles.card}>
          <Text style={styles.sectionLabel}>PUERTA / TORNIQUETE ACTIVO</Text>
          <ScrollView horizontal showsHorizontalScrollIndicator={false} style={{ marginTop: 6 }}>
            {GATES.map((gate) => {
              const active = selectedGate === gate;
              return (
                <TouchableOpacity
                  key={gate}
                  style={[styles.gateChip, active && styles.gateChipActive]}
                  onPress={() => setSelectedGate(gate)}
                >
                  <Text style={[styles.gateChipText, active && styles.gateChipTextActive]}>
                    🚪 {gate}
                  </Text>
                </TouchableOpacity>
              );
            })}
          </ScrollView>
        </View>

        {/* Visor de Cámara QR */}
        <View style={styles.card}>
          <View style={styles.rowBetween}>
            <Text style={styles.cardTitle}>📷 Lector QR Criptográfico</Text>
            <TouchableOpacity
              style={styles.smallBtn}
              onPress={() => setCameraEnabled(!cameraEnabled)}
            >
              <Text style={styles.smallBtnText}>
                {cameraEnabled ? 'Pausar Cámara' : 'Activar Cámara'}
              </Text>
            </TouchableOpacity>
          </View>
          <Text style={styles.cardSub}>
            Escanea el QR dinámico desde la pantalla de la PC (http://localhost:4000) o desde otro dispositivo.
          </Text>

          {!permission ? (
            <View style={styles.cameraPlaceholder}>
              <ActivityIndicator color="#38BDF8" />
              <Text style={styles.placeholderText}>Solicitando permisos de cámara...</Text>
            </View>
          ) : !permission.granted ? (
            <View style={styles.cameraPlaceholder}>
              <Text style={styles.placeholderText}>
                Necesitamos permiso de la cámara para escanear los códigos QR en la puerta.
              </Text>
              <TouchableOpacity style={styles.primaryBtn} onPress={requestPermission}>
                <Text style={styles.primaryBtnText}>Conceder Permiso de Cámara</Text>
              </TouchableOpacity>
            </View>
          ) : cameraEnabled ? (
            <View style={styles.cameraContainer}>
              <CameraView
                style={styles.camera}
                facing="back"
                barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
                onBarcodeScanned={scanLocked ? undefined : onBarcodeScanned}
              />
              <View style={styles.reticleOverlay} pointerEvents="none">
                <View
                  style={[
                    styles.reticleBox,
                    scanLocked && { borderColor: theme ? theme.border : '#38BDF8' },
                  ]}
                />
                <Text style={styles.reticleHint}>
                  {scanLocked
                    ? 'Escaneo procesado — Presiona "Escanear Siguiente"'
                    : 'Apunta al QR Dinámico (Ventana 15s)'}
                </Text>
              </View>
            </View>
          ) : (
            <View style={styles.cameraPlaceholder}>
              <Text style={styles.placeholderText}>Cámara en pausa</Text>
            </View>
          )}

          {scanLocked && (
            <TouchableOpacity
              style={[styles.primaryBtn, { marginTop: 12, backgroundColor: '#38BDF8' }]}
              onPress={() => setScanLocked(false)}
            >
              <Text style={[styles.primaryBtnText, { color: '#082F49' }]}>
                🔄 Escanear Siguiente Boleto
              </Text>
            </TouchableOpacity>
          )}
        </View>

        {/* Tarjeta de Respuesta en Sub-Segundo */}
        {lastScanResult && theme && (
          <View
            style={[
              styles.resultBanner,
              { backgroundColor: theme.bg, borderColor: theme.border },
            ]}
          >
            <View style={styles.rowBetween}>
              <View style={[styles.statusBadge, { backgroundColor: theme.badgeBg }]}>
                <Text style={[styles.statusBadgeText, { color: theme.badgeText }]}>
                  {theme.icon} {lastScanResult.status}
                </Text>
              </View>
              <View style={styles.latencyPill}>
                <Text style={styles.latencyText}>⚡ {lastScanResult.latencyMs} ms</Text>
              </View>
            </View>

            <Text style={styles.resultTitle}>{lastScanResult.title}</Text>
            <Text style={styles.resultMsg}>{lastScanResult.message}</Text>

            {lastScanResult.ticket && (
              <View style={styles.ticketSummaryBox}>
                <Text style={styles.ticketSummaryLine}>
                  🎟️ Boleto: <Text style={styles.boldWhite}>{lastScanResult.ticket.ticketId}</Text>
                </Text>
                {lastScanResult.ticket.buyerName && (
                  <Text style={styles.ticketSummaryLine}>
                    👤 Titular: <Text style={styles.boldWhite}>{lastScanResult.ticket.buyerName}</Text>
                  </Text>
                )}
                <Text style={styles.ticketSummaryLine}>
                  💺 Ubicación:{' '}
                  <Text style={styles.boldWhite}>
                    {lastScanResult.ticket.section}{' '}
                    {lastScanResult.ticket.row
                      ? `Fila ${lastScanResult.ticket.row} - Asiento ${lastScanResult.ticket.seat}`
                      : lastScanResult.ticket.seatLabel || ''}
                  </Text>
                </Text>
              </View>
            )}

            {/* Verificaciones Criptográficas */}
            {lastScanResult.cryptoChecks && (
              <View style={styles.cryptoChecksRow}>
                <Text style={styles.cryptoCheckItem}>
                  {lastScanResult.cryptoChecks.ecdsaVerified ? '✅' : '❌'} ECDSA secp256r1
                </Text>
                <Text style={styles.cryptoCheckItem}>
                  {lastScanResult.cryptoChecks.hmacVerified ? '✅' : '❌'} HMAC-SHA256
                </Text>
                <Text style={styles.cryptoCheckItem}>
                  {lastScanResult.cryptoChecks.totpWindowValid ? '✅' : '❌'} Ventana 15s
                </Text>
              </View>
            )}

            {lastScanResult.auditBlock && (
              <Text style={styles.blockHashFooter}>
                ⛓️ Bloque Auditoría #{lastScanResult.auditBlock.blockIndex} • SHA-256:{' '}
                {lastScanResult.auditBlock.blockHash.slice(0, 20)}...
              </Text>
            )}

            {lastScanResult.status === 'ALREADY_USED' && lastScanResult.ticket?.ticketId && (
              <TouchableOpacity
                style={[styles.secondaryBtn, { marginTop: 10 }]}
                onPress={() => handleResetTicket(lastScanResult.ticket.ticketId)}
              >
                <Text style={styles.secondaryBtnText}>
                  🔄 Restaurar este boleto a DISPONIBLE para volver a probar
                </Text>
              </TouchableOpacity>
            )}
          </View>
        )}

        {/* Simulador Rápido Integrado (para probar sin segunda pantalla) */}
        <View style={styles.card}>
          <Text style={styles.cardTitle}>⚡ Simulador Rápido de Casos Criptográficos</Text>
          <Text style={styles.cardSub}>
            Prueba la respuesta en sub-segundo directamente para el boleto activo ({selectedTicketId || 'TKT-2026-0001'}):
          </Text>
          <View style={styles.simGrid}>
            <TouchableOpacity
              style={[styles.simBtn, { borderColor: '#10B981' }]}
              onPress={() => runQuickSimulation('VALID')}
            >
              <Text style={[styles.simBtnTitle, { color: '#6EE7B7' }]}>✅ 1. QR Válido</Text>
              <Text style={styles.simBtnSub}>ECDSA + HMAC 15s</Text>
            </TouchableOpacity>

            <TouchableOpacity
              style={[styles.simBtn, { borderColor: '#F59E0B' }]}
              onPress={() => runQuickSimulation('REPLAY')}
            >
              <Text style={[styles.simBtnTitle, { color: '#FCD34D' }]}>⏱️ 2. Replay Attack</Text>
              <Text style={styles.simBtnSub}>Ventana expirada</Text>
            </TouchableOpacity>

            <TouchableOpacity
              style={[styles.simBtn, { borderColor: '#F43F5E' }]}
              onPress={() => runQuickSimulation('FAKE_SIGNATURE')}
            >
              <Text style={[styles.simBtnTitle, { color: '#FDA4AF' }]}>🚨 3. Firma Falsa</Text>
              <Text style={styles.simBtnSub}>Payload alterado</Text>
            </TouchableOpacity>

            <TouchableOpacity
              style={[styles.simBtn, { borderColor: '#38BDF8' }]}
              onPress={() => runQuickSimulation('FAKE_HMAC')}
            >
              <Text style={[styles.simBtnTitle, { color: '#7DD3FC' }]}>🔓 4. HMAC Falso</Text>
              <Text style={styles.simBtnSub}>Sin SK_session</Text>
            </TouchableOpacity>
          </View>
        </View>
      </ScrollView>
    );
  };

  const renderAuditTab = () => {
    if (!dashboard) {
      return (
        <View style={styles.centerBox}>
          <ActivityIndicator size="large" color="#38BDF8" />
          <Text style={styles.placeholderText}>Cargando Libro Mayor de Auditoría...</Text>
        </View>
      );
    }

    const { occupancy, securityCounters, chainIntegrity, recentLedger } = dashboard;

    return (
      <ScrollView style={styles.tabContent} contentContainerStyle={{ paddingBottom: 36 }}>
        {/* Integridad de la Cadena de Hashes SHA-256 */}
        <View
          style={[
            styles.card,
            {
              borderColor: chainIntegrity.intact ? '#10B981' : '#F43F5E',
              backgroundColor: chainIntegrity.intact ? '#062E22' : '#4C0519',
            },
          ]}
        >
          <View style={styles.rowBetween}>
            <View style={{ flex: 1 }}>
              <Text style={styles.cardTitle}>
                {chainIntegrity.intact
                  ? '⛓️ Libro Mayor Hash-Chain: ÍNTEGRO'
                  : '🚨 ALERTA: CADENA COMPROMETIDA'}
              </Text>
              <Text style={[styles.cardSub, { color: '#CBD5E1', marginBottom: 4 }]}>
                {chainIntegrity.totalBlocks} bloques encadenados con SHA-256
              </Text>
              <Text style={styles.monoSmall}>
                Tip Hash: {chainIntegrity.latestHash?.slice(0, 28)}...
              </Text>
            </View>
            <TouchableOpacity
              style={styles.verifyBtn}
              onPress={handleVerifyHashChain}
              disabled={verifyingChain}
            >
              <Text style={styles.verifyBtnText}>
                {verifyingChain ? '...' : '🔍 Verificar'}
              </Text>
            </TouchableOpacity>
          </View>
        </View>

        {/* Estadísticas de Aforo del Auditorio */}
        <View style={styles.card}>
          <View style={styles.rowBetween}>
            <Text style={styles.cardTitle}>🏛️ Aforo del Auditorio en Tiempo Real</Text>
            <Text style={{ color: '#38BDF8', fontWeight: '800' }}>
              {occupancy.checkedInCount} / {occupancy.totalCapacity} ({occupancy.capacityOccupancyPercent}%)
            </Text>
          </View>
          <Text style={styles.cardSub}>
            Boletos emitidos: {occupancy.ticketsIssued} • Pendientes por ingresar:{' '}
            {occupancy.remainingIssuedToEnter}
          </Text>

          {occupancy.sections.map((sec) => (
            <View key={sec.section} style={styles.sectionBarRow}>
              <View style={styles.rowBetween}>
                <Text style={styles.secName}>{sec.section}</Text>
                <Text style={styles.secStats}>
                  {sec.inside} / {sec.capacity} ({sec.occupancyPercent}%)
                </Text>
              </View>
              <View style={styles.progressTrack}>
                <View
                  style={[
                    styles.progressFill,
                    { width: `${Math.min(100, sec.occupancyPercent)}%` },
                  ]}
                />
              </View>
            </View>
          ))}
        </View>

        {/* Contadores de Seguridad */}
        <View style={styles.kpiGrid}>
          <View style={styles.kpiCard}>
            <Text style={styles.kpiLabel}>VÁLIDOS</Text>
            <Text style={[styles.kpiValue, { color: '#10B981' }]}>
              {securityCounters.validEntries}
            </Text>
          </View>
          <View style={styles.kpiCard}>
            <Text style={styles.kpiLabel}>REPLAY</Text>
            <Text style={[styles.kpiValue, { color: '#F59E0B' }]}>
              {securityCounters.replayBlocked}
            </Text>
          </View>
          <View style={styles.kpiCard}>
            <Text style={styles.kpiLabel}>FALSOS</Text>
            <Text style={[styles.kpiValue, { color: '#F43F5E' }]}>
              {securityCounters.fakeRejected}
            </Text>
          </View>
          <View style={styles.kpiCard}>
            <Text style={styles.kpiLabel}>YA INGRESÓ</Text>
            <Text style={[styles.kpiValue, { color: '#38BDF8' }]}>
              {securityCounters.alreadyUsedBlocked}
            </Text>
          </View>
        </View>

        {/* Registro Inmutable de Bloques (Hash-Chain) */}
        <View style={styles.card}>
          <Text style={styles.cardTitle}>📜 Registro de Auditoría (Bloques SHA-256)</Text>
          <Text style={styles.cardSub}>
            Latencia promedio de verificación: {securityCounters.avgLatencyMs} ms
          </Text>

          {recentLedger.map((block) => {
            const bTheme = STATUS_THEME[block.validationResult] || STATUS_THEME.FAKE;
            return (
              <View key={block.blockIndex} style={styles.ledgerItem}>
                <View style={styles.rowBetween}>
                  <Text style={styles.ledgerIndex}>
                    Bloque #{block.blockIndex} • {block.ticketId}
                  </Text>
                  <View
                    style={[
                      styles.ledgerBadge,
                      { backgroundColor: bTheme.bg, borderColor: bTheme.border },
                    ]}
                  >
                    <Text style={{ color: '#FFF', fontSize: 11, fontWeight: '800' }}>
                      {bTheme.icon} {block.validationResult}
                    </Text>
                  </View>
                </View>

                <Text style={styles.ledgerReason}>{block.reason}</Text>

                <View style={styles.rowBetween}>
                  <Text style={styles.ledgerMeta}>
                    🚪 {block.gateId} • 💺 {block.section} ({block.seatLabel})
                  </Text>
                  <Text style={styles.ledgerMeta}>⚡ {block.latencyMs} ms</Text>
                </View>

                <View style={styles.hashBox}>
                  <Text style={styles.hashText}>
                    Prev: {block.prevHash.slice(0, 24)}...
                  </Text>
                  <Text style={[styles.hashText, { color: '#38BDF8' }]}>
                    Curr: {block.blockHash.slice(0, 24)}...
                  </Text>
                </View>
              </View>
            );
          })}
        </View>
      </ScrollView>
    );
  };

  const renderWalletTab = () => {
    return (
      <ScrollView style={styles.tabContent} contentContainerStyle={{ paddingBottom: 36 }}>
        <View style={styles.card}>
          <Text style={styles.cardTitle}>🎟️ Generador QR Dinámico (Módulo 5 ➔ 6)</Text>
          <Text style={styles.cardSub}>
            Selecciona cualquier boleto para visualizar su QR rotativo cada 15s (HMAC-SHA256 + ECDSA secp256r1).
          </Text>

          <ScrollView horizontal showsHorizontalScrollIndicator={false} style={{ marginVertical: 8 }}>
            {tickets.map((t) => {
              const selected = t.ticketId === selectedTicketId;
              return (
                <TouchableOpacity
                  key={t.ticketId}
                  style={[styles.ticketChip, selected && styles.ticketChipActive]}
                  onPress={() => setSelectedTicketId(t.ticketId)}
                >
                  <Text style={styles.ticketChipId}>
                    {t.status === 'USED' ? '🔵' : '🟢'} {t.ticketId}
                  </Text>
                  <Text style={styles.ticketChipSub}>
                    {t.section} {t.row}-{t.seat}
                  </Text>
                </TouchableOpacity>
              );
            })}
          </ScrollView>

          {/* Selector de Modo Criptográfico */}
          <View style={styles.simGrid}>
            {[
              { id: 'VALID', label: '✅ QR Válido (15s)' },
              { id: 'REPLAY', label: '⏱️ Replay (-120s)' },
              { id: 'FAKE_SIGNATURE', label: '🚨 Firma Falsa' },
              { id: 'FAKE_HMAC', label: '🔓 HMAC Falso' },
            ].map((m) => (
              <TouchableOpacity
                key={m.id}
                style={[
                  styles.modePill,
                  qrMode === m.id && { borderColor: '#38BDF8', backgroundColor: '#0C4A6E' },
                ]}
                onPress={() => setQrMode(m.id)}
              >
                <Text style={styles.modePillText}>{m.label}</Text>
              </TouchableOpacity>
            ))}
          </View>

          {qrBundle && (
            <View style={styles.qrCardWhite}>
              <Image
                source={{ uri: qrBundle.qrDataUrl }}
                style={{ width: 240, height: 240 }}
                resizeMode="contain"
              />
              <Text style={styles.qrCardTicketTitle}>
                {qrBundle.ticket.ticketId} • {qrBundle.ticket.section} {qrBundle.ticket.row}-
                {qrBundle.ticket.seat}
              </Text>
              <Text style={styles.qrCardBuyer}>{qrBundle.ticket.buyerName}</Text>
              <View style={styles.totpPillDark}>
                <Text style={styles.totpPillText}>
                  ⏱️ Ventana TOTP #{qrBundle.totp.currentStep} • Rota en {totpCountdown}s
                </Text>
              </View>
            </View>
          )}

          <View style={styles.rowBetween}>
            <TouchableOpacity
              style={[styles.secondaryBtn, { flex: 1, marginRight: 6 }]}
              onPress={() => selectedTicketId && handleResetTicket(selectedTicketId)}
            >
              <Text style={styles.secondaryBtnText}>🔄 Restaurar Boleto</Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={[styles.secondaryBtn, { flex: 1, marginLeft: 6 }]}
              onPress={handleResetAllTickets}
            >
              <Text style={styles.secondaryBtnText}>🧹 Restaurar Todos</Text>
            </TouchableOpacity>
          </View>
        </View>

        {/* Emitir Nuevo Boleto Firmado con ECDSA secp256r1 */}
        <View style={styles.card}>
          <Text style={styles.cardTitle}>➕ Emitir Nuevo Boleto (ECDSA secp256r1)</Text>
          <TextInput
            style={styles.input}
            placeholder="Nombre del comprador (ej. Sofía Ramírez)"
            placeholderTextColor="#64748B"
            value={newBuyerName}
            onChangeText={setNewBuyerName}
          />
          <View style={styles.rowBetween}>
            {['VIP', 'Preferente', 'General', 'Palcos'].map((sec) => (
              <TouchableOpacity
                key={sec}
                style={[
                  styles.secSelectBtn,
                  newSection === sec && { borderColor: '#38BDF8', backgroundColor: '#1E293B' },
                ]}
                onPress={() => setNewSection(sec)}
              >
                <Text style={{ color: '#F8FAFC', fontSize: 12, fontWeight: '700' }}>{sec}</Text>
              </TouchableOpacity>
            ))}
          </View>
          <TouchableOpacity
            style={[styles.primaryBtn, { marginTop: 12 }]}
            onPress={handleCreateTicket}
          >
            <Text style={styles.primaryBtnText}>✍️ Firmar con ECDSA y Emitir Boleto</Text>
          </TouchableOpacity>
        </View>
      </ScrollView>
    );
  };

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#070B14" />

      {/* Header Superior */}
      <View style={styles.header}>
        <View style={{ flex: 1 }}>
          <Text style={styles.headerTitle}>🛡️ STC Validator — Módulo 6</Text>
          <Text style={styles.headerSub}>
            {connected
              ? `🟢 PKI ECDSA secp256r1 Activa (${serverUrl})`
              : `🔴 Desconectado (${serverUrl})`}
          </Text>
        </View>
        <TouchableOpacity
          style={styles.configBtn}
          onPress={() => {
            setTempUrlInput(serverUrl);
            setShowConfigModal(true);
          }}
        >
          <Text style={styles.configBtnText}>⚙️ Red / IP</Text>
        </TouchableOpacity>
      </View>

      {/* Contenido Principal */}
      <View style={{ flex: 1 }}>
        {activeTab === 'SCANNER' && renderScannerTab()}
        {activeTab === 'AUDIT' && renderAuditTab()}
        {activeTab === 'WALLET' && renderWalletTab()}
      </View>

      {/* Barra de Navegación Inferior */}
      <View style={styles.bottomNav}>
        <TouchableOpacity
          style={[styles.navTab, activeTab === 'SCANNER' && styles.navTabActive]}
          onPress={() => setActiveTab('SCANNER')}
        >
          <Text style={[styles.navText, activeTab === 'SCANNER' && styles.navTextActive]}>
            📷 Escáner QR
          </Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={[styles.navTab, activeTab === 'AUDIT' && styles.navTabActive]}
          onPress={() => setActiveTab('AUDIT')}
        >
          <Text style={[styles.navText, activeTab === 'AUDIT' && styles.navTextActive]}>
            📊 Auditoría & Aforo
          </Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={[styles.navTab, activeTab === 'WALLET' && styles.navTabActive]}
          onPress={() => setActiveTab('WALLET')}
        >
          <Text style={[styles.navText, activeTab === 'WALLET' && styles.navTextActive]}>
            🎟️ Wallet QR (15s)
          </Text>
        </TouchableOpacity>
      </View>

      {/* Modal de Configuración de IP del Backend Node.js */}
      <Modal visible={showConfigModal} transparent animationType="fade">
        <View style={styles.modalBackdrop}>
          <View style={styles.modalCard}>
            <Text style={styles.cardTitle}>⚙️ Conexión al Servidor Node.js</Text>
            <Text style={styles.cardSub}>
              Si usas tu celular físico con Expo Go, ingresa la dirección IP Wi-Fi de tu computadora (puerto 4000):
            </Text>
            <TextInput
              style={styles.input}
              value={tempUrlInput}
              onChangeText={setTempUrlInput}
              autoCapitalize="none"
              autoCorrect={false}
              placeholder="http://10.100.67.223:4000"
              placeholderTextColor="#64748B"
            />
            {healthInfo && (
              <Text style={styles.monoSmall}>
                Fingerprint X.509 PKI:{'\n'}
                {healthInfo.pki?.certificateFingerprint?.slice(0, 47)}...
              </Text>
            )}
            <View style={[styles.rowBetween, { marginTop: 14 }]}>
              <TouchableOpacity
                style={[styles.secondaryBtn, { flex: 1, marginRight: 6 }]}
                onPress={() => setShowConfigModal(false)}
              >
                <Text style={styles.secondaryBtnText}>Cancelar</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[styles.primaryBtn, { flex: 1, marginLeft: 6 }]}
                onPress={() => {
                  setServerUrl(tempUrlInput.trim());
                  setShowConfigModal(false);
                }}
              >
                <Text style={styles.primaryBtnText}>Guardar y Conectar</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#070B14',
  },
  header: {
    paddingHorizontal: 16,
    paddingVertical: 12,
    backgroundColor: '#0F172A',
    borderBottomWidth: 1,
    borderBottomColor: '#1E293B',
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  headerTitle: {
    color: '#F8FAFC',
    fontSize: 16,
    fontWeight: '800',
  },
  headerSub: {
    color: '#94A3B8',
    fontSize: 11,
    marginTop: 2,
  },
  configBtn: {
    backgroundColor: '#1E293B',
    paddingHorizontal: 10,
    paddingVertical: 7,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: '#334155',
  },
  configBtnText: {
    color: '#38BDF8',
    fontSize: 12,
    fontWeight: '700',
  },
  tabContent: {
    flex: 1,
    padding: 14,
  },
  card: {
    backgroundColor: '#111827',
    borderRadius: 14,
    padding: 14,
    marginBottom: 14,
    borderWidth: 1,
    borderColor: '#1E293B',
  },
  cardTitle: {
    color: '#F8FAFC',
    fontSize: 15,
    fontWeight: '800',
  },
  cardSub: {
    color: '#94A3B8',
    fontSize: 12,
    marginTop: 3,
    marginBottom: 10,
  },
  sectionLabel: {
    color: '#94A3B8',
    fontSize: 11,
    fontWeight: '700',
    letterSpacing: 0.6,
  },
  rowBetween: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  gateChip: {
    backgroundColor: '#090D16',
    borderWidth: 1,
    borderColor: '#334155',
    borderRadius: 8,
    paddingHorizontal: 12,
    paddingVertical: 8,
    marginRight: 8,
  },
  gateChipActive: {
    backgroundColor: '#0C4A6E',
    borderColor: '#38BDF8',
  },
  gateChipText: {
    color: '#94A3B8',
    fontSize: 12,
    fontWeight: '700',
  },
  gateChipTextActive: {
    color: '#F8FAFC',
  },
  cameraContainer: {
    height: 250,
    borderRadius: 12,
    overflow: 'hidden',
    position: 'relative',
    backgroundColor: '#000',
  },
  camera: {
    flex: 1,
  },
  reticleOverlay: {
    ...StyleSheet.absoluteFillObject,
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: 'rgba(0,0,0,0.2)',
  },
  reticleBox: {
    width: 175,
    height: 175,
    borderWidth: 2.5,
    borderColor: '#10B981',
    borderRadius: 16,
  },
  reticleHint: {
    color: '#FFFFFF',
    fontSize: 11,
    fontWeight: '700',
    backgroundColor: 'rgba(15,23,42,0.85)',
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 99,
    marginTop: 10,
  },
  cameraPlaceholder: {
    height: 170,
    backgroundColor: '#090D16',
    borderRadius: 12,
    alignItems: 'center',
    justifyContent: 'center',
    padding: 16,
    borderWidth: 1,
    borderColor: '#1E293B',
  },
  placeholderText: {
    color: '#94A3B8',
    fontSize: 13,
    textAlign: 'center',
    marginVertical: 8,
  },
  primaryBtn: {
    backgroundColor: '#6366F1',
    paddingVertical: 11,
    paddingHorizontal: 14,
    borderRadius: 9,
    alignItems: 'center',
  },
  primaryBtnText: {
    color: '#FFFFFF',
    fontWeight: '800',
    fontSize: 13,
  },
  secondaryBtn: {
    backgroundColor: '#1E293B',
    paddingVertical: 10,
    paddingHorizontal: 12,
    borderRadius: 9,
    borderWidth: 1,
    borderColor: '#334155',
    alignItems: 'center',
  },
  secondaryBtnText: {
    color: '#E2E8F0',
    fontWeight: '700',
    fontSize: 12,
  },
  smallBtn: {
    backgroundColor: '#1E293B',
    paddingHorizontal: 10,
    paddingVertical: 5,
    borderRadius: 6,
  },
  smallBtnText: {
    color: '#CBD5E1',
    fontSize: 11,
    fontWeight: '600',
  },
  resultBanner: {
    borderRadius: 14,
    padding: 15,
    marginBottom: 14,
    borderWidth: 2,
  },
  statusBadge: {
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 6,
  },
  statusBadgeText: {
    fontWeight: '900',
    fontSize: 12,
  },
  latencyPill: {
    backgroundColor: 'rgba(0,0,0,0.35)',
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 99,
  },
  latencyText: {
    color: '#38BDF8',
    fontWeight: '800',
    fontSize: 13,
  },
  resultTitle: {
    color: '#FFFFFF',
    fontSize: 17,
    fontWeight: '900',
    marginTop: 10,
  },
  resultMsg: {
    color: '#F1F5F9',
    fontSize: 13,
    marginTop: 4,
    lineHeight: 18,
  },
  ticketSummaryBox: {
    backgroundColor: 'rgba(0,0,0,0.3)',
    borderRadius: 8,
    padding: 10,
    marginTop: 10,
  },
  ticketSummaryLine: {
    color: '#CBD5E1',
    fontSize: 12,
    marginBottom: 2,
  },
  boldWhite: {
    color: '#FFFFFF',
    fontWeight: '800',
  },
  cryptoChecksRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginTop: 10,
    paddingTop: 8,
    borderTopWidth: 1,
    borderTopColor: 'rgba(255,255,255,0.15)',
  },
  cryptoCheckItem: {
    color: '#F8FAFC',
    fontSize: 11,
    fontWeight: '700',
  },
  blockHashFooter: {
    color: '#CBD5E1',
    fontSize: 10,
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
    marginTop: 8,
  },
  simGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'space-between',
    gap: 8,
  },
  simBtn: {
    width: '48%',
    backgroundColor: '#090D16',
    borderWidth: 1,
    borderRadius: 10,
    padding: 10,
    marginBottom: 4,
  },
  simBtnTitle: {
    fontWeight: '800',
    fontSize: 13,
  },
  simBtnSub: {
    color: '#94A3B8',
    fontSize: 11,
    marginTop: 2,
  },
  sectionBarRow: {
    marginTop: 10,
  },
  secName: {
    color: '#F8FAFC',
    fontSize: 13,
    fontWeight: '700',
  },
  secStats: {
    color: '#94A3B8',
    fontSize: 12,
  },
  progressTrack: {
    height: 7,
    backgroundColor: '#1E293B',
    borderRadius: 99,
    marginTop: 5,
    overflow: 'hidden',
  },
  progressFill: {
    height: '100%',
    backgroundColor: '#38BDF8',
  },
  kpiGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'space-between',
    marginBottom: 10,
  },
  kpiCard: {
    width: '23.5%',
    backgroundColor: '#111827',
    borderWidth: 1,
    borderColor: '#1E293B',
    borderRadius: 10,
    padding: 10,
    alignItems: 'center',
  },
  kpiLabel: {
    color: '#94A3B8',
    fontSize: 10,
    fontWeight: '800',
  },
  kpiValue: {
    fontSize: 19,
    fontWeight: '900',
    marginTop: 2,
  },
  verifyBtn: {
    backgroundColor: '#10B981',
    paddingHorizontal: 12,
    paddingVertical: 8,
    borderRadius: 8,
  },
  verifyBtnText: {
    color: '#022C22',
    fontWeight: '800',
    fontSize: 12,
  },
  ledgerItem: {
    backgroundColor: '#090D16',
    borderRadius: 10,
    padding: 12,
    marginTop: 10,
    borderWidth: 1,
    borderColor: '#1E293B',
  },
  ledgerIndex: {
    color: '#F8FAFC',
    fontWeight: '800',
    fontSize: 13,
  },
  ledgerBadge: {
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderRadius: 6,
    borderWidth: 1,
  },
  ledgerReason: {
    color: '#CBD5E1',
    fontSize: 12,
    marginVertical: 6,
  },
  ledgerMeta: {
    color: '#94A3B8',
    fontSize: 11,
  },
  hashBox: {
    marginTop: 6,
    paddingTop: 6,
    borderTopWidth: 1,
    borderTopColor: '#1E293B',
  },
  hashText: {
    color: '#64748B',
    fontSize: 10,
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
  },
  monoSmall: {
    color: '#94A3B8',
    fontSize: 10,
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
  },
  ticketChip: {
    backgroundColor: '#090D16',
    borderWidth: 1,
    borderColor: '#334155',
    borderRadius: 10,
    paddingHorizontal: 12,
    paddingVertical: 8,
    marginRight: 8,
  },
  ticketChipActive: {
    backgroundColor: '#1E1B4B',
    borderColor: '#6366F1',
  },
  ticketChipId: {
    color: '#F8FAFC',
    fontWeight: '800',
    fontSize: 12,
  },
  ticketChipSub: {
    color: '#94A3B8',
    fontSize: 11,
  },
  modePill: {
    width: '48%',
    backgroundColor: '#090D16',
    borderWidth: 1,
    borderColor: '#334155',
    borderRadius: 8,
    padding: 8,
    alignItems: 'center',
    marginBottom: 6,
  },
  modePillText: {
    color: '#E2E8F0',
    fontSize: 12,
    fontWeight: '700',
  },
  qrCardWhite: {
    backgroundColor: '#FFFFFF',
    borderRadius: 16,
    padding: 16,
    alignItems: 'center',
    marginVertical: 12,
  },
  qrCardTicketTitle: {
    color: '#0F172A',
    fontWeight: '900',
    fontSize: 14,
    marginTop: 6,
  },
  qrCardBuyer: {
    color: '#475569',
    fontSize: 12,
    marginBottom: 8,
  },
  totpPillDark: {
    backgroundColor: '#0F172A',
    paddingHorizontal: 12,
    paddingVertical: 5,
    borderRadius: 99,
  },
  totpPillText: {
    color: '#38BDF8',
    fontSize: 11,
    fontWeight: '800',
  },
  input: {
    backgroundColor: '#090D16',
    borderWidth: 1,
    borderColor: '#334155',
    borderRadius: 8,
    color: '#F8FAFC',
    paddingHorizontal: 12,
    paddingVertical: 10,
    fontSize: 13,
    marginBottom: 10,
  },
  secSelectBtn: {
    flex: 1,
    backgroundColor: '#090D16',
    borderWidth: 1,
    borderColor: '#334155',
    borderRadius: 8,
    paddingVertical: 8,
    marginHorizontal: 3,
    alignItems: 'center',
  },
  bottomNav: {
    flexDirection: 'row',
    backgroundColor: '#0F172A',
    borderTopWidth: 1,
    borderTopColor: '#1E293B',
    paddingVertical: 8,
    paddingHorizontal: 10,
  },
  navTab: {
    flex: 1,
    paddingVertical: 9,
    alignItems: 'center',
    borderRadius: 8,
  },
  navTabActive: {
    backgroundColor: '#1E293B',
  },
  navText: {
    color: '#94A3B8',
    fontSize: 12,
    fontWeight: '700',
  },
  navTextActive: {
    color: '#38BDF8',
  },
  centerBox: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    padding: 24,
  },
  modalBackdrop: {
    flex: 1,
    backgroundColor: 'rgba(0,0,0,0.75)',
    alignItems: 'center',
    justifyContent: 'center',
    padding: 20,
  },
  modalCard: {
    width: '100%',
    maxWidth: 420,
    backgroundColor: '#111827',
    borderRadius: 14,
    padding: 18,
    borderWidth: 1,
    borderColor: '#334155',
  },
});
