import React, { createContext, useContext, useState, useEffect, useRef, useCallback } from 'react';
import apiService from '../services/api';
import socketService from '../services/socket';

const MonitoringContext = createContext(null);

export function MonitoringProvider({ children }) {
  // User selections (Persist in UI across polling updates)
  const [selectedInterface, setSelectedInterface] = useState(() => {
    return localStorage.getItem('netintel_interface') || '';
  });
  const [selectedMode, setSelectedMode] = useState(() => {
    return localStorage.getItem('netintel_mode') || 'LIVE';
  });

  // Authoritative Backend State
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [activeMode, setActiveMode] = useState('LIVE');
  const [activeInterface, setActiveInterface] = useState('');
  const [monitoringState, setMonitoringState] = useState('IDLE'); // 'IDLE' | 'STARTING' | 'ACTIVE' | 'STOPPING' | 'ERROR'

  const [interfaces, setInterfaces] = useState([]);
  const [stats, setStats] = useState({
    total_packets: 0,
    total_bytes: 0,
    normal_packets: 0,
    attack_packets: 0,
    threat_level: 'LOW',
    normal_pct: 100.0,
    attack_pct: 0.0,
    packets_per_second: 0.0,
    bytes_per_second: 0.0,
    active_flows: 0,
    tcp_count: 0,
    udp_count: 0,
    icmp_count: 0,
    duration_seconds: 0.0,
  });

  const [recentPackets, setRecentPackets] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [flows, setFlows] = useState([]);
  const [modelInfo, setModelInfo] = useState(null);
  const [trafficHistory, setTrafficHistory] = useState([]);
  const [aiAnalysis, setAiAnalysis] = useState({}); // Store AI analysis state per alert_id
  const [securityEvents, setSecurityEvents] = useState([
    {
      id: 'init-1',
      title: 'Engine Standby',
      desc: 'NetIntel intrusion detection system connected to backend.',
      time: 'Just now',
      type: 'normal',
    },
  ]);

  const [error, setError] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  // Packet and alert buffers for high-frequency Socket.IO batching
  const packetBufferRef = useRef([]);
  const alertBufferRef = useRef([]);

  // Helper: record a traffic data point for the 60s time-series chart
  const recordTrafficPoint = useCallback((data) => {
    const now = Date.now();
    setTrafficHistory((prev) => {
      const point = {
        t: now,
        pps: data.packets_per_second || 0,
        bps: data.bytes_per_second || 0,
        flows: data.active_flows || 0,
        tcp: data.tcp_count || 0,
        udp: data.udp_count || 0,
        attacks: data.attack_packets || 0,
      };
      const cutoff = now - 65000; // keep ~65s of history
      const trimmed = prev.filter((p) => p.t > cutoff);
      return [...trimmed, point];
    });
  }, []);

  // Save user preferences
  const handleSetSelectedInterface = (iface) => {
    setSelectedInterface(iface);
    if (iface) {
      localStorage.setItem('netintel_interface', iface);
    }
  };

  const handleSetSelectedMode = (mode) => {
    const valid = mode === 'SIMULATION' ? 'SIMULATION' : 'LIVE';
    setSelectedMode(valid);
    localStorage.setItem('netintel_mode', valid);
  };

  // Fetch available network interfaces
  const fetchInterfaces = useCallback(async () => {
    try {
      const data = await apiService.getInterfaces();
      const list = data.interfaces || [];
      setInterfaces(list);

      // Auto-select first active UP non-loopback interface if not yet chosen
      setSelectedInterface((current) => {
        if (current && list.some((i) => i.name === current)) {
          return current;
        }
        const activeUp = list.find((i) => i.status === 'UP' && !i.is_loopback);
        const fallback = activeUp ? activeUp.name : list[0]?.name || 'Auto';
        localStorage.setItem('netintel_interface', fallback);
        return fallback;
      });
    } catch (err) {
      console.warn('Failed to fetch network interfaces:', err.message);
    }
  }, []);

  // Fetch model specifications
  const fetchModelInfo = useCallback(async () => {
    try {
      const data = await apiService.getModelInfo();
      setModelInfo(data);
    } catch (err) {
      console.warn('Failed to fetch model info:', err.message);
    }
  }, []);

  // Fetch active flows snapshot
  const fetchFlows = useCallback(async () => {
    try {
      const data = await apiService.getFlows(100);
      setFlows(data.flows || []);
    } catch (err) {
      console.debug('Failed to fetch flows:', err.message);
    }
  }, []);

  // Fetch status snapshot from backend
  const fetchStatus = useCallback(async () => {
    try {
      const data = await apiService.getStatus();
      const running = Boolean(data.is_running);
      setIsMonitoring(running);
      if (data.capture_mode) setActiveMode(data.capture_mode);
      if (data.interface) setActiveInterface(data.interface);

      if (data.error_message) {
        setError(data.error_message);
        setMonitoringState('ERROR');
      } else if (running) {
        setMonitoringState('ACTIVE');
        setError(null);
      } else {
        setMonitoringState((prev) => (prev === 'STARTING' || prev === 'STOPPING' ? prev : 'IDLE'));
      }

      setStats((prev) => ({ ...prev, ...data }));
      recordTrafficPoint(data);
    } catch (err) {
      console.warn('Backend offline:', err.message);
      setMonitoringState('ERROR');
      setError('Backend server offline or unreachable at http://localhost:5000');
    }
  }, [recordTrafficPoint]);

  const fetchAlerts = useCallback(async () => {
    try {
      const data = await apiService.getAlerts(50);
      if (data.alerts && data.alerts.length > 0) {
        setAlerts((prev) => {
          const existingIds = new Set(prev.map((a) => a.id));
          const newItems = data.alerts.filter((a) => !existingIds.has(a.id));
          return [...prev, ...newItems].slice(0, 100);
        });
      }
    } catch (err) {
      console.debug('Failed to fetch initial alerts:', err.message);
    }
  }, []);

  // Initial load
  useEffect(() => {
    fetchInterfaces();
    fetchModelInfo();
    fetchStatus();
    fetchFlows();
    fetchAlerts();

    const statusTimer = setInterval(() => {
      fetchStatus();
      fetchFlows();
    }, 2000);

    return () => clearInterval(statusTimer);
  }, [fetchInterfaces, fetchModelInfo, fetchStatus, fetchFlows, fetchAlerts]);

  // Socket.IO event subscribers
  useEffect(() => {
    socketService.connect();

    const handlePacket = (pkt) => {
      packetBufferRef.current.push(pkt);
    };

    const handleAlert = (alertPkt) => {
      alertBufferRef.current.push(alertPkt);
    };

    const handleStatus = (statusData) => {
      const running = Boolean(statusData.is_running);
      setIsMonitoring(running);
      if (statusData.capture_mode) setActiveMode(statusData.capture_mode);
      if (statusData.interface) setActiveInterface(statusData.interface);

      if (statusData.error_message) {
        setError(statusData.error_message);
        setMonitoringState('ERROR');
      } else if (running) {
        setMonitoringState('ACTIVE');
        setError(null);
      }

      setStats((prev) => ({ ...prev, ...statusData }));
      recordTrafficPoint(statusData);
    };

    socketService.on('packet', handlePacket);
    socketService.on('alert', handleAlert);
    socketService.on('status', handleStatus);

    const handleAiStarted = (data) => {
      setAiAnalysis((prev) => ({
        ...prev,
        [data.alert_id]: { state: 'ANALYZING', timestamp: data.timestamp }
      }));
    };
    
    const handleAiCompleted = (data) => {
      setAiAnalysis((prev) => ({
        ...prev,
        [data.alert_id]: { state: 'COMPLETED', analysis: data.analysis, timestamp: data.timestamp }
      }));
    };
    
    const handleAiFailed = (data) => {
      setAiAnalysis((prev) => ({
        ...prev,
        [data.alert_id]: { state: 'FAILED', error: data.error, timestamp: data.timestamp }
      }));
    };

    socketService.on('ai_analysis_started', handleAiStarted);
    socketService.on('ai_analysis_completed', handleAiCompleted);
    socketService.on('ai_analysis_failed', handleAiFailed);

    // Batch UI updates every 250ms
    const batchTimer = setInterval(() => {
      if (packetBufferRef.current.length > 0) {
        const newPackets = [...packetBufferRef.current];
        packetBufferRef.current = [];

        setRecentPackets((prev) => {
          const combined = [...newPackets, ...prev];
          return combined.slice(0, 150);
        });
      }

      if (alertBufferRef.current.length > 0) {
        const newAlerts = [...alertBufferRef.current];
        alertBufferRef.current = [];

        setAlerts((prev) => {
          const combined = [...newAlerts, ...prev];
          return combined.slice(0, 100);
        });

        const newEvents = newAlerts.map((a) => ({
          id: a.id || `alert-${Date.now()}-${Math.random()}`,
          title: `Threat: ${a.attack_type || 'Intrusion Alert'}`,
          desc: `Detected from ${a.src_ip} -> ${a.dst_ip}:${a.dst_port || ''} (${a.confidence_pct || 99}% conf)`,
          time: 'Just now',
          type: 'attack',
        }));

        setSecurityEvents((prev) => [...newEvents, ...prev].slice(0, 30));
      }
    }, 250);

    return () => {
      clearInterval(batchTimer);
      socketService.off('packet', handlePacket);
      socketService.off('alert', handleAlert);
      socketService.off('status', handleStatus);
      socketService.off('ai_analysis_started', handleAiStarted);
      socketService.off('ai_analysis_completed', handleAiCompleted);
      socketService.off('ai_analysis_failed', handleAiFailed);
    };
  }, [recordTrafficPoint]);


  // Explicit Start Monitoring Handler
  const startMonitoring = async () => {
    setIsLoading(true);
    setError(null);
    setMonitoringState('STARTING');

    try {
      const modeToStart = selectedMode || 'LIVE';
      const ifaceToStart = selectedInterface || null;

      const res = await apiService.startMonitoring(modeToStart, ifaceToStart);
      setIsMonitoring(true);
      setActiveMode(res.capture_mode || modeToStart);
      setActiveInterface(res.interface || ifaceToStart || 'Auto');
      setMonitoringState('ACTIVE');

      setSecurityEvents((prev) => [
        {
          id: `start-${Date.now()}`,
          title: `Monitoring Active (${res.capture_mode || modeToStart})`,
          desc: `Capturing on interface: ${res.interface || ifaceToStart || 'Auto'}`,
          time: 'Just now',
          type: 'normal',
        },
        ...prev,
      ]);

      await fetchStatus();
      await fetchFlows();
    } catch (err) {
      console.error('Failed to start monitoring:', err);
      const msg =
        err.response?.data?.error ||
        err.response?.data?.message ||
        err.message ||
        'Failed to start packet capture engine.';
      setError(msg);
      setIsMonitoring(false);
      setMonitoringState('ERROR');
    } finally {
      setIsLoading(false);
    }
  };

  // Explicit Stop Monitoring Handler
  const stopMonitoring = async () => {
    setIsLoading(true);
    setMonitoringState('STOPPING');

    try {
      await apiService.stopMonitoring();
      setIsMonitoring(false);
      setMonitoringState('IDLE');

      setSecurityEvents((prev) => [
        {
          id: `stop-${Date.now()}`,
          title: 'Monitoring Stopped',
          desc: 'Packet capture engine cleanly halted by operator.',
          time: 'Just now',
          type: 'warning',
        },
        ...prev,
      ]);

      await fetchStatus();
    } catch (err) {
      console.error('Failed to stop monitoring:', err);
      setError(err.response?.data?.error || 'Failed to stop monitoring engine.');
      setMonitoringState('ERROR');
    } finally {
      setIsLoading(false);
    }
  };

  const value = {
    // User selections (persisted)
    selectedInterface,
    setSelectedInterface: handleSetSelectedInterface,
    selectedMode,
    setSelectedMode: handleSetSelectedMode,

    // Backend live status
    isMonitoring,
    activeMode,
    activeInterface,
    monitoringState,
    interfaces,
    stats,
    recentPackets,
    alerts,
    flows,
    modelInfo,
    securityEvents,
    trafficHistory,
    aiAnalysis,
    error,
    isLoading,

    // Lifecycle Actions
    startMonitoring,
    stopMonitoring,
    fetchStatus,
    fetchInterfaces,
    fetchFlows,
    fetchModelInfo,
  };

  return <MonitoringContext.Provider value={value}>{children}</MonitoringContext.Provider>;
}

export function useMonitoring() {
  const context = useContext(MonitoringContext);
  if (!context) {
    throw new Error('useMonitoring must be used within a MonitoringProvider');
  }
  return context;
}

