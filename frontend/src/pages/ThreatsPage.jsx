import React, { useState } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  Search,
  X,
  Shield,
  Activity,
  Brain,
  Sparkles,
} from 'lucide-react';
import { useMonitoring } from '../context/MonitoringContext';
import { apiService } from '../services/api';
import AiAnalysisPanel from '../components/AiAnalysisPanel';
import InvestigationChat from '../components/InvestigationChat';

export default function ThreatsPage() {
  const { alerts, isMonitoring, aiAnalysis } = useMonitoring();

  const [selectedThreat, setSelectedThreat] = useState(null);
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [searchFilter, setSearchFilter] = useState('');

  const currentThreatId = selectedThreat ? (selectedThreat.id || selectedThreat.alert_id) : null;

  const handleOpenAiAnalysis = async (alert) => {
    if (!alert) return;
    setSelectedThreat(alert);
    const alertId = alert.id || alert.alert_id;
    const currentState = aiAnalysis[alertId]?.state;

    // Trigger LLM analysis only if not already running or completed
    if (!currentState || currentState === 'FAILED' || currentState === 'IDLE') {
      try {
        await apiService.triggerAiAnalysis(alert);
      } catch (err) {
        console.error('Failed to trigger AI analysis:', err);
      }
    }
  };


  // Tally severity counts from real alerts
  const criticalCount = alerts.filter((a) => (a.severity || '').toUpperCase() === 'CRITICAL').length;
  const highCount = alerts.filter((a) => (a.severity || '').toUpperCase() === 'HIGH').length;
  const mediumCount = alerts.filter((a) => (a.severity || '').toUpperCase() === 'MEDIUM').length;
  const lowCount = alerts.filter((a) => (a.severity || '').toUpperCase() === 'LOW').length;

  const cleanSearch = searchFilter.trim().toLowerCase();
  const filteredAlerts = alerts.filter((a) => {
    if (severityFilter !== 'ALL' && (a.severity || 'HIGH').toUpperCase() !== severityFilter) {
      return false;
    }
    if (cleanSearch) {
      const src = (a.src_ip || '').toLowerCase();
      const dst = (a.dst_ip || '').toLowerCase();
      const type = (a.attack_type || '').toLowerCase();
      const details = (a.details || '').toLowerCase();
      if (
        !src.includes(cleanSearch) &&
        !dst.includes(cleanSearch) &&
        !type.includes(cleanSearch) &&
        !details.includes(cleanSearch)
      ) {
        return false;
      }
    }
    return true;
  });

  return (
    <div className="h-full flex flex-col space-y-3 max-h-full overflow-hidden relative">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 pb-2 border-b border-[#202735] flex-shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-[#F4F7FB]">Threat Intelligence</h1>
            <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-[#FF3B5C]/15 text-[#FF5C6C] border border-[#FF3B5C]/30 flex items-center gap-1">
              <ShieldAlert className="w-3 h-3" />
              {alerts.length} Detected Incidents
            </span>
          </div>
          <p className="text-xs text-[#9AA4B2] mt-0.5">
            Real-time security threats identified by XGBoost flow classifier and ScanDetector.
          </p>
        </div>
      </div>

      {/* Severity Stat Cards (Section 30 of design.md) */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 flex-shrink-0">
        <div className="bg-[#121720] border border-[#202735] rounded-xl p-3 flex items-center justify-between">
          <div>
            <div className="text-[10px] font-mono uppercase text-[#667085]">Critical</div>
            <div className="text-2xl font-bold font-mono text-[#FF3B5C] mt-0.5">{criticalCount}</div>
          </div>
          <div className="w-8 h-8 rounded-lg bg-[#FF3B5C]/10 border border-[#FF3B5C]/30 flex items-center justify-center text-[#FF3B5C]">
            <ShieldAlert className="w-4 h-4" />
          </div>
        </div>

        <div className="bg-[#121720] border border-[#202735] rounded-xl p-3 flex items-center justify-between">
          <div>
            <div className="text-[10px] font-mono uppercase text-[#667085]">High Severity</div>
            <div className="text-2xl font-bold font-mono text-[#FF5C6C] mt-0.5">{highCount}</div>
          </div>
          <div className="w-8 h-8 rounded-lg bg-[#FF5C6C]/10 border border-[#FF5C6C]/30 flex items-center justify-center text-[#FF5C6C]">
            <AlertTriangle className="w-4 h-4" />
          </div>
        </div>

        <div className="bg-[#121720] border border-[#202735] rounded-xl p-3 flex items-center justify-between">
          <div>
            <div className="text-[10px] font-mono uppercase text-[#667085]">Medium</div>
            <div className="text-2xl font-bold font-mono text-[#F5B84B] mt-0.5">{mediumCount}</div>
          </div>
          <div className="w-8 h-8 rounded-lg bg-[#F5B84B]/10 border border-[#F5B84B]/30 flex items-center justify-center text-[#F5B84B]">
            <Activity className="w-4 h-4" />
          </div>
        </div>

        <div className="bg-[#121720] border border-[#202735] rounded-xl p-3 flex items-center justify-between">
          <div>
            <div className="text-[10px] font-mono uppercase text-[#667085]">Low / Suspicious</div>
            <div className="text-2xl font-bold font-mono text-[#62E8F7] mt-0.5">{lowCount}</div>
          </div>
          <div className="w-8 h-8 rounded-lg bg-[#62E8F7]/10 border border-[#62E8F7]/30 flex items-center justify-center text-[#62E8F7]">
            <Shield className="w-4 h-4" />
          </div>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2.5 bg-[#121720] border border-[#202735] rounded-xl p-2.5 flex-shrink-0">
        <div className="flex items-center gap-1 text-[11px]">
          <span className="text-[10px] font-mono text-[#667085] uppercase mr-1">Severity:</span>
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-2.5 py-1 rounded-lg font-medium transition-all ${
                severityFilter === sev
                  ? 'bg-[#FF3B5C]/20 text-[#FF5C6C] border border-[#FF3B5C]/40'
                  : 'text-[#9AA4B2] hover:bg-[#161B25] hover:text-[#F4F7FB]'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>

        <div className="relative w-48 sm:w-64">
          <Search className="w-3.5 h-3.5 text-[#667085] absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            placeholder="Search threats..."
            className="w-full bg-[#161B25] border border-[#202735] rounded-lg py-1 pl-8 pr-2.5 text-[11px] text-[#F4F7FB] placeholder-[#667085] focus:outline-none focus:border-[#FF5C6C]/40"
          />
        </div>
      </div>

      {/* Threat Incident Table */}
      <div className="flex-1 bg-[#121720] border border-[#202735] rounded-xl overflow-hidden flex flex-col min-h-0">
        <div className="overflow-y-auto flex-1">
          <table className="w-full text-left border-collapse">
            <thead className="bg-[#161B25] sticky top-0 z-10 text-[10px] uppercase font-mono tracking-wider text-[#667085] border-b border-[#202735]">
              <tr>
                <th className="py-2.5 px-3">Time</th>
                <th className="py-2.5 px-3">Attack Type</th>
                <th className="py-2.5 px-3">Source IP</th>
                <th className="py-2.5 px-3">Destination IP</th>
                <th className="py-2.5 px-3 text-center">Severity</th>
                <th className="py-2.5 px-3 text-right">Confidence</th>
                <th className="py-2.5 px-3 text-center">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#202735]/60 text-[11px]">
              {filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-16 text-center text-[#667085]">
                    <div className="flex flex-col items-center justify-center gap-2">
                      <Shield className="w-8 h-8 text-[#35D07F]/40" />
                      <span className="font-semibold text-sm text-[#F4F7FB]">No Threats Detected</span>
                      <span className="text-xs max-w-sm text-[#9AA4B2]">
                        {isMonitoring
                          ? 'Active capture is running cleanly without anomaly spikes or hostile scan signatures.'
                          : 'Monitoring is offline. Start the engine on Dashboard to evaluate traffic.'}
                      </span>
                    </div>
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert, idx) => {
                  const conf = alert.confidence_pct ? `${alert.confidence_pct.toFixed(1)}%` : '—';
                  const sev = (alert.severity || 'HIGH').toUpperCase();
                  const sevColor =
                    sev === 'CRITICAL'
                      ? 'bg-[#FF3B5C]/20 border-[#FF3B5C]/40 text-[#FF3B5C]'
                      : sev === 'HIGH'
                      ? 'bg-[#FF5C6C]/20 border-[#FF5C6C]/40 text-[#FF5C6C]'
                      : sev === 'MEDIUM'
                      ? 'bg-[#F5B84B]/20 border-[#F5B84B]/40 text-[#F5B84B]'
                      : 'bg-[#62E8F7]/20 border-[#62E8F7]/40 text-[#62E8F7]';

                  return (
                    <tr
                      key={alert.id || idx}
                      onClick={() => setSelectedThreat(alert)}
                      className="hover:bg-[#161B25] cursor-pointer transition-colors"
                    >
                      <td className="py-2.5 px-3 font-mono text-[10px] text-[#9AA4B2]">
                        {alert.timestamp_str || 'Just now'}
                      </td>
                      <td className="py-2.5 px-3 font-semibold text-[#FF5C6C]">
                        {alert.attack_type || 'Malicious Intrusion'}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-[#F4F7FB]">{alert.src_ip || '—'}</td>
                      <td className="py-2.5 px-3 font-mono text-[#9AA4B2]">
                        {alert.dst_ip ? `${alert.dst_ip}${alert.dst_port ? ':' + alert.dst_port : ''}` : '—'}
                      </td>
                      <td className="py-2.5 px-3 text-center">
                        <span className={`px-2 py-0.5 rounded-full text-[9px] font-mono font-semibold border ${sevColor}`}>
                          {sev}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 font-mono text-right text-[#F4F7FB]">{conf}</td>
                      <td className="py-2.5 px-3 text-center" onClick={(e) => e.stopPropagation()}>
                        <button
                          onClick={() => handleOpenAiAnalysis(alert)}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[10px] font-mono font-semibold bg-[#A78BFA]/10 hover:bg-[#A78BFA]/20 text-[#A78BFA] border border-[#A78BFA]/30 hover:border-[#A78BFA]/60 transition-all cursor-pointer shadow-sm active:scale-95"
                          title="Open AI Security Analysis"
                        >
                          <Brain className="w-3.5 h-3.5 text-[#A78BFA]" />
                          <span>AI Analysis</span>
                          {aiAnalysis[alert.id || alert.alert_id]?.state === 'COMPLETED' && (
                            <span className="w-1.5 h-1.5 rounded-full bg-[#35D07F]" title="Analysis Ready" />
                          )}
                          {aiAnalysis[alert.id || alert.alert_id]?.state === 'ANALYZING' && (
                            <span className="w-1.5 h-1.5 rounded-full bg-[#F5B84B] animate-ping" title="Analyzing..." />
                          )}
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Threat Details Drawer (Section 32 of design.md: 420-480px width) */}
      {selectedThreat && (
        <div className="fixed inset-y-0 right-0 w-[450px] bg-[#0E131C] border-l border-[#202735] shadow-2xl z-50 flex flex-col p-5 overflow-y-auto animate-in slide-in-from-right duration-200">
          <div className="flex items-center justify-between pb-3 border-b border-[#202735]">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-[#FF5C6C]" />
              <h2 className="text-base font-bold text-[#F4F7FB]">Threat Incident Details</h2>
            </div>
            <button
              onClick={() => setSelectedThreat(null)}
              className="p-1.5 rounded-lg hover:bg-[#161B25] text-[#9AA4B2] hover:text-[#F4F7FB]"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="py-4 space-y-4 text-xs">
            {/* Primary Threat Banner */}
            <div className="p-3.5 bg-[#FF3B5C]/10 border border-[#FF3B5C]/30 rounded-xl space-y-1">
              <div className="text-[10px] uppercase font-mono text-[#FF5C6C] font-semibold">
                Classified Threat Type
              </div>
              <div className="text-lg font-bold text-[#F4F7FB]">
                {selectedThreat.attack_type || 'Malicious Intrusion'}
              </div>
              <div className="text-[11px] text-[#9AA4B2] leading-relaxed">
                {selectedThreat.details ||
                  'Flow signature triggered ML feature anomaly weights characteristic of an intrusion.'}
              </div>
            </div>

            {/* Core Attribution */}
            <div className="bg-[#121720] border border-[#202735] rounded-xl p-3.5 space-y-2.5">
              <div className="text-[10px] uppercase font-mono text-[#667085]">Network Attribution</div>
              <div className="grid grid-cols-2 gap-2 text-[11px]">
                <div>
                  <span className="text-[#667085] block">Source Host</span>
                  <span className="font-mono text-[#F4F7FB] font-semibold">{selectedThreat.src_ip || '—'}</span>
                </div>
                <div>
                  <span className="text-[#667085] block">Destination Host</span>
                  <span className="font-mono text-[#F4F7FB] font-semibold">{selectedThreat.dst_ip || '—'}</span>
                </div>
                <div>
                  <span className="text-[#667085] block">Target Port</span>
                  <span className="font-mono text-[#62E8F7]">{selectedThreat.dst_port || '—'}</span>
                </div>
                <div>
                  <span className="text-[#667085] block">Transport Protocol</span>
                  <span className="font-mono text-[#A78BFA]">{selectedThreat.protocol || 'TCP'}</span>
                </div>
              </div>
            </div>

            {/* Model Evaluation */}
            <div className="bg-[#121720] border border-[#202735] rounded-xl p-3.5 space-y-2.5">
              <div className="text-[10px] uppercase font-mono text-[#667085]">Model Diagnostic</div>
              <div className="grid grid-cols-2 gap-2 text-[11px]">
                <div>
                  <span className="text-[#667085] block">Classification Confidence</span>
                  <span className="font-mono text-[#35D07F] font-bold">
                    {selectedThreat.confidence_pct ? `${selectedThreat.confidence_pct.toFixed(2)}%` : '—'}
                  </span>
                </div>
                <div>
                  <span className="text-[#667085] block">Severity Tier</span>
                  <span className="font-mono text-[#FF5C6C] font-semibold">
                    {selectedThreat.severity || 'HIGH'}
                  </span>
                </div>
                <div>
                  <span className="text-[#667085] block">Detection Engine</span>
                  <span className="font-mono text-[#F4F7FB]">XGBoost + Welford</span>
                </div>
                <div>
                  <span className="text-[#667085] block">Timestamp</span>
                  <span className="font-mono text-[#9AA4B2]">{selectedThreat.timestamp_str || 'Live'}</span>
                </div>
              </div>
            </div>
            
            {/* AI Analysis Panel */}
            <AiAnalysisPanel
              alert={selectedThreat}
              aiState={currentThreatId ? aiAnalysis[currentThreatId] : undefined}
              onTriggerAnalysis={() => handleOpenAiAnalysis(selectedThreat)}
            />
            
            {/* AI Investigation Chat */}
            <InvestigationChat alertId={currentThreatId} />
          </div>
        </div>
      )}
    </div>
  );
}
