import React, { useState } from 'react';
import {
  Brain,
  Sparkles,
  Loader2,
  AlertCircle,
  CheckCircle2,
  BookOpen,
  Copy,
  Check,
  RotateCw,
  Shield,
  Terminal,
  ExternalLink,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';

export default function AiAnalysisPanel({ alert, aiState, onTriggerAnalysis }) {
  const [copied, setCopied] = useState(false);
  const [sourcesOpen, setSourcesOpen] = useState(false);

  const handleCopy = (text) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // State 1: Not triggered yet
  if (!aiState || !aiState.state) {
    return (
      <div className="bg-gradient-to-br from-[#121720] to-[#161B25] border border-[#202735] hover:border-[#A78BFA]/40 rounded-xl p-4 transition-all shadow-lg">
        <div className="flex items-start gap-3">
          <div className="p-2.5 rounded-lg bg-[#A78BFA]/10 border border-[#A78BFA]/30 text-[#A78BFA]">
            <Brain className="w-5 h-5 animate-pulse" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-mono font-bold text-[#F4F7FB] flex items-center gap-1.5">
                AI Threat Intelligence
                <span className="text-[9px] px-1.5 py-0.5 rounded bg-[#A78BFA]/20 text-[#A78BFA] border border-[#A78BFA]/40 font-mono">
                  GROQ + RAG
                </span>
              </h3>
            </div>
            <p className="text-[11px] text-[#9AA4B2] mt-1 leading-relaxed">
              Generate an in-depth cyber forensic analysis with MITRE ATT&CK technique mapping and playbook response guidance.
            </p>

            <div className="mt-3.5 flex items-center gap-2">
              <button
                onClick={onTriggerAnalysis}
                className="inline-flex items-center justify-center gap-2 px-3.5 py-1.5 rounded-lg text-[11px] font-mono font-semibold bg-gradient-to-r from-[#A78BFA] to-[#62E8F7] hover:from-[#9065FA] hover:to-[#42D8F0] text-[#090D13] shadow-md hover:shadow-cyan-500/20 transition-all cursor-pointer"
              >
                <Sparkles className="w-3.5 h-3.5 text-[#090D13]" />
                Run AI Security Analysis
              </button>
              <span className="text-[10px] font-mono text-[#667085]">On-demand token optimization</span>
            </div>
          </div>
        </div>
      </div>
    );
  }

  const { state, analysis, error } = aiState;

  // State 2: Disabled
  if (state === 'DISABLED') {
    return (
      <div className="bg-[#121720] border border-[#202735] rounded-xl p-4 flex items-center justify-between text-[#9AA4B2]">
        <div className="flex items-center gap-2.5">
          <AlertCircle className="w-4 h-4 text-[#F5B84B]" />
          <div>
            <div className="text-[11px] font-mono font-semibold text-[#F4F7FB]">AI Layer Offline</div>
            <div className="text-[10px] text-[#667085]">AI_ENABLED is currently disabled in backend environment.</div>
          </div>
        </div>
        <button
          onClick={onTriggerAnalysis}
          className="px-2.5 py-1 text-[10px] font-mono rounded bg-[#202735] hover:bg-[#2A3346] text-[#F4F7FB]"
        >
          Retry
        </button>
      </div>
    );
  }

  // State 3: Analyzing / Pending
  if (state === 'ANALYZING' || state === 'PENDING') {
    return (
      <div className="bg-[#121720] border border-[#A78BFA]/30 rounded-xl p-4 shadow-lg shadow-purple-500/5 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Loader2 className="w-4 h-4 text-[#A78BFA] animate-spin" />
            <span className="text-[11px] font-mono font-semibold text-[#F4F7FB]">
              AI Security Copilot Analyzing...
            </span>
          </div>
          <span className="text-[9px] font-mono text-[#A78BFA] px-2 py-0.5 rounded-full bg-[#A78BFA]/10 border border-[#A78BFA]/30 animate-pulse">
            Processing Threat
          </span>
        </div>

        <div className="space-y-1.5 pt-1 text-[10px] font-mono">
          <div className="flex items-center gap-2 text-[#35D07F]">
            <CheckCircle2 className="w-3 h-3 shrink-0" />
            <span>Telemetry & Flow Statistics Normalized</span>
          </div>
          <div className="flex items-center gap-2 text-[#62E8F7] animate-pulse">
            <Loader2 className="w-3 h-3 shrink-0 animate-spin" />
            <span>Querying FAISS Knowledge Store (MITRE ATT&CK & Playbooks)</span>
          </div>
          <div className="flex items-center gap-2 text-[#667085]">
            <div className="w-3 h-3 rounded-full border border-[#667085] flex items-center justify-center text-[8px]">3</div>
            <span>Groq LLM Reasoning & Defensive Synthesis</span>
          </div>
        </div>
      </div>
    );
  }

  // State 4: Failed
  if (state === 'FAILED' || error) {
    return (
      <div className="bg-[#FF3B5C]/10 border border-[#FF3B5C]/30 rounded-xl p-4 flex flex-col gap-2.5">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-[#FF5C6C]" />
            <span className="text-[11px] font-mono font-semibold text-[#FF5C6C]">AI Analysis Failed</span>
          </div>
          <button
            onClick={onTriggerAnalysis}
            className="inline-flex items-center gap-1 px-2.5 py-1 text-[10px] font-mono rounded bg-[#FF3B5C]/20 hover:bg-[#FF3B5C]/30 text-[#FF5C6C] border border-[#FF3B5C]/40 transition-colors"
          >
            <RotateCw className="w-3 h-3" />
            Retry
          </button>
        </div>
        <p className="text-[10px] text-[#9AA4B2] leading-relaxed">
          {error || 'Unable to communicate with Groq LLM or RAG vector store. Please check your API key and connection.'}
        </p>
      </div>
    );
  }

  // State 5: Completed
  if (state === 'COMPLETED' && analysis) {
    const sev = (analysis.severity || 'HIGH').toUpperCase();
    const sevBadgeColor =
      sev === 'CRITICAL'
        ? 'bg-[#FF3B5C]/20 text-[#FF3B5C] border-[#FF3B5C]/40'
        : sev === 'HIGH'
        ? 'bg-[#FF5C6C]/20 text-[#FF5C6C] border-[#FF5C6C]/40'
        : sev === 'MEDIUM'
        ? 'bg-[#F5B84B]/20 text-[#F5B84B] border-[#F5B84B]/40'
        : 'bg-[#62E8F7]/20 text-[#62E8F7] border-[#62E8F7]/40';

    return (
      <div className="bg-[#121720] border border-[#202735] rounded-xl overflow-hidden shadow-xl space-y-0 divide-y divide-[#202735]">
        {/* Header bar */}
        <div className="bg-[#161B25] px-4 py-2.5 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Brain className="w-4 h-4 text-[#A78BFA]" />
            <span className="text-xs font-mono font-bold text-[#F4F7FB]">AI Security Intelligence</span>
            <span className={`text-[9px] font-mono font-bold px-2 py-0.5 rounded border ${sevBadgeColor}`}>
              {sev}
            </span>
          </div>
          <div className="flex items-center gap-1.5">
            <button
              onClick={() => handleCopy(analysis.summary)}
              className="p-1 rounded text-[#9AA4B2] hover:text-[#F4F7FB] hover:bg-[#202735] transition-colors"
              title="Copy Summary"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-[#35D07F]" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
            <button
              onClick={onTriggerAnalysis}
              className="p-1 rounded text-[#9AA4B2] hover:text-[#F4F7FB] hover:bg-[#202735] transition-colors"
              title="Re-run Analysis"
            >
              <RotateCw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Executive Summary */}
        <div className="p-4 space-y-1.5">
          <div className="text-[10px] font-mono uppercase tracking-wider text-[#667085] font-semibold">
            Executive Summary
          </div>
          <p className="text-xs text-[#F4F7FB] leading-relaxed font-sans font-medium">
            {analysis.summary}
          </p>
        </div>

        {/* Technical Deep Dive */}
        {analysis.technical_analysis && (
          <div className="p-4 space-y-1.5 bg-[#0D1118]">
            <div className="flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-wider text-[#62E8F7] font-semibold">
              <Terminal className="w-3 h-3 text-[#62E8F7]" />
              Technical Mechanics
            </div>
            <div className="text-[11px] font-mono text-[#9AA4B2] leading-relaxed whitespace-pre-line bg-[#090D13] p-2.5 rounded-lg border border-[#202735]">
              {analysis.technical_analysis}
            </div>
          </div>
        )}

        {/* MITRE ATT&CK Mapping */}
        {analysis.mitre_attack && analysis.mitre_attack.length > 0 && (
          <div className="p-4 space-y-2.5">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase tracking-wider text-[#A78BFA] font-semibold">
                MITRE ATT&CK Techniques
              </span>
              <span className="text-[9px] font-mono text-[#667085]">
                {analysis.mitre_attack.length} Identified
              </span>
            </div>
            <div className="space-y-2">
              {analysis.mitre_attack.map((mitre, idx) => (
                <div
                  key={idx}
                  className="bg-[#161B25] border border-[#202735] hover:border-[#A78BFA]/30 rounded-lg p-2.5 transition-colors"
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-xs font-bold text-[#62E8F7] flex items-center gap-1">
                      {mitre.technique_id}
                      <span className="text-[#F4F7FB] font-normal">· {mitre.technique_name}</span>
                    </span>
                  </div>
                  {mitre.rationale && (
                    <p className="text-[10px] text-[#9AA4B2] leading-relaxed">{mitre.rationale}</p>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Forensic Evidence Points */}
        {analysis.evidence && analysis.evidence.length > 0 && (
          <div className="p-4 space-y-2">
            <div className="text-[10px] font-mono uppercase tracking-wider text-[#667085] font-semibold flex items-center gap-1.5">
              <Shield className="w-3 h-3 text-[#35D07F]" />
              Observed Evidence
            </div>
            <ul className="space-y-1.5">
              {analysis.evidence.map((item, idx) => (
                <li key={idx} className="flex items-start gap-2 text-[11px] text-[#F4F7FB]">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#35D07F] shrink-0 mt-1.5" />
                  <span className="leading-snug">{item}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Recommended Actions / Playbook */}
        {analysis.recommended_actions && analysis.recommended_actions.length > 0 && (
          <div className="p-4 space-y-2.5">
            <div className="text-[10px] font-mono uppercase tracking-wider text-[#35D07F] font-semibold">
              Immediate Defensive Recommendations
            </div>
            <div className="space-y-1.5">
              {analysis.recommended_actions.map((act, idx) => (
                <div
                  key={idx}
                  className="flex items-start gap-2.5 p-2 rounded-lg bg-[#161B25] border border-[#202735] text-[11px] text-[#F4F7FB]"
                >
                  <span className="font-mono text-[9px] font-bold px-1.5 py-0.5 rounded bg-[#35D07F]/20 text-[#35D07F] border border-[#35D07F]/40 shrink-0">
                    {String(idx + 1).padStart(2, '0')}
                  </span>
                  <span className="leading-relaxed">{act}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* RAG Knowledge Citations Collapsible */}
        {analysis.sources && analysis.sources.length > 0 && (
          <div className="p-4 space-y-2">
            <button
              onClick={() => setSourcesOpen(!sourcesOpen)}
              className="w-full flex items-center justify-between text-[10px] font-mono uppercase tracking-wider text-[#667085] hover:text-[#9AA4B2] transition-colors"
            >
              <div className="flex items-center gap-1.5">
                <BookOpen className="w-3.5 h-3.5 text-[#A78BFA]" />
                <span>Grounded Knowledge Sources ({analysis.sources.length})</span>
              </div>
              {sourcesOpen ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            </button>

            {sourcesOpen && (
              <div className="space-y-1.5 pt-1">
                {analysis.sources.map((src, idx) => (
                  <div
                    key={idx}
                    className="p-2 rounded bg-[#090D13] border border-[#202735] flex items-center justify-between text-[10px]"
                  >
                    <div className="min-w-0 pr-2">
                      <div className="font-mono text-[#A78BFA] font-semibold truncate">{src.source_id}</div>
                      <div className="text-[#667085] truncate">{src.title}</div>
                    </div>
                    {src.relevance !== undefined && (
                      <span className="font-mono text-[9px] text-[#62E8F7] px-1.5 py-0.5 rounded bg-[#62E8F7]/10 shrink-0">
                        {typeof src.relevance === 'number'
                          ? `${(src.relevance * 100).toFixed(0)}% match`
                          : src.relevance}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    );
  }

  return null;
}
