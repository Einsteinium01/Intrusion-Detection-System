import React, { useState, useRef, useEffect } from 'react';
import {
  Brain,
  MessageSquare,
  Sparkles,
  X,
  Send,
  Loader2,
  ShieldAlert,
  AlertCircle,
  Copy,
  Check,
  ChevronDown,
  Trash2,
  ExternalLink,
  Minimize2,
} from 'lucide-react';
import { useMonitoring } from '../context/MonitoringContext';
import { apiService } from '../services/api';

const QUICK_PROMPTS = [
  'Summarize all detected threats',
  'What immediate mitigation steps should I take?',
  'Explain the latest attack technique',
  'Are any hosts performing reconnaissance?',
];

export default function AiChatOverlay() {
  const { alerts, stats, isMonitoring } = useMonitoring();
  const [isOpen, setIsOpen] = useState(false);
  const [selectedAlertId, setSelectedAlertId] = useState('general');
  const [inputQuestion, setInputQuestion] = useState('');
  const [loading, setLoading] = useState(false);
  const [copiedIdx, setCopiedIdx] = useState(null);

  const [messages, setMessages] = useState([
    {
      id: 'welcome',
      role: 'assistant',
      text: "Hello! I'm your NetIntel Security Copilot. I have live access to your IDS detection engine, active flows, and the MITRE ATT&CK RAG knowledge base. Ask me anything about current attacks, threat severity, or defensive response steps.",
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ]);

  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    if (isOpen) {
      scrollToBottom();
    }
  }, [messages, isOpen]);

  const handleCopy = (text, idx) => {
    navigator.clipboard.writeText(text);
    setCopiedIdx(idx);
    setTimeout(() => setCopiedIdx(null), 2000);
  };

  const handleSend = async (questionText) => {
    const q = (questionText || inputQuestion).trim();
    if (!q || loading) return;

    const userMsg = {
      id: `user-${Date.now()}`,
      role: 'user',
      text: q,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      target: selectedAlertId === 'general' ? 'All Threats' : selectedAlertId,
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputQuestion('');
    setLoading(true);

    try {
      const data = await apiService.investigateThreat(
        selectedAlertId === 'general' ? '' : selectedAlertId,
        q
      );

      const assistantMsg = {
        id: `ai-${Date.now()}`,
        role: 'assistant',
        text: data.answer || 'Investigation query complete.',
        evidence: data.supporting_evidence || [],
        sources: data.sources || [],
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };

      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err) {
      const errText = err.response?.data?.error || err.message || 'Failed to get answer from AI.';
      setMessages((prev) => [
        ...prev,
        {
          id: `ai-err-${Date.now()}`,
          role: 'assistant',
          isError: true,
          text: `Error: ${errText}. Please ensure backend and AI are online.`,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const clearChat = () => {
    setMessages([
      {
        id: 'welcome',
        role: 'assistant',
        text: 'Chat history cleared. How can I assist you with your network security posture?',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      },
    ]);
  };

  return (
    <>
      {/* Floating Action Button (Always visible on bottom-right) */}
      {!isOpen && (
        <div className="fixed bottom-6 right-6 z-40">
          <button
            onClick={() => setIsOpen(true)}
            className="group relative flex items-center gap-2.5 px-4 py-2.5 rounded-full bg-gradient-to-r from-[#161B25] to-[#121720] border border-[#202735] hover:border-[#62E8F7]/60 text-[#F4F7FB] shadow-2xl hover:shadow-cyan-500/20 transition-all duration-300 cursor-pointer hover:scale-105 active:scale-95"
            aria-label="Open AI Security Assistant"
          >
            {/* Glowing dot / aura */}
            <span className="absolute -top-1 -right-1 flex h-3 w-3">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#62E8F7] opacity-75"></span>
              <span className="relative inline-flex rounded-full h-3 w-3 bg-[#62E8F7]"></span>
            </span>

            <div className="w-7 h-7 rounded-full bg-[#62E8F7]/15 border border-[#62E8F7]/40 flex items-center justify-center text-[#62E8F7] group-hover:rotate-12 transition-transform">
              <Brain className="w-4 h-4" />
            </div>

            <div className="flex flex-col text-left">
              <span className="text-xs font-mono font-bold leading-none text-[#F4F7FB] flex items-center gap-1.5">
                AI Assistant
                {alerts.length > 0 && (
                  <span className="px-1.5 py-0.2 rounded-full text-[9px] font-mono bg-[#FF3B5C]/20 text-[#FF5C6C] border border-[#FF3B5C]/40">
                    {alerts.length} threats
                  </span>
                )}
              </span>
              <span className="text-[9px] font-mono text-[#667085] leading-tight">Ask about attacks & traffic</span>
            </div>
          </button>
        </div>
      )}

      {/* Floating Chat Window Overlay */}
      {isOpen && (
        <div className="fixed bottom-6 right-6 w-[440px] max-w-[calc(100vw-2rem)] h-[580px] max-h-[calc(100vh-5rem)] bg-[#0E131C] border border-[#202735] shadow-2xl rounded-2xl z-50 flex flex-col overflow-hidden animate-in fade-in slide-in-from-bottom-5 duration-200">
          {/* Header */}
          <div className="bg-[#161B25] border-b border-[#202735] p-3.5 flex items-center justify-between shrink-0">
            <div className="flex items-center gap-2.5">
              <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-[#A78BFA]/20 to-[#62E8F7]/20 border border-[#62E8F7]/30 flex items-center justify-center text-[#62E8F7]">
                <Brain className="w-4 h-4" />
              </div>
              <div>
                <h2 className="text-xs font-mono font-bold text-[#F4F7FB] flex items-center gap-1.5">
                  NetIntel Copilot
                  <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-[#35D07F]/15 text-[#35D07F] font-mono border border-[#35D07F]/30">
                    Online
                  </span>
                </h2>
                <span className="text-[10px] text-[#667085] font-mono">
                  Grounded with Groq & MITRE ATT&CK RAG
                </span>
              </div>
            </div>

            <div className="flex items-center gap-1">
              <button
                onClick={clearChat}
                className="p-1.5 rounded-lg text-[#667085] hover:text-[#FF5C6C] hover:bg-[#202735] transition-colors"
                title="Clear Chat History"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => setIsOpen(false)}
                className="p-1.5 rounded-lg text-[#9AA4B2] hover:text-[#F4F7FB] hover:bg-[#202735] transition-colors"
                title="Minimize Chat"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Context Selector: Target Specific Threat or Global Overview */}
          <div className="bg-[#121720] px-3.5 py-2 border-b border-[#202735] flex items-center gap-2 shrink-0">
            <span className="text-[10px] font-mono text-[#667085] shrink-0 uppercase">Scope:</span>
            <select
              value={selectedAlertId}
              onChange={(e) => setSelectedAlertId(e.target.value)}
              className="flex-1 bg-[#161B25] border border-[#202735] rounded-lg px-2 py-1 text-[11px] font-mono text-[#F4F7FB] focus:outline-none focus:border-[#62E8F7]/40 truncate"
            >
              <option value="general">🌐 All Network Threats ({alerts.length} active)</option>
              {alerts.map((a, i) => (
                <option key={a.id || i} value={a.id || a.alert_id}>
                  [{a.severity || 'HIGH'}] {a.attack_type || 'Threat'} - {a.src_ip}
                </option>
              ))}
            </select>
          </div>

          {/* Messages Stream */}
          <div className="flex-1 p-3.5 overflow-y-auto space-y-3 min-h-0 text-xs">
            {messages.map((m, idx) => (
              <div
                key={m.id || idx}
                className={`flex flex-col ${m.role === 'user' ? 'items-end' : 'items-start'}`}
              >
                {/* Meta header */}
                <div className="flex items-center gap-1.5 text-[9px] font-mono text-[#667085] mb-1 px-1">
                  <span>{m.role === 'user' ? 'You' : 'NetIntel AI'}</span>
                  <span>·</span>
                  <span>{m.timestamp}</span>
                  {m.target && <span className="text-[#62E8F7]">({m.target})</span>}
                </div>

                {/* Message bubble */}
                <div
                  className={`max-w-[90%] rounded-xl p-3 text-[11px] leading-relaxed relative group ${
                    m.role === 'user'
                      ? 'bg-gradient-to-r from-[#62E8F7]/15 to-[#A78BFA]/15 border border-[#62E8F7]/40 text-[#F4F7FB]'
                      : m.isError
                      ? 'bg-[#FF3B5C]/10 border border-[#FF3B5C]/30 text-[#FF5C6C]'
                      : 'bg-[#121720] border border-[#202735] text-[#F4F7FB]'
                  }`}
                >
                  <p className="whitespace-pre-line font-sans">{m.text}</p>

                  {/* Evidence list if present */}
                  {m.evidence && m.evidence.length > 0 && (
                    <div className="mt-2.5 pt-2 border-t border-[#202735]">
                      <span className="text-[10px] font-mono uppercase text-[#35D07F] font-semibold block mb-1">
                        Corroborating Evidence:
                      </span>
                      <ul className="list-disc pl-4 space-y-0.5 text-[10px] text-[#9AA4B2]">
                        {m.evidence.map((ev, i) => (
                          <li key={i}>{ev}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Sources if present */}
                  {m.sources && m.sources.length > 0 && (
                    <div className="mt-2 pt-1.5 border-t border-[#202735] flex flex-wrap gap-1 text-[9px] text-[#667085]">
                      <span className="font-mono text-[#A78BFA]">RAG Sources:</span>
                      {m.sources.map((s, i) => (
                        <span key={i} className="font-mono text-[#9AA4B2]">
                          [{s.source_id}]
                        </span>
                      ))}
                    </div>
                  )}

                  {/* Quick Copy button */}
                  {m.role === 'assistant' && !m.isError && (
                    <button
                      onClick={() => handleCopy(m.text, idx)}
                      className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 p-1 rounded hover:bg-[#202735] text-[#9AA4B2] hover:text-[#F4F7FB] transition-opacity"
                      title="Copy response"
                    >
                      {copiedIdx === idx ? (
                        <Check className="w-3 h-3 text-[#35D07F]" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                    </button>
                  )}
                </div>
              </div>
            ))}

            {loading && (
              <div className="flex items-center gap-2 p-3 rounded-xl bg-[#121720] border border-[#202735] text-xs text-[#9AA4B2]">
                <Loader2 className="w-4 h-4 text-[#62E8F7] animate-spin" />
                <span className="font-mono text-[11px] animate-pulse">
                  Querying Groq LLM & RAG Vector Store...
                </span>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Quick Prompts Carousel */}
          <div className="px-3 py-2 bg-[#121720] border-t border-[#202735] overflow-x-auto flex gap-1.5 shrink-0 no-scrollbar">
            {QUICK_PROMPTS.map((p, idx) => (
              <button
                key={idx}
                onClick={() => handleSend(p)}
                disabled={loading}
                className="whitespace-nowrap px-2.5 py-1 rounded-full text-[10px] font-mono bg-[#161B25] hover:bg-[#202735] text-[#9AA4B2] hover:text-[#F4F7FB] border border-[#202735] hover:border-[#62E8F7]/40 transition-colors disabled:opacity-40 cursor-pointer"
              >
                {p}
              </button>
            ))}
          </div>

          {/* Input Box */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSend();
            }}
            className="p-3 bg-[#161B25] border-t border-[#202735] flex items-center gap-2 shrink-0"
          >
            <input
              type="text"
              value={inputQuestion}
              onChange={(e) => setInputQuestion(e.target.value)}
              placeholder="Ask about attacks, mitigation, or network..."
              disabled={loading}
              className="flex-1 bg-[#121720] border border-[#202735] rounded-xl px-3 py-2 text-xs text-[#F4F7FB] placeholder-[#667085] focus:outline-none focus:border-[#62E8F7]/50"
            />
            <button
              type="submit"
              disabled={loading || !inputQuestion.trim()}
              className="p-2.5 rounded-xl bg-gradient-to-r from-[#A78BFA] to-[#62E8F7] hover:from-[#9065FA] hover:to-[#42D8F0] text-[#090D13] font-bold disabled:opacity-40 transition-all cursor-pointer shadow-md hover:shadow-cyan-500/20"
              title="Send Question"
            >
              {loading ? (
                <Loader2 className="w-4 h-4 animate-spin text-[#090D13]" />
              ) : (
                <Send className="w-4 h-4 text-[#090D13]" />
              )}
            </button>
          </form>
        </div>
      )}
    </>
  );
}
