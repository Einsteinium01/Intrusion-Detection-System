import React, { useState } from 'react';
import { Send, Loader2, Sparkles, AlertCircle, HelpCircle } from 'lucide-react';
import { apiService } from '../services/api';

const QUICK_QUESTIONS = [
  'Why was this host flagged?',
  'What are the immediate mitigation steps?',
  'Explain the MITRE technique involved',
];

export default function InvestigationChat({ alertId }) {
  const [question, setQuestion] = useState('');
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState(null);
  const [error, setError] = useState(null);

  const handleAsk = async (queryText) => {
    const q = queryText || question;
    if (!q || !q.trim()) return;

    setLoading(true);
    setError(null);
    try {
      const data = await apiService.investigateThreat(alertId, q.trim());
      setResponse(data);
    } catch (err) {
      const msg = err.response?.data?.error || err.message || 'Investigation request failed';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    handleAsk(question);
  };

  return (
    <div className="bg-[#121720] border border-[#202735] rounded-xl flex flex-col overflow-hidden shadow-lg">
      <div className="bg-[#161B25] border-b border-[#202735] px-3.5 py-2.5 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Sparkles className="w-3.5 h-3.5 text-[#62E8F7]" />
          <span className="text-xs font-mono font-bold text-[#F4F7FB]">Investigate With AI</span>
        </div>
        <span className="text-[9px] font-mono text-[#667085]">Grounded in telemetry & RAG</span>
      </div>

      <div className="p-3.5 space-y-3">
        {/* Quick prompt pills */}
        <div className="flex flex-wrap gap-1.5">
          {QUICK_QUESTIONS.map((q, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => {
                setQuestion(q);
                handleAsk(q);
              }}
              disabled={loading}
              className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-[#161B25] hover:bg-[#202735] text-[#9AA4B2] hover:text-[#F4F7FB] border border-[#202735] hover:border-[#62E8F7]/40 transition-colors disabled:opacity-50 text-left"
            >
              {q}
            </button>
          ))}
        </div>

        {error && (
          <div className="bg-[#FF3B5C]/10 border border-[#FF3B5C]/30 rounded-lg p-2.5 text-[11px] text-[#FF5C6C] flex items-start gap-2">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
            <span className="leading-snug">{error}</span>
          </div>
        )}

        {response && (
          <div className="bg-[#090D13] border border-[#202735] rounded-lg p-3 text-[11px] space-y-2.5">
            <div className="text-[#F4F7FB] leading-relaxed font-sans font-medium">
              {response.answer}
            </div>

            {response.supporting_evidence && response.supporting_evidence.length > 0 && (
              <div className="pt-1.5 border-t border-[#202735]">
                <span className="text-[10px] uppercase font-mono text-[#62E8F7] font-semibold block mb-1">
                  Corroborating Evidence:
                </span>
                <ul className="list-disc pl-4 text-[#9AA4B2] space-y-0.5 text-[10px]">
                  {response.supporting_evidence.map((ev, i) => (
                    <li key={i}>{ev}</li>
                  ))}
                </ul>
              </div>
            )}

            {response.sources && response.sources.length > 0 && (
              <div className="text-[9px] text-[#667085] flex gap-1 flex-wrap pt-1 border-t border-[#202735]">
                <span className="font-mono uppercase text-[#A78BFA]">RAG Citations:</span>
                {response.sources.map((s, i) => (
                  <span key={i} className="font-mono text-[#9AA4B2]">
                    [{s.source_id}] {s.title}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}

        <form onSubmit={handleSubmit} className="flex gap-2">
          <input
            type="text"
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="Ask a technical investigation question..."
            className="flex-1 bg-[#161B25] border border-[#202735] rounded-lg px-3 py-1.5 text-[11px] text-[#F4F7FB] placeholder-[#667085] focus:outline-none focus:border-[#62E8F7]/50"
            disabled={loading}
          />
          <button
            type="submit"
            disabled={loading || !question.trim()}
            className="bg-[#62E8F7]/10 hover:bg-[#62E8F7]/20 text-[#62E8F7] border border-[#62E8F7]/30 hover:border-[#62E8F7]/60 rounded-lg px-3 flex items-center justify-center transition-all disabled:opacity-40 cursor-pointer"
          >
            {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
          </button>
        </form>
      </div>
    </div>
  );
}
