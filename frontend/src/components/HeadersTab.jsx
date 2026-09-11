import React from 'react';
import { CheckCircle2, XCircle, AlertTriangle, Shield, Layers, HelpCircle } from 'lucide-react';

export default function HeadersTab({ headersData }) {
  if (!headersData) return null;

  const present = headersData.present_headers || {};
  const missing = headersData.missing_headers || [];
  const contradictions = headersData.contradictions || [];
  const breakingChanges = headersData.breaking_changes || [];
  const csp = headersData.csp_breakdown;
  const hsts = headersData.hsts_breakdown;

  return (
    <div className="space-y-6">
      {/* Contradictions & Breaking Changes Alerts */}
      {(contradictions.length > 0 || breakingChanges.length > 0) && (
        <div className="space-y-3">
          {contradictions.map((c, i) => (
            <div key={i} className="p-4 rounded-xl border border-amber-500/40 bg-amber-950/20 text-amber-200">
              <div className="flex items-center gap-2 font-bold text-amber-400">
                <AlertTriangle className="w-5 h-5" /> Contradictory Security Header Configuration
              </div>
              <p className="text-sm mt-1">{c.description}</p>
              <div className="text-xs text-amber-300/80 mt-1.5 font-medium">Impact: {c.impact}</div>
            </div>
          ))}

          {breakingChanges.map((b, i) => (
            <div key={i} className="p-4 rounded-xl border border-rose-500/40 bg-rose-950/20 text-rose-200">
              <div className="flex items-center gap-2 font-bold text-rose-400">
                <AlertTriangle className="w-5 h-5" /> Deprecated or Risky Configuration Detected
              </div>
              <p className="text-sm mt-1">{b.description}</p>
              <div className="text-xs text-rose-300/80 mt-1.5 font-medium">Impact: {b.impact}</div>
            </div>
          ))}
        </div>
      )}

      {/* CSP Deep Breakdown */}
      {csp && (
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/40 space-y-3">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-400" /> Content-Security-Policy (CSP) Directives
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono">
            {Object.entries(csp.directives || {}).map(([directive, values]) => {
              const hasUnsafe = values.some(v => v.includes('unsafe') || v === '*');
              return (
                <div
                  key={directive}
                  className={`p-2.5 rounded border ${
                    hasUnsafe ? 'border-amber-500/40 bg-amber-950/10' : 'border-slate-800 bg-slate-950/50'
                  }`}
                >
                  <span className="text-cyan-400 font-semibold">{directive}: </span>
                  <span className={hasUnsafe ? 'text-amber-300' : 'text-slate-300'}>
                    {values.length ? values.join(' ') : 'none'}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Present Headers */}
      <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/40 space-y-4">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" /> Present Security Headers ({Object.keys(present).length})
        </h3>
        {Object.keys(present).length > 0 ? (
          <div className="grid grid-cols-1 gap-3">
            {Object.entries(present).map(([key, item]) => (
              <div key={key} className="p-3 rounded-lg border border-slate-800 bg-slate-950/60 flex flex-col md:flex-row md:items-center justify-between gap-2">
                <div>
                  <div className="text-sm font-semibold text-slate-200">{item.name}</div>
                  <div className="text-xs text-slate-400 font-mono mt-0.5 break-all">{item.value}</div>
                </div>
                <div className="text-xs text-slate-500 md:text-right shrink-0">{item.purpose}</div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-sm text-slate-500 italic">No standard security headers were returned by the target server.</div>
        )}
      </div>

      {/* Missing Headers */}
      <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/40 space-y-4">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
          <XCircle className="w-4 h-4 text-rose-400" /> Missing Recommended Headers ({missing.length})
        </h3>
        {missing.length > 0 ? (
          <div className="grid grid-cols-1 gap-3">
            {missing.map((item, i) => {
              const sevBadge = item.severity === 'HIGH' ? 'bg-red-950 text-red-400 border-red-800' : 'bg-amber-950 text-amber-400 border-amber-800';
              return (
                <div key={i} className="p-3 rounded-lg border border-slate-800/80 bg-slate-950/40 flex flex-col md:flex-row md:items-center justify-between gap-2">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-slate-200">{item.name}</span>
                      <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${sevBadge}`}>
                        {item.severity}
                      </span>
                    </div>
                    <div className="text-xs text-slate-400 mt-1">{item.purpose}</div>
                  </div>
                  <div className="text-xs font-mono text-cyan-400/90 bg-cyan-950/20 px-2.5 py-1 rounded border border-cyan-900/40 md:text-right shrink-0">
                    Recommended: {item.recommended}
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="text-sm text-emerald-400">All recommended security headers are actively enforced!</div>
        )}
      </div>
    </div>
  );
}
