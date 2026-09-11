import React, { useState } from 'react';
import { Globe, Shield, AlertTriangle, XCircle, CheckCircle2, Info, ExternalLink, Lock } from 'lucide-react';

export default function BrowserMatrixTab({ matrixData, domain }) {
  const [selectedBrowserKey, setSelectedBrowserKey] = useState('tor');

  if (!matrixData || !matrixData.browsers) {
    return (
      <div className="p-8 text-center text-slate-400 bg-slate-900/40 rounded-2xl border border-slate-800">
        No browser matrix data available for this target. Run a scan to evaluate multi-browser compatibility.
      </div>
    );
  }

  const browsers = matrixData.browsers;
  const currentBrowser = browsers[selectedBrowserKey] || browsers['tor'] || Object.values(browsers)[0];

  const getStatusBadge = (status) => {
    switch (status) {
      case 'SHIELDED':
        return {
          bg: 'bg-emerald-950/60 border-emerald-500/40 text-emerald-400',
          icon: CheckCircle2,
          text: 'Shielded / Compatible'
        };
      case 'WARNINGS_PRESENT':
        return {
          bg: 'bg-amber-950/60 border-amber-500/40 text-amber-400',
          icon: AlertTriangle,
          text: 'Warnings / Gaps'
        };
      case 'BLOCKED_RISK':
      case 'CRITICAL_RISK':
      default:
        return {
          bg: 'bg-red-950/60 border-red-500/40 text-red-400',
          icon: XCircle,
          text: 'Interception / Block Risk'
        };
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="p-5 rounded-2xl bg-gradient-to-r from-slate-900 via-indigo-950/30 to-slate-900 border border-indigo-900/40 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xl">🌐</span>
            <h3 className="text-base font-bold text-slate-100">
              Multi-Browser Security & Compatibility Matrix
            </h3>
            <span className="text-[10px] uppercase tracking-wider font-semibold px-2 py-0.5 rounded-full bg-indigo-900/80 text-indigo-300 border border-indigo-700">
              Cross-Engine Analysis
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-3xl">
            Evaluates how <span className="text-cyan-400 font-semibold">{domain}</span> is handled across distinct browser security engines (Tor anonymity circuits, Brave Shields, Yandex Protect, Chrome CT & HSTS, Firefox dCookie, and Safari 398-day limits).
          </p>
        </div>

        <div className="flex items-center gap-3 bg-slate-950/80 px-4 py-2.5 rounded-xl border border-slate-800 shrink-0">
          <div>
            <div className="text-[10px] uppercase font-semibold text-slate-400">Average Defense Score</div>
            <div className="text-xl font-extrabold text-cyan-400">
              {matrixData.overall_browser_score}<span className="text-xs text-slate-500 font-normal">/100</span>
            </div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-indigo-950/60 border border-indigo-800/60 flex items-center justify-center text-lg">
            🛡️
          </div>
        </div>
      </div>

      {/* Browser Selector Cards Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {Object.entries(browsers).map(([key, b]) => {
          const isSelected = selectedBrowserKey === key;
          const statusInfo = getStatusBadge(b.status);
          const StatusIcon = statusInfo.icon;

          return (
            <button
              key={key}
              onClick={() => setSelectedBrowserKey(key)}
              className={`p-4 rounded-xl border text-left transition-all cursor-pointer relative overflow-hidden flex flex-col justify-between ${
                isSelected
                  ? 'bg-slate-800/90 border-cyan-500/70 shadow-lg shadow-cyan-950/40 ring-1 ring-cyan-500/30'
                  : 'bg-slate-900/50 border-slate-800 hover:border-slate-700 hover:bg-slate-800/40'
              }`}
            >
              <div>
                <div className="flex items-center justify-between">
                  <span className="text-2xl">{b.icon}</span>
                  <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${statusInfo.bg}`}>
                    {b.score}%
                  </span>
                </div>
                <div className="font-bold text-sm text-slate-200 mt-2">{b.name}</div>
                <div className="text-[10px] text-slate-400 truncate">{b.engine}</div>
              </div>

              <div className="mt-3 pt-2 border-t border-slate-800/80 flex items-center gap-1 text-[10px]">
                <StatusIcon className="w-3 h-3 shrink-0" />
                <span className="truncate">{statusInfo.text.split('/')[0]}</span>
              </div>
            </button>
          );
        })}
      </div>

      {/* Selected Browser Deep Dive Card */}
      {currentBrowser && (
        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-6 shadow-xl">
          {/* Header */}
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-5 border-b border-slate-800">
            <div className="flex items-center gap-3">
              <span className="text-3xl">{currentBrowser.icon}</span>
              <div>
                <div className="flex items-center gap-2">
                  <h4 className="text-lg font-bold text-slate-100">{currentBrowser.name}</h4>
                  <span className="text-xs px-2.5 py-0.5 rounded-full bg-slate-800 border border-slate-700 text-slate-300 font-mono">
                    {currentBrowser.engine}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  <span className="font-semibold text-slate-300">Browser Threat Model:</span> {currentBrowser.threat_model}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <div className="text-right">
                <div className="text-[10px] uppercase font-semibold text-slate-400">Compatibility Rating</div>
                <div className="text-xl font-bold text-slate-100">
                  {currentBrowser.score}<span className="text-xs text-slate-500 font-normal">/100</span>
                </div>
              </div>
              <div className={`px-3 py-1.5 rounded-xl border text-xs font-semibold flex items-center gap-1.5 ${getStatusBadge(currentBrowser.status).bg}`}>
                {React.createElement(getStatusBadge(currentBrowser.status).icon, { className: 'w-4 h-4' })}
                <span>{getStatusBadge(currentBrowser.status).text}</span>
              </div>
            </div>
          </div>

          {/* Verdict Banner */}
          <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 text-xs flex items-center justify-between gap-3">
            <div className="flex items-center gap-2 text-slate-300">
              <Info className="w-4 h-4 text-cyan-400 shrink-0" />
              <span>
                <strong className="text-slate-100">Browser Verdict:</strong> {currentBrowser.verdict}
              </span>
            </div>
          </div>

          {/* Detailed Findings & Impact Pointers */}
          <div>
            <h5 className="text-xs uppercase tracking-wider font-bold text-slate-400 mb-3 flex items-center gap-2">
              <Shield className="w-3.5 h-3.5 text-indigo-400" />
              <span>Specific Engine Enforcement & Security Findings ({currentBrowser.findings.length})</span>
            </h5>

            <div className="space-y-3">
              {currentBrowser.findings.map((finding, idx) => {
                const isCrit = finding.type === 'CRITICAL';
                const isWarn = finding.type === 'WARNING';
                const isPass = finding.type === 'PASS' || finding.type === 'EXCELLENT';

                const borderBg = isCrit
                  ? 'border-red-500/30 bg-red-950/20 text-red-300'
                  : isWarn
                  ? 'border-amber-500/30 bg-amber-950/20 text-amber-300'
                  : isPass
                  ? 'border-emerald-500/30 bg-emerald-950/20 text-emerald-300'
                  : 'border-slate-800 bg-slate-950/40 text-slate-300';

                const icon = isCrit
                  ? <XCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                  : isWarn
                  ? <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  : isPass
                  ? <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  : <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />;

                return (
                  <div key={idx} className={`p-3.5 rounded-xl border ${borderBg} flex items-start gap-3`}>
                    {icon}
                    <div className="flex-1">
                      <div className="text-xs font-bold">{finding.title}</div>
                      <div className="text-[11px] text-slate-400 mt-0.5 leading-relaxed">{finding.desc}</div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
