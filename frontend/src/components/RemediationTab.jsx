import React, { useState } from 'react';
import { Download, Copy, Check, Terminal, FileCode, Server, Shield, Sparkles } from 'lucide-react';
import confetti from 'canvas-confetti';

export default function RemediationTab({ domain, remediations }) {
  const [activePlatform, setActivePlatform] = useState('nginx');
  const [copied, setCopied] = useState(false);

  if (!remediations) {
    return (
      <div className="p-8 text-center text-slate-400">
        Run a scan on a domain to generate custom hardened remediation configurations.
      </div>
    );
  }

  const currentRem = remediations[activePlatform] || remediations.nginx;

  const handleCopy = () => {
    if (currentRem?.content) {
      navigator.clipboard.writeText(currentRem.content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    }
  };

  const handleDownloadZip = () => {
    try {
      confetti({
        particleCount: 80,
        spread: 70,
        origin: { y: 0.6 }
      });
    } catch (e) {}

    // Trigger download from backend API
    const downloadUrl = `/api/download-fix-pack?domain=${encodeURIComponent(domain || 'target')}`;
    window.open(downloadUrl, '_blank');
  };

  const platforms = [
    { key: 'nginx', label: 'Nginx Server', icon: Server },
    { key: 'apache', label: 'Apache (.htaccess)', icon: Server },
    { key: 'caddy', label: 'Caddyfile', icon: Server },
    { key: 'cloudflare', label: 'Cloudflare Edge', icon: Shield },
    { key: 'nodejs', label: 'Node.js / Express', icon: FileCode },
    { key: 'docker', label: 'Docker Proxy', icon: Terminal },
    { key: 'readme', label: 'Deployment Guide', icon: Sparkles }
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner with 1-Click Download */}
      <div className="p-6 rounded-2xl border border-cyan-500/30 bg-gradient-to-r from-cyan-950/40 via-slate-900 to-indigo-950/30 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 font-bold uppercase tracking-wider text-xs">
            <Sparkles className="w-4 h-4" /> One-Click Auto-Remediator
          </div>
          <h2 className="text-xl font-bold text-slate-100 mt-1">
            Production Hardening Pack for <span className="text-cyan-300 font-mono">{domain || 'target'}</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-xl">
            Pre-configured to eliminate all detected TLS, header, and cookie weaknesses. Choose your server platform below or download the complete deployment bundle.
          </p>
        </div>

        <button
          onClick={handleDownloadZip}
          className="shrink-0 inline-flex items-center gap-2 px-5 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-sm shadow-lg shadow-cyan-500/20 transition-all active:scale-95 cursor-pointer"
        >
          <Download className="w-4 h-4" />
          Download Fix Bundle (.zip)
        </button>
      </div>

      {/* Platform Selector Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-3">
        {platforms.map(p => {
          const Icon = p.icon;
          const isActive = activePlatform === p.key;
          return (
            <button
              key={p.key}
              onClick={() => setActivePlatform(p.key)}
              className={`inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                isActive
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 shadow-sm'
                  : 'bg-slate-900/60 text-slate-400 border border-slate-800 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              {p.label}
            </button>
          );
        })}
      </div>

      {/* Code Editor / Config Preview */}
      <div className="rounded-xl border border-slate-800 bg-slate-950 overflow-hidden shadow-2xl">
        {/* Code Bar */}
        <div className="flex items-center justify-between px-4 py-2.5 bg-slate-900/80 border-b border-slate-800 text-xs">
          <div className="flex items-center gap-2 font-mono text-slate-300">
            <FileCode className="w-4 h-4 text-cyan-400" />
            <span className="font-semibold text-cyan-300">{currentRem?.filename}</span>
            <span className="text-slate-500">({currentRem?.language})</span>
          </div>

          <button
            onClick={handleCopy}
            className="inline-flex items-center gap-1.5 px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-all active:scale-95 cursor-pointer"
          >
            {copied ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-400">Copied!</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5 text-slate-400" />
                <span>Copy Snippet</span>
              </>
            )}
          </button>
        </div>

        {/* Description */}
        {currentRem?.description && (
          <div className="px-4 py-2 bg-slate-900/40 border-b border-slate-850 text-xs text-slate-400">
            {currentRem.description}
          </div>
        )}

        {/* Preformatted Code */}
        <div className="p-4 max-h-[500px] overflow-y-auto">
          <pre className="font-mono text-xs text-slate-200 leading-relaxed selection:bg-cyan-500 selection:text-black">
            <code>{currentRem?.content}</code>
          </pre>
        </div>
      </div>
    </div>
  );
}
