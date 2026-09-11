import React, { useState, useEffect } from 'react';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Search,
  Lock,
  FileCode,
  Cookie,
  Radio,
  Sparkles,
  BookOpen,
  FileText,
  AlertTriangle,
  History,
  CheckCircle2,
  ExternalLink,
  ChevronRight,
  RefreshCw,
  Zap,
  Globe
} from 'lucide-react';
import confetti from 'canvas-confetti';

import SSLTab from './components/SSLTab';
import HeadersTab from './components/HeadersTab';
import CookiesTab from './components/CookiesTab';
import EdgeCasesTab from './components/EdgeCasesTab';
import RemediationTab from './components/RemediationTab';
import AIExplainerTab from './components/AIExplainerTab';
import BrowserMatrixTab from './components/BrowserMatrixTab';
import AuditReportModal from './components/AuditReportModal';

export default function App() {
  const [target, setTarget] = useState('vulnerable-demo.site');
  const [activeTab, setActiveTab] = useState('remediation');
  const [isScanning, setIsScanning] = useState(false);
  const [scanStep, setScanStep] = useState(0);
  const [scanData, setScanData] = useState(null);
  const [errorMsg, setErrorMsg] = useState(null);
  const [isReportOpen, setIsReportOpen] = useState(false);
  const [recentScans, setRecentScans] = useState([]);

  // Scan steps for animated progress
  const scanSteps = [
    "Establishing TLS Handshake & Extracting Certificate Chain...",
    "Probing SSLv3 / TLS 1.0 / 1.1 / 1.2 / 1.3 & Ciphers...",
    "Auditing Security Headers & Detecting Contradictions...",
    "Inspecting Cookies for HttpOnly, Secure & SameSite Flags...",
    "Tracing HTTP-to-HTTPS Redirect Chains & Scraping DOM Assets...",
    "Querying DNS CAA & Generating One-Click Remediation Bundle..."
  ];

  const runScan = async (domainToScan, scenario = null) => {
    const domain = (domainToScan || target).trim();
    if (!domain) return;

    setIsScanning(true);
    setErrorMsg(null);
    setScanStep(0);

    // Step animation interval
    const stepInterval = setInterval(() => {
      setScanStep(prev => (prev < scanSteps.length - 1 ? prev + 1 : prev));
    }, 400);

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: domain,
          scenario: scenario || (domain.includes('vulnerable') ? 'demo-vulnerable' : (domain.includes('secure') ? 'demo-secure' : null))
        })
      });

      if (!response.ok) {
        throw new Error(`Scan failed with status ${response.status}`);
      }

      const data = await response.json();
      setScanData(data);

      if (data.score?.overall_score >= 85) {
        try {
          confetti({ particleCount: 60, spread: 60 });
        } catch (e) {}
      }

      // Refresh recent scans
      fetchHistory();
    } catch (err) {
      console.error(err);
      setErrorMsg(`Failed to scan '${domain}'. Check if the domain exists or try a demo scenario.`);
    } finally {
      clearInterval(stepInterval);
      setIsScanning(false);
    }
  };

  const fetchHistory = async () => {
    try {
      const res = await fetch('/api/history');
      if (res.ok) {
        const d = await res.json();
        setRecentScans(d.history || []);
      }
    } catch (e) {}
  };

  // Initial demo scan on mount
  useEffect(() => {
    runScan('vulnerable-demo.site', 'demo-vulnerable');
  }, []);

  const score = scanData?.score || {};
  const severities = score.severity_counts || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 flex flex-col font-['Inter',sans-serif]">
      {/* Top Header */}
      <header className="border-b border-slate-800/80 bg-slate-950/70 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 to-blue-500 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-extrabold text-base tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-cyan-400 to-blue-400">
                  ONE-CLICK SHIELD
                </span>
                <span className="text-[10px] uppercase tracking-wider font-semibold px-2 py-0.5 rounded-full bg-cyan-950/80 text-cyan-300 border border-cyan-800">
                  v2.0 Hackathon
                </span>
              </div>
              <p className="text-[11px] text-slate-400 hidden sm:block">
                Unified Web Security Scanner & Auto-Remediator (Problem P18)
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => setIsReportOpen(true)}
              disabled={!scanData}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 text-xs font-semibold text-slate-200 transition-all disabled:opacity-50 cursor-pointer"
            >
              <FileText className="w-3.5 h-3.5 text-cyan-400" />
              <span>Audit Report</span>
            </button>

            <a
              href="https://github.com"
              target="_blank"
              rel="noreferrer"
              className="text-xs text-slate-400 hover:text-slate-200 hidden md:inline-flex items-center gap-1"
            >
              <span>CLI:</span> <code className="text-cyan-400 font-mono">python shield.py</code>
            </a>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 py-8 space-y-6">
        {/* Scanner Search Box & Demo Presets */}
        <div className="p-6 rounded-2xl border border-slate-800 bg-slate-900/60 backdrop-blur-sm shadow-xl space-y-4">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              runScan();
            }}
            className="flex flex-col sm:flex-row gap-3"
          >
            <div className="relative flex-1">
              <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="Enter domain or URL (e.g., example.com, badssl.com)"
                className="w-full pl-11 pr-4 py-3 bg-slate-950/80 border border-slate-700/80 rounded-xl text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all font-mono"
              />
            </div>
            <button
              type="submit"
              disabled={isScanning}
              className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-sm shadow-lg shadow-cyan-500/20 transition-all active:scale-95 disabled:opacity-50 cursor-pointer"
            >
              {isScanning ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Scanning Target...</span>
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4" />
                  <span>Scan Domain</span>
                </>
              )}
            </button>
          </form>

          {/* Quick Demo Target Chips */}
          <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
            <span className="font-semibold text-slate-300">Quick Test Targets:</span>
            <button
              onClick={() => {
                setTarget('vulnerable-demo.site');
                runScan('vulnerable-demo.site', 'demo-vulnerable');
              }}
              className="px-2.5 py-1 rounded-md bg-red-950/40 text-red-300 border border-red-800/60 hover:bg-red-900/40 transition-all font-mono cursor-pointer"
            >
              ⚠️ Vulnerable Demo (P18 Showcase)
            </button>
            <button
              onClick={() => {
                setTarget('hardened-example.org');
                runScan('hardened-example.org', 'demo-secure');
              }}
              className="px-2.5 py-1 rounded-md bg-emerald-950/40 text-emerald-300 border border-emerald-800/60 hover:bg-emerald-900/40 transition-all font-mono cursor-pointer"
            >
              🛡️ Hardened Fortress (Grade A+)
            </button>
            <button
              onClick={() => {
                setTarget('github.com');
                runScan('github.com');
              }}
              className="px-2.5 py-1 rounded-md bg-slate-800 text-slate-300 border border-slate-700 hover:bg-slate-700 transition-all font-mono cursor-pointer"
            >
              🌐 github.com
            </button>
            <button
              onClick={() => {
                setTarget('cloudflare.com');
                runScan('cloudflare.com');
              }}
              className="px-2.5 py-1 rounded-md bg-slate-800 text-slate-300 border border-slate-700 hover:bg-slate-700 transition-all font-mono cursor-pointer"
            >
              🌐 cloudflare.com
            </button>
          </div>

          {/* Scanning Progress Bar */}
          {isScanning && (
            <div className="pt-2 space-y-2">
              <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-300"
                  style={{ width: `${((scanStep + 1) / scanSteps.length) * 100}%` }}
                />
              </div>
              <div className="text-xs text-cyan-400 font-mono flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
                <span>{scanSteps[scanStep]}</span>
              </div>
            </div>
          )}

          {errorMsg && (
            <div className="p-3 rounded-lg bg-red-950/40 border border-red-800/60 text-xs text-red-300">
              {errorMsg}
            </div>
          )}
        </div>

        {/* Scan Results Hero Card */}
        {scanData && (
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
            {/* Grade & Score Card */}
            <div className="p-6 rounded-2xl border border-slate-800 bg-slate-900/50 flex flex-col justify-between">
              <div>
                <div className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Security Posture Grade</div>
                <div className="flex items-center gap-4 mt-2">
                  <div
                    className="w-16 h-16 rounded-2xl flex items-center justify-center font-black text-3xl text-slate-950 shadow-xl"
                    style={{ backgroundColor: score.posture_color || '#10b981' }}
                  >
                    {score.grade}
                  </div>
                  <div>
                    <div className="text-2xl font-black text-slate-100">{score.overall_score}<span className="text-xs text-slate-500 font-normal">/100</span></div>
                    <div className="text-xs font-semibold mt-0.5" style={{ color: score.posture_color }}>
                      {score.posture_status}
                    </div>
                  </div>
                </div>
              </div>

              <div className="pt-4 border-t border-slate-800 text-[11px] text-slate-400 font-mono">
                Target: <span className="text-cyan-400 font-semibold">{scanData.target}</span>
              </div>
            </div>

            {/* Severity Breakdown Badges */}
            <div className="lg:col-span-3 p-6 rounded-2xl border border-slate-800 bg-slate-900/50 flex flex-col justify-between">
              <div>
                <div className="text-xs text-slate-400 uppercase tracking-wider font-semibold mb-3">
                  Detected Vulnerability Severity Breakdown
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className="p-3 rounded-xl border border-red-500/30 bg-red-950/20">
                    <div className="text-xs text-red-400 font-semibold uppercase">Critical</div>
                    <div className="text-2xl font-bold text-red-300 mt-1">{severities.CRITICAL}</div>
                    <div className="text-[10px] text-red-400/70 mt-0.5">Immediate threat</div>
                  </div>
                  <div className="p-3 rounded-xl border border-orange-500/30 bg-orange-950/20">
                    <div className="text-xs text-orange-400 font-semibold uppercase">High</div>
                    <div className="text-2xl font-bold text-orange-300 mt-1">{severities.HIGH}</div>
                    <div className="text-[10px] text-orange-400/70 mt-0.5">Severe flaw</div>
                  </div>
                  <div className="p-3 rounded-xl border border-amber-500/30 bg-amber-950/20">
                    <div className="text-xs text-amber-400 font-semibold uppercase">Medium</div>
                    <div className="text-2xl font-bold text-amber-300 mt-1">{severities.MEDIUM}</div>
                    <div className="text-[10px] text-amber-400/70 mt-0.5">Defensive gap</div>
                  </div>
                  <div className="p-3 rounded-xl border border-blue-500/30 bg-blue-950/20">
                    <div className="text-xs text-blue-400 font-semibold uppercase">Low / Info</div>
                    <div className="text-2xl font-bold text-blue-300 mt-1">{severities.LOW + severities.INFO}</div>
                    <div className="text-[10px] text-blue-400/70 mt-0.5">Best practice</div>
                  </div>
                </div>
              </div>

              <div className="mt-4 text-xs text-slate-300 bg-slate-950/60 p-3 rounded-xl border border-slate-800">
                {score.executive_summary}
              </div>
            </div>
          </div>
        )}

        {/* Tab Navigation */}
        {scanData && (
          <div className="space-y-4">
            <div className="flex flex-wrap gap-2 border-b border-slate-800/80 pb-3">
              {[
                { id: 'remediation', label: 'One-Click Auto-Remediator', icon: Sparkles, highlight: true },
                { id: 'browsers', label: 'Multi-Browser Matrix (Brave, Tor, Yandex)', icon: Globe },
                { id: 'ssl', label: 'SSL / TLS & Protocols', icon: Lock },
                { id: 'headers', label: 'Security Headers', icon: FileCode },
                { id: 'cookies', label: 'Cookies & Session', icon: Cookie },
                { id: 'edge', label: 'Edge Cases & DNS', icon: Radio },
                { id: 'ai', label: 'Plain-English Explainer', icon: BookOpen },
              ].map(tab => {
                const Icon = tab.icon;
                const isActive = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold transition-all cursor-pointer ${
                      isActive
                        ? tab.highlight
                          ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 shadow-md shadow-cyan-500/20'
                          : 'bg-slate-800 text-cyan-300 border border-cyan-500/40 shadow-sm'
                        : 'bg-slate-900/70 text-slate-400 border border-slate-800 hover:text-slate-200 hover:bg-slate-800/40'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                    {tab.label}
                  </button>
                );
              })}
            </div>

            {/* Active Tab Panel */}
            <div className="transition-all duration-200">
              {activeTab === 'remediation' && (
                <RemediationTab domain={scanData.target} remediations={scanData.remediations} />
              )}
              {activeTab === 'browsers' && (
                <BrowserMatrixTab matrixData={scanData.browser_matrix} domain={scanData.target} />
              )}
              {activeTab === 'ssl' && (
                <SSLTab sslData={scanData.ssl} />
              )}
              {activeTab === 'headers' && (
                <HeadersTab headersData={scanData.headers} />
              )}
              {activeTab === 'cookies' && (
                <CookiesTab cookiesData={scanData.cookies} />
              )}
              {activeTab === 'edge' && (
                <EdgeCasesTab edgeCasesData={scanData.edge_cases} />
              )}
              {activeTab === 'ai' && (
                <AIExplainerTab issues={score.all_issues} scoreData={score} />
              )}
            </div>
          </div>
        )}
      </main>

      {/* Audit Report Modal */}
      <AuditReportModal
        isOpen={isReportOpen}
        onClose={() => setIsReportOpen(false)}
        scanData={scanData}
      />

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 py-6 mt-12 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>One-Click Shield • Kalpvruksh 2.0 Mini Hackathon 2026 (Problem P18)</span>
          <span className="text-slate-400 font-mono">Defending Small Organizations & Independent Web Deployments</span>
        </div>
      </footer>
    </div>
  );
}
