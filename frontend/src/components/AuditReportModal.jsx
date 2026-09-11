import React from 'react';
import { X, Printer, Download, ShieldCheck, AlertTriangle } from 'lucide-react';

export default function AuditReportModal({ isOpen, onClose, scanData }) {
  if (!isOpen || !scanData) return null;

  const score = scanData.score || {};
  const issues = score.all_issues || [];

  const handlePrint = () => {
    window.print();
  };

  const handleExportJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(scanData, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `shield-audit-${scanData.target}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="relative w-full max-w-4xl max-h-[90vh] bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl flex flex-col overflow-hidden text-slate-100">
        {/* Header Bar */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold">Executive Web Security Configuration Audit</h2>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleExportJson}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 transition-all cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" /> Export JSON
            </button>
            <button
              onClick={handlePrint}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-xs font-semibold text-white transition-all cursor-pointer"
            >
              <Printer className="w-3.5 h-3.5" /> Print / Save PDF
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-all cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Report Content */}
        <div className="p-6 overflow-y-auto space-y-6 text-slate-200 print:p-0">
          {/* Executive Header */}
          <div className="p-5 rounded-xl border border-slate-800 bg-slate-950/60 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <div className="text-xs text-cyan-400 font-semibold uppercase tracking-wider">Target Domain</div>
              <div className="text-2xl font-bold text-slate-100 mt-0.5">{scanData.target}</div>
              <div className="text-xs text-slate-400 mt-1">
                Scan Audit Date: {new Date(scanData.scan_timestamp).toLocaleString()}
              </div>
            </div>

            <div className="flex items-center gap-4">
              <div className="text-right">
                <div className="text-xs text-slate-400 uppercase font-semibold">Security Score</div>
                <div className="text-xl font-bold text-slate-200">{score.overall_score}/100</div>
              </div>
              <div
                className="w-14 h-14 rounded-2xl flex items-center justify-center font-black text-2xl text-slate-950 shadow-lg"
                style={{ backgroundColor: score.posture_color || '#10b981' }}
              >
                {score.grade}
              </div>
            </div>
          </div>

          {/* Posture Summary */}
          <div className="text-xs text-slate-300 leading-relaxed bg-slate-950 p-4 rounded-xl border border-slate-800">
            <span className="font-semibold text-cyan-300 block mb-1">Audit Findings Overview:</span>
            {score.executive_summary}
          </div>

          {/* Category Table */}
          <div>
            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Category Scores</h4>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {Object.entries(score.category_breakdown || {}).map(([key, cat]) => (
                <div key={key} className="p-3 rounded-lg border border-slate-800 bg-slate-950 text-center">
                  <div className="text-[11px] text-slate-400">{cat.label}</div>
                  <div className="text-lg font-bold text-slate-100 mt-1">{cat.score}/100</div>
                  <div className="text-[10px] text-slate-500">{cat.issues_count} findings</div>
                </div>
              ))}
            </div>
          </div>

          {/* Issues List */}
          <div>
            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
              Itemized Vulnerability Log ({issues.length})
            </h4>
            <div className="space-y-2">
              {issues.map((iss, idx) => (
                <div key={idx} className="p-3 rounded-lg border border-slate-800 bg-slate-950/40 text-xs">
                  <div className="flex items-center justify-between">
                    <div className="font-semibold text-slate-200 flex items-center gap-2">
                      <span className={`text-[10px] font-bold px-1.5 py-0.2 rounded border ${
                        iss.severity === 'CRITICAL' ? 'bg-red-950 text-red-400 border-red-800' :
                        iss.severity === 'HIGH' ? 'bg-orange-950 text-orange-400 border-orange-800' :
                        'bg-amber-950 text-amber-400 border-amber-800'
                      }`}>
                        {iss.severity}
                      </span>
                      {iss.title}
                    </div>
                    <span className="text-[11px] text-slate-500">{iss.category}</span>
                  </div>
                  <div className="text-slate-400 mt-1">{iss.description}</div>
                  <div className="text-cyan-400/80 font-medium mt-1">Impact: {iss.impact}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
