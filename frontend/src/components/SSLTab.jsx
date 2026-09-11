import React from 'react';
import { ShieldCheck, ShieldAlert, Lock, AlertTriangle, Key, CheckCircle2, XCircle, RefreshCw } from 'lucide-react';

export default function SSLTab({ sslData }) {
  if (!sslData) return null;

  const cert = sslData.certificate || {};
  const chain = sslData.chain || [];
  const protocols = sslData.protocols || {};
  const cipher = sslData.cipher || {};
  const issues = sslData.issues || [];

  const daysRemaining = cert.days_remaining ?? 0;
  const isExpired = cert.is_expired;

  let expiryStatusColor = 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30';
  if (isExpired) {
    expiryStatusColor = 'bg-red-500/20 text-red-400 border-red-500/30';
  } else if (daysRemaining < 14) {
    expiryStatusColor = 'bg-red-500/20 text-red-400 border-red-500/30';
  } else if (daysRemaining < 30) {
    expiryStatusColor = 'bg-amber-500/20 text-amber-400 border-amber-500/30';
  }

  return (
    <div className="space-y-6">
      {/* Expiration Banner */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className={`p-4 rounded-xl border ${expiryStatusColor} flex items-center justify-between`}>
          <div>
            <div className="text-xs font-semibold uppercase tracking-wider opacity-80">Validity Status</div>
            <div className="text-xl font-bold mt-1">
              {isExpired ? 'EXPIRED' : (daysRemaining < 30 ? 'Expiring Soon' : 'Valid & Active')}
            </div>
            <div className="text-xs mt-1">
              {daysRemaining >= 0 ? `${daysRemaining} days remaining` : `Expired ${Math.abs(daysRemaining)} days ago`}
            </div>
          </div>
          <Lock className="w-8 h-8 opacity-80" />
        </div>

        <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/60 flex items-center justify-between">
          <div>
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">Hostname / SAN Match</div>
            <div className="text-xl font-bold mt-1 flex items-center gap-1.5">
              {cert.hostname_valid ? (
                <span className="text-emerald-400 flex items-center gap-1"><CheckCircle2 className="w-5 h-5"/> Matches</span>
              ) : (
                <span className="text-red-400 flex items-center gap-1"><XCircle className="w-5 h-5"/> Mismatch</span>
              )}
            </div>
            <div className="text-xs text-slate-400 mt-1 truncate max-w-[200px]" title={cert.san_match_details}>
              {cert.san_match_details || 'Verified'}
            </div>
          </div>
          <Key className="w-8 h-8 text-cyan-400/80" />
        </div>

        <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/60 flex items-center justify-between">
          <div>
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">PFS & OCSP</div>
            <div className="text-xl font-bold mt-1">
              {cipher.pfs_supported ? (
                <span className="text-emerald-400">PFS Supported</span>
              ) : (
                <span className="text-red-400">No Forward Secrecy</span>
              )}
            </div>
            <div className="text-xs text-slate-400 mt-1">
              OCSP Stapled: {sslData.ocsp_stapled ? <span className="text-emerald-400 font-semibold">Yes</span> : <span className="text-amber-400">No</span>}
            </div>
          </div>
          <RefreshCw className="w-8 h-8 text-indigo-400/80" />
        </div>
      </div>

      {/* Protocol Support Matrix */}
      <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/40">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Cryptographic Protocol Support Matrix</h3>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { proto: 'TLSv1.0', label: 'TLS 1.0 (Deprecated)', safe: false },
            { proto: 'TLSv1.1', label: 'TLS 1.1 (Deprecated)', safe: false },
            { proto: 'TLSv1.2', label: 'TLS 1.2 (Standard)', safe: true },
            { proto: 'TLSv1.3', label: 'TLS 1.3 (Modern)', safe: true },
          ].map(({ proto, label, safe }) => {
            const isEnabled = protocols[proto];
            const isVulnerable = !safe && isEnabled;
            return (
              <div
                key={proto}
                className={`p-3 rounded-lg border text-center transition-all ${
                  isVulnerable
                    ? 'border-red-500/50 bg-red-950/20 text-red-300'
                    : isEnabled
                    ? 'border-emerald-500/30 bg-emerald-950/20 text-emerald-300'
                    : 'border-slate-800 bg-slate-900/30 text-slate-500'
                }`}
              >
                <div className="text-xs font-medium">{label}</div>
                <div className="text-base font-bold mt-1 flex items-center justify-center gap-1">
                  {isEnabled ? (
                    isVulnerable ? <><XCircle className="w-4 h-4 text-red-400"/> Enabled (Risky)</> : <><CheckCircle2 className="w-4 h-4 text-emerald-400"/> Supported</>
                  ) : (
                    <span className="text-slate-500">Disabled</span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Certificate Hierarchy & Details */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Chain Hierarchy */}
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/40">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4 flex items-center gap-2">
            <Lock className="w-4 h-4 text-cyan-400" /> Certificate Chain Hierarchy
          </h3>
          <div className="space-y-4">
            {chain.length > 0 ? (
              chain.map((node, idx) => (
                <div key={idx} className="relative pl-6 border-l-2 border-cyan-500/40 space-y-1">
                  <div className="absolute -left-[9px] top-0 w-4 h-4 rounded-full bg-cyan-500/20 border-2 border-cyan-400"></div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/60">
                      {node.level}
                    </span>
                    <span className="font-semibold text-slate-200 text-sm">{node.subject}</span>
                  </div>
                  <div className="text-xs text-slate-400">Issuer: {node.issuer}</div>
                  {node.valid_until && <div className="text-xs text-slate-500">Expires: {node.valid_until}</div>}
                </div>
              ))
            ) : (
              <div className="text-sm text-slate-400">Single leaf certificate detected. Intermediate chain not verified.</div>
            )}
          </div>
        </div>

        {/* Certificate Metadata & SANs */}
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/40 space-y-3 text-sm">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-2 flex items-center gap-2">
            <Key className="w-4 h-4 text-indigo-400" /> Cryptographic Parameters
          </h3>
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="p-2.5 rounded bg-slate-800/40 border border-slate-800">
              <span className="text-slate-400 block">Common Name (CN)</span>
              <span className="font-mono font-medium text-slate-200 truncate block mt-0.5">{cert.common_name || 'N/A'}</span>
            </div>
            <div className="p-2.5 rounded bg-slate-800/40 border border-slate-800">
              <span className="text-slate-400 block">Issuer Authority</span>
              <span className="font-medium text-slate-200 truncate block mt-0.5">{cert.issuer_name || 'N/A'}</span>
            </div>
            <div className="p-2.5 rounded bg-slate-800/40 border border-slate-800">
              <span className="text-slate-400 block">Key Type & Size</span>
              <span className="font-mono font-medium text-slate-200 mt-0.5 block">{cert.key_type} {cert.key_size ? `${cert.key_size} bits` : ''}</span>
            </div>
            <div className="p-2.5 rounded bg-slate-800/40 border border-slate-800">
              <span className="text-slate-400 block">Negotiated Cipher</span>
              <span className="font-mono font-medium text-slate-200 truncate mt-0.5 block" title={cipher.name}>{cipher.name || 'N/A'}</span>
            </div>
          </div>

          <div className="pt-2">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-1.5">
              Subject Alternative Names ({cert.sans?.length || 0})
            </span>
            <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto pr-1">
              {cert.sans && cert.sans.length > 0 ? (
                cert.sans.map((san, i) => (
                  <span key={i} className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                    {san}
                  </span>
                ))
              ) : (
                <span className="text-xs text-slate-500">No SAN entries found.</span>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
