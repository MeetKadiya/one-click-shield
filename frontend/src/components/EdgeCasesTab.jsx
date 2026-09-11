import React from 'react';
import { ArrowRight, AlertTriangle, Globe, Radio, ShieldCheck, ShieldAlert, CheckCircle2, XCircle } from 'lucide-react';

export default function EdgeCasesTab({ edgeCasesData }) {
  if (!edgeCasesData) return null;

  const redirects = edgeCasesData.redirects || {};
  const mixedContent = edgeCasesData.mixed_content || {};
  const thirdParty = edgeCasesData.third_party_resources || [];
  const subdomains = edgeCasesData.subdomains || [];
  const dns = edgeCasesData.dns_posture || {};
  const issues = edgeCasesData.issues || [];

  return (
    <div className="space-y-6">
      {/* Redirect Chain Visualizer */}
      <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/40 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
            <Radio className="w-4 h-4 text-cyan-400" /> HTTP to HTTPS Redirection Flow
          </h3>
          <span className={`text-xs px-2.5 py-1 rounded font-semibold border ${
            redirects.enforces_https
              ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
              : 'bg-red-950 text-red-400 border-red-800'
          }`}>
            {redirects.enforces_https ? 'HTTPS Enforced' : 'Plaintext HTTP Exposed'}
          </span>
        </div>

        {redirects.chain && redirects.chain.length > 0 ? (
          <div className="flex flex-wrap items-center gap-2 p-3 rounded-lg bg-slate-950 border border-slate-800">
            {redirects.chain.map((hop, index) => (
              <React.Fragment key={index}>
                <div className="p-2.5 rounded-lg border border-slate-800 bg-slate-900/80 text-xs">
                  <div className="flex items-center gap-1.5 font-semibold">
                    <span className={`w-2 h-2 rounded-full ${hop.is_https ? 'bg-emerald-400' : 'bg-amber-400'}`} />
                    <span className="text-slate-200">Hop {hop.hop || index + 1}</span>
                    <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono ${
                      hop.status_code === 301 || hop.status_code === 308 ? 'bg-cyan-950 text-cyan-400 border border-cyan-800' : 'bg-slate-800 text-slate-300'
                    }`}>
                      {hop.status_code}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400 font-mono mt-1 max-w-[200px] truncate" title={hop.url}>
                    {hop.url}
                  </div>
                </div>
                {index < redirects.chain.length - 1 && (
                  <ArrowRight className="w-4 h-4 text-slate-600 shrink-0" />
                )}
              </React.Fragment>
            ))}
          </div>
        ) : (
          <div className="text-sm text-slate-500 italic">No redirect history available.</div>
        )}
      </div>

      {/* Mixed Content & Third-Party Scripts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Mixed Content Status */}
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/40 space-y-3">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" /> Mixed Content Inspection
          </h3>
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className={`p-3 rounded-lg border ${
              mixedContent.active?.length > 0 ? 'border-red-500/40 bg-red-950/20 text-red-300' : 'border-slate-800 bg-slate-950 text-slate-300'
            }`}>
              <div className="font-semibold text-sm">{mixedContent.active?.length || 0} Active Mixed</div>
              <div className="text-[11px] text-slate-400 mt-0.5">HTTP Scripts & Iframes</div>
            </div>
            <div className={`p-3 rounded-lg border ${
              mixedContent.passive?.length > 0 ? 'border-amber-500/40 bg-amber-950/20 text-amber-300' : 'border-slate-800 bg-slate-950 text-slate-300'
            }`}>
              <div className="font-semibold text-sm">{mixedContent.passive?.length || 0} Passive Mixed</div>
              <div className="text-[11px] text-slate-400 mt-0.5">HTTP Images & Media</div>
            </div>
          </div>
          {mixedContent.active?.length > 0 && (
            <div className="text-xs text-red-400 bg-red-950/40 p-2.5 rounded border border-red-900/60 font-mono">
              Active mixed scripts detected. Browsers will automatically block these execution sources.
            </div>
          )}
        </div>

        {/* DNS CAA & DNSSEC */}
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/40 space-y-3">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
            <Globe className="w-4 h-4 text-indigo-400" /> DNS CAA & DNSSEC Posture
          </h3>
          <div className="space-y-2 text-xs">
            <div className="p-3 rounded-lg border border-slate-800 bg-slate-950 flex items-center justify-between">
              <div>
                <div className="font-semibold text-slate-200">DNS CAA (Certificate Authority Authorization)</div>
                <div className="text-[11px] text-slate-400">Restricts which CAs can issue certificates</div>
              </div>
              {dns.has_caa ? (
                <span className="text-emerald-400 font-semibold flex items-center gap-1"><CheckCircle2 className="w-4 h-4"/> Configured</span>
              ) : (
                <span className="text-amber-400 font-semibold flex items-center gap-1"><XCircle className="w-4 h-4"/> Missing</span>
              )}
            </div>
            <div className="p-3 rounded-lg border border-slate-800 bg-slate-950 flex items-center justify-between">
              <div>
                <div className="font-semibold text-slate-200">DNSSEC Authentication</div>
                <div className="text-[11px] text-slate-400">Cryptographically signs DNS responses</div>
              </div>
              {dns.dnssec_enabled ? (
                <span className="text-emerald-400 font-semibold flex items-center gap-1"><CheckCircle2 className="w-4 h-4"/> Enabled</span>
              ) : (
                <span className="text-slate-400 font-semibold flex items-center gap-1">Disabled</span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Third Party Scripts & SRI Table */}
      <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/40 space-y-4">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-cyan-400" /> External Third-Party Assets & Subresource Integrity (SRI)
        </h3>
        {thirdParty.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase tracking-wider">
                  <th className="pb-2.5 px-2">Type</th>
                  <th className="pb-2.5 px-2">Origin</th>
                  <th className="pb-2.5 px-2">Asset URL</th>
                  <th className="pb-2.5 px-2 text-center">SRI Hash Present</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {thirdParty.map((res, i) => (
                  <tr key={i} className="hover:bg-slate-800/20">
                    <td className="py-2.5 px-2 text-slate-300 capitalize">{res.type}</td>
                    <td className="py-2.5 px-2 text-cyan-400 font-semibold">{res.origin}</td>
                    <td className="py-2.5 px-2 text-slate-400 truncate max-w-sm" title={res.url}>{res.url}</td>
                    <td className="py-2.5 px-2 text-center">
                      {res.has_sri ? (
                        <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px]">
                          SRI Protected
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded bg-amber-950 text-amber-400 border border-amber-800 text-[10px]">
                          Missing SRI
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-sm text-slate-500 italic">No external third-party script dependencies detected.</div>
        )}
      </div>
    </div>
  );
}
