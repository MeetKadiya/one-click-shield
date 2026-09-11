import React from 'react';
import { Cookie, Check, X, AlertOctagon, ShieldAlert, Key } from 'lucide-react';

export default function CookiesTab({ cookiesData }) {
  if (!cookiesData) return null;

  const cookies = cookiesData.cookies || [];
  const total = cookiesData.total_cookies || 0;
  const missingHttpOnly = cookiesData.missing_httponly_count || 0;
  const missingSecure = cookiesData.missing_secure_count || 0;
  const missingSameSite = cookiesData.missing_samesite_count || 0;

  return (
    <div className="space-y-6">
      {/* Stat Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40">
          <div className="text-xs text-slate-400 uppercase font-semibold">Total Cookies Set</div>
          <div className="text-2xl font-bold text-slate-100 mt-1">{total}</div>
        </div>
        <div className={`p-4 rounded-xl border ${missingHttpOnly > 0 ? 'border-amber-500/30 bg-amber-950/20' : 'border-slate-800 bg-slate-900/40'}`}>
          <div className="text-xs text-slate-400 uppercase font-semibold">Missing HttpOnly</div>
          <div className={`text-2xl font-bold mt-1 ${missingHttpOnly > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
            {missingHttpOnly}
          </div>
        </div>
        <div className={`p-4 rounded-xl border ${missingSecure > 0 ? 'border-red-500/30 bg-red-950/20' : 'border-slate-800 bg-slate-900/40'}`}>
          <div className="text-xs text-slate-400 uppercase font-semibold">Missing Secure</div>
          <div className={`text-2xl font-bold mt-1 ${missingSecure > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
            {missingSecure}
          </div>
        </div>
        <div className={`p-4 rounded-xl border ${missingSameSite > 0 ? 'border-amber-500/30 bg-amber-950/20' : 'border-slate-800 bg-slate-900/40'}`}>
          <div className="text-xs text-slate-400 uppercase font-semibold">Missing SameSite</div>
          <div className={`text-2xl font-bold mt-1 ${missingSameSite > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
            {missingSameSite}
          </div>
        </div>
      </div>

      {/* Cookies Table */}
      <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/40 space-y-4">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
          <Cookie className="w-4 h-4 text-amber-400" /> Cookie Attributes & Session Security
        </h3>

        {cookies.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase tracking-wider">
                  <th className="pb-3 px-3">Cookie Name</th>
                  <th className="pb-3 px-3 text-center">HttpOnly</th>
                  <th className="pb-3 px-3 text-center">Secure</th>
                  <th className="pb-3 px-3 text-center">SameSite</th>
                  <th className="pb-3 px-3">Domain / Path</th>
                  <th className="pb-3 px-3">Findings</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {cookies.map((c, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/20">
                    <td className="py-3 px-3">
                      <div className="font-mono font-semibold text-slate-200 flex items-center gap-1.5">
                        {c.name}
                        {c.is_session_cookie && (
                          <span className="text-[10px] bg-red-950/80 text-red-400 px-1.5 py-0.5 rounded border border-red-800 flex items-center gap-0.5">
                            <Key className="w-3 h-3"/> Session
                          </span>
                        )}
                        {c.name.startsWith('__Host-') && (
                          <span className="text-[10px] bg-indigo-950 text-indigo-400 px-1.5 py-0.5 rounded border border-indigo-800">
                            __Host- Prefix
                          </span>
                        )}
                        {c.name.startsWith('__Secure-') && (
                          <span className="text-[10px] bg-cyan-950 text-cyan-400 px-1.5 py-0.5 rounded border border-cyan-800">
                            __Secure- Prefix
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] text-slate-500 font-mono mt-0.5 truncate max-w-xs">{c.value}</div>
                    </td>

                    <td className="py-3 px-3 text-center">
                      {c.httponly ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 text-[11px] font-medium">
                          <Check className="w-3 h-3" /> Yes
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-amber-950 text-amber-400 border border-amber-800 text-[11px] font-medium">
                          <X className="w-3 h-3" /> No
                        </span>
                      )}
                    </td>

                    <td className="py-3 px-3 text-center">
                      {c.secure ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 text-[11px] font-medium">
                          <Check className="w-3 h-3" /> Yes
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800 text-[11px] font-medium">
                          <X className="w-3 h-3" /> No
                        </span>
                      )}
                    </td>

                    <td className="py-3 px-3 text-center">
                      {c.samesite ? (
                        <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 font-mono text-[11px]">
                          {c.samesite}
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded bg-amber-950 text-amber-400 border border-amber-800 text-[11px]">
                          None Set
                        </span>
                      )}
                    </td>

                    <td className="py-3 px-3 text-slate-400 font-mono text-[11px]">
                      <div>{c.domain || '(host-only)'}</div>
                      <div>{c.path || '/'}</div>
                    </td>

                    <td className="py-3 px-3">
                      {c.issues && c.issues.length > 0 ? (
                        <div className="space-y-1">
                          {c.issues.map((iss, i) => (
                            <div key={i} className="text-amber-400 text-[11px] flex items-center gap-1">
                              <ShieldAlert className="w-3 h-3 shrink-0 text-amber-500" />
                              <span>{iss.title}</span>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <span className="text-emerald-400 text-[11px] flex items-center gap-1">
                          <Check className="w-3 h-3" /> Hardened
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-sm text-slate-500 italic">No Set-Cookie headers were observed in the response.</div>
        )}
      </div>
    </div>
  );
}
