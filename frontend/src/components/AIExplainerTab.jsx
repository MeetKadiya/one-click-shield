import React from 'react';
import { HelpCircle, AlertTriangle, ShieldCheck, Zap, BookOpen, ExternalLink } from 'lucide-react';

export default function AIExplainerTab({ issues, scoreData }) {
  const allIssues = issues || [];

  const explanations = [
    {
      topic: "Why does my website look fine in Chrome, but gets a low security score?",
      content: "Modern web browsers are designed to load websites whenever possible. They only show big red warning screens when something is catastrophically broken (like an expired certificate or total hostname mismatch). However, they silently allow missing security headers, unflagged cookies, and weak cryptographic handshakes. This creates a false sense of security for non-specialists."
    },
    {
      topic: "What is an Incomplete Certificate Chain?",
      content: "When a server presents an SSL certificate, it must also provide the 'intermediate certificates' that connect your site certificate back to a trusted root authority. Desktop browsers often cache intermediate certificates from other sites, so your site works for you. But mobile devices, curl, and automated API callers will reject the connection because they do not have that intermediate certificate cached."
    },
    {
      topic: "Why are HttpOnly and Secure cookie flags critical?",
      content: "Without 'HttpOnly', any JavaScript running on your page (even from an analytics widget or advertising tag) can read your login tokens using document.cookie. Without 'Secure', browsers will send the cookie in unencrypted plaintext if a user ever clicks an 'http://' link or connects on public airport Wi-Fi."
    },
    {
      topic: "What are Header Contradictions?",
      content: "Many site owners copy configuration lines from multiple tutorials. For instance, setting 'X-Frame-Options: DENY' while also setting Content-Security-Policy 'frame-ancestors self'. Different browsers follow different priority rules, leading to unpredictable security postures across devices."
    },
    {
      topic: "Why is 'X-XSS-Protection: 1; mode=block' deprecated?",
      content: "Legacy browsers (older Internet Explorer, Safari, and Chrome) included an auditor intended to block reflected XSS. Security researchers found that this auditor had design flaws that actually introduced new cross-site leaks. Security authorities now universally advise omitting it or setting it to '0', and using Content-Security-Policy (CSP) instead."
    }
  ];

  return (
    <div className="space-y-6">
      {/* Overview Card */}
      <div className="p-6 rounded-2xl border border-indigo-500/30 bg-gradient-to-r from-indigo-950/40 via-slate-900 to-cyan-950/30">
        <div className="flex items-center gap-2 text-indigo-400 font-bold uppercase tracking-wider text-xs">
          <BookOpen className="w-4 h-4" /> Plain-English Security Advisor
        </div>
        <h2 className="text-xl font-bold text-slate-100 mt-1">
          Demystifying Web Security Configurations for Non-Specialists
        </h2>
        <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
          Site owners frequently discover configuration weaknesses only after user complaints or security incidents. This guide explains exactly why these issues happen, how attackers exploit them, and how One-Click Shield resolves them.
        </p>
      </div>

      {/* Target-Specific Findings in Plain English */}
      <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/40 space-y-4">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
          <Zap className="w-4 h-4 text-amber-400" /> Key Takeaways for Your Scanned Domain
        </h3>

        {allIssues.length > 0 ? (
          <div className="space-y-3">
            {allIssues.slice(0, 5).map((iss, i) => (
              <div key={i} className="p-3.5 rounded-lg border border-slate-800 bg-slate-950 flex flex-col md:flex-row gap-3">
                <div className="shrink-0">
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${
                    iss.severity === 'CRITICAL' ? 'bg-red-950 text-red-400 border-red-800' :
                    iss.severity === 'HIGH' ? 'bg-orange-950 text-orange-400 border-orange-800' :
                    'bg-amber-950 text-amber-400 border-amber-800'
                  }`}>
                    {iss.severity}
                  </span>
                </div>
                <div>
                  <div className="text-sm font-semibold text-slate-200">{iss.title}</div>
                  <div className="text-xs text-slate-400 mt-1">{iss.description}</div>
                  <div className="text-xs text-cyan-400/90 font-medium mt-1">
                    <span className="font-semibold text-cyan-300">Why it matters: </span>
                    {iss.impact}
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-sm text-emerald-400">
            No critical configuration flaws found. Your server demonstrates top-tier security standards.
          </div>
        )}
      </div>

      {/* Core Concept Explainers */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {explanations.map((exp, idx) => (
          <div key={idx} className="p-5 rounded-xl border border-slate-800 bg-slate-900/30 space-y-2">
            <h4 className="text-sm font-semibold text-cyan-300 flex items-start gap-2">
              <HelpCircle className="w-4 h-4 shrink-0 mt-0.5 text-cyan-400" />
              {exp.topic}
            </h4>
            <p className="text-xs text-slate-400 leading-relaxed pl-6">
              {exp.content}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}
