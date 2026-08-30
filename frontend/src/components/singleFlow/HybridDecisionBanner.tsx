import React from 'react';
import { ShieldAlert, ShieldCheck, AlertTriangle, ArrowRight } from 'lucide-react';
import { DecisionPreviewResponse } from '../../types/inference';
import { StatusBadge, SeverityBadge } from '../common/Badge';

interface HybridDecisionBannerProps {
  decision: DecisionPreviewResponse;
}

export const HybridDecisionBanner: React.FC<HybridDecisionBannerProps> = ({ decision }) => {
  const isAttack = decision.status === 'KNOWN_ATTACK';
  const isAnomaly = decision.status === 'UNKNOWN_ANOMALY';

  const borderColor = isAttack
    ? 'border-red-600/70 bg-gradient-to-r from-red-950/90 via-slate-900 to-slate-900'
    : isAnomaly
    ? 'border-amber-600/70 bg-gradient-to-r from-amber-950/80 via-slate-900 to-slate-900'
    : 'border-emerald-600/70 bg-gradient-to-r from-emerald-950/70 via-slate-900 to-slate-900';

  return (
    <div className={`rounded-2xl border-2 p-5 shadow-2xl transition-all ${borderColor}`}>
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-400">
              Authoritative Triage Verdict
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
              Policy: {decision.policy_version}
            </span>
          </div>
          <div className="flex items-center gap-3">
            <StatusBadge status={decision.status} size="md" />
            <SeverityBadge severity={decision.severity} size="md" />
          </div>
        </div>

        {/* Risk Score Pill */}
        <div className="flex items-center gap-3 bg-slate-950/80 border border-slate-800 px-4 py-2 rounded-xl">
          <div className="text-right">
            <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Risk Score</div>
            <div className="text-2xl font-black font-mono text-slate-100">{decision.risk_score} / 100</div>
          </div>
          <div className={`w-3.5 h-10 rounded-full ${
            decision.risk_score >= 75 ? 'bg-red-500' : decision.risk_score >= 45 ? 'bg-amber-500' : 'bg-emerald-500'
          }`} />
        </div>
      </div>

      {/* Explanation */}
      <div className="mt-3 text-xs leading-relaxed text-slate-300">
        <strong className="text-slate-100">Analysis Explanation: </strong>
        {decision.explanation}
      </div>
    </div>
  );
};
