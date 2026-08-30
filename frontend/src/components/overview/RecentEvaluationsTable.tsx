import React from 'react';
import { SessionEvaluationRecord } from '../../types/inference';
import { StatusBadge, SeverityBadge } from '../common/Badge';
import { formatPercent, formatLatency } from '../../utils/formatters';

interface RecentEvaluationsTableProps {
  evaluations: SessionEvaluationRecord[];
}

export const RecentEvaluationsTable: React.FC<RecentEvaluationsTableProps> = ({ evaluations }) => {
  const recent = evaluations.slice(0, 10);

  if (recent.length === 0) {
    return (
      <div className="p-8 text-center text-slate-500 text-xs bg-slate-950/40 rounded-xl border border-slate-800">
        No evaluation activity recorded in current session. Run Single-Flow or Batch analysis to inspect telemetry live.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/90 shadow-md">
      <table className="w-full text-left text-xs text-slate-300">
        <thead className="bg-slate-950/80 text-[11px] uppercase tracking-wider text-slate-400 border-b border-slate-800">
          <tr>
            <th className="px-4 py-3 font-semibold">Timestamp</th>
            <th className="px-4 py-3 font-semibold">Triage Status</th>
            <th className="px-4 py-3 font-semibold">Predicted Class</th>
            <th className="px-4 py-3 font-semibold">Confidence</th>
            <th className="px-4 py-3 font-semibold">Anomaly Score</th>
            <th className="px-4 py-3 font-semibold">Risk Score</th>
            <th className="px-4 py-3 font-semibold">Latency</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/60 font-mono">
          {recent.map((record) => {
            const isAttack = record.decision.status === 'KNOWN_ATTACK';
            return (
              <tr key={record.id} className="hover:bg-slate-800/40 transition-colors">
                <td className="px-4 py-2.5 text-slate-400 font-sans">
                  {new Date(record.timestamp).toLocaleTimeString()}
                </td>
                <td className="px-4 py-2.5 font-sans">
                  <StatusBadge status={record.decision.status} size="sm" />
                </td>
                <td className="px-4 py-2.5 font-sans">
                  <span className={`font-bold ${isAttack ? 'text-red-300' : 'text-slate-200'}`}>
                    {record.prediction.predicted_family}
                  </span>
                </td>
                <td className="px-4 py-2.5">{formatPercent(record.prediction.class_confidence)}</td>
                <td className="px-4 py-2.5 text-purple-300">{record.prediction.normalized_anomaly_score.toFixed(4)}</td>
                <td className="px-4 py-2.5">
                  <span className={`font-bold ${record.decision.risk_score >= 60 ? 'text-red-400' : 'text-slate-300'}`}>
                    {record.decision.risk_score} / 100
                  </span>
                </td>
                <td className="px-4 py-2.5 text-slate-400">{formatLatency(record.prediction.inference_latency_ms)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};
