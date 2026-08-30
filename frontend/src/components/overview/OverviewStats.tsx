import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, Activity, Zap } from 'lucide-react';
import { SessionEvaluationRecord } from '../../types/inference';
import { MetricCard } from '../common/MetricCard';
import { formatNumber } from '../../utils/formatters';

interface OverviewStatsProps {
  evaluations: SessionEvaluationRecord[];
}

export const OverviewStats: React.FC<OverviewStatsProps> = ({ evaluations }) => {
  const total = evaluations.length;
  const attacks = evaluations.filter((e) => e.decision.status === 'KNOWN_ATTACK').length;
  const anomalies = evaluations.filter((e) => e.decision.status === 'UNKNOWN_ANOMALY').length;
  const normal = evaluations.filter((e) => e.decision.status === 'NORMAL').length;

  const avgRisk =
    total > 0
      ? (evaluations.reduce((acc, curr) => acc + curr.decision.risk_score, 0) / total).toFixed(1)
      : '0';

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
      <MetricCard
        label="Total Evaluated Flows"
        value={formatNumber(total)}
        subtext="Session Telemetry Buffer"
        icon={<Activity className="w-5 h-5" />}
        accent="blue"
      />
      <MetricCard
        label="Normal / Benign"
        value={formatNumber(normal)}
        subtext={total > 0 ? `${((normal / total) * 100).toFixed(1)}% of volume` : '0%'}
        icon={<ShieldCheck className="w-5 h-5" />}
        accent="emerald"
      />
      <MetricCard
        label="Unknown Anomalies"
        value={formatNumber(anomalies)}
        subtext={total > 0 ? `${((anomalies / total) * 100).toFixed(1)}% elevated` : '0%'}
        icon={<AlertTriangle className="w-5 h-5" />}
        accent="amber"
      />
      <MetricCard
        label="Confirmed Attacks"
        value={formatNumber(attacks)}
        subtext={total > 0 ? `${((attacks / total) * 100).toFixed(1)}% high risk` : '0%'}
        icon={<ShieldAlert className="w-5 h-5" />}
        accent={attacks > 0 ? 'red' : 'emerald'}
      />
      <MetricCard
        label="Average Risk Score"
        value={`${avgRisk} / 100`}
        subtext="Weighted hybrid triage score"
        icon={<Zap className="w-5 h-5" />}
        accent={parseFloat(avgRisk) >= 60 ? 'red' : parseFloat(avgRisk) >= 30 ? 'amber' : 'emerald'}
      />
    </div>
  );
};
