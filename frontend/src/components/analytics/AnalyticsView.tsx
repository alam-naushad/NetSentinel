import React from 'react';
import { BarChart3, Database, Info, Activity, Clock } from 'lucide-react';
import { useApp } from '../../context/useApp';
import { formatLatency, formatNumber } from '../../utils/formatters';
import { MetricCard } from '../common/MetricCard';
import { LatencyTrendChart } from './LatencyTrendChart';
import { TriageBreakdownChart } from './TriageBreakdownChart';

export const AnalyticsView: React.FC = () => {
  const { sessionEvaluations } = useApp();

  const totalFlows = sessionEvaluations.length;
  const totalLatency = sessionEvaluations.reduce((acc, curr) => acc + curr.prediction.inference_latency_ms, 0);
  const avgLatency = totalFlows > 0 ? totalLatency / totalFlows : 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-black text-slate-100 tracking-tight flex items-center gap-2">
          <BarChart3 className="w-5 h-5 text-blue-400" />
          Session-Level Inference Analytics
        </h2>
        <p className="text-xs text-slate-400 mt-0.5">
          Performance profiling and triage distribution metrics across the active session buffer.
        </p>
      </div>

      {/* Ephemeral Session Notice Banner (Requirement 2) */}
      <div className="p-4 rounded-xl bg-blue-950/40 border border-blue-800/50 text-xs text-blue-200 flex items-start gap-3">
        <Info className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
        <div className="leading-relaxed">
          <strong className="text-blue-100">Session-Scoped Analytics: </strong>
          This telemetry represents an in-memory session ring buffer (up to 500 records) of evaluations executed during your current browser session. Persistent cross-session historical analytics and audit log storage will be introduced in subsequent stages with PostgreSQL.
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <MetricCard
          label="Buffer Evaluation Count"
          value={formatNumber(totalFlows)}
          subtext="Active session evaluation records"
          icon={<Activity className="w-5 h-5" />}
          accent="blue"
        />
        <MetricCard
          label="Average Model Latency"
          value={formatLatency(avgLatency)}
          subtext="Supervised + Anomaly Scorer combined"
          icon={<Clock className="w-5 h-5" />}
          accent="purple"
        />
        <MetricCard
          label="Cumulative Latency"
          value={formatLatency(totalLatency)}
          subtext="Total execution compute time"
          icon={<BarChart3 className="w-5 h-5" />}
          accent="emerald"
        />
      </div>

      {/* Analytics Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg space-y-2">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200">
              Inference Latency Dynamics (Latest 30 Flows)
            </h4>
            <span className="text-[11px] text-slate-400 font-mono">ms per flow</span>
          </div>
          <LatencyTrendChart evaluations={sessionEvaluations} />
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg space-y-2">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200">
              Triage Verdict Distribution
            </h4>
            <span className="text-[11px] text-slate-400 font-mono">Normal vs. Anomaly vs. Attack</span>
          </div>
          <TriageBreakdownChart evaluations={sessionEvaluations} />
        </div>
      </div>
    </div>
  );
};
