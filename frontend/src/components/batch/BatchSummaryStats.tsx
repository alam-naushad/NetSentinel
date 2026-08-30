import React from 'react';
import { BatchFlowInferenceResponse } from '../../types/inference';
import { MetricCard } from '../common/MetricCard';
import { Activity, Clock, Zap, ShieldAlert, CheckCircle } from 'lucide-react';
import { formatLatency, formatNumber } from '../../utils/formatters';

interface BatchSummaryStatsProps {
  result: BatchFlowInferenceResponse;
}

export const BatchSummaryStats: React.FC<BatchSummaryStatsProps> = ({ result }) => {
  const throughput = ((result.total_flows / (result.total_latency_ms || 1)) * 1000).toFixed(0);
  const anomalies = result.summary['STATISTICAL_ANOMALIES_FLAGGED'] || 0;
  const benignCount = result.summary['BENIGN'] || 0;
  const attackCount = result.total_flows - benignCount;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      <MetricCard
        label="Total Processed Flows"
        value={formatNumber(result.total_flows)}
        subtext={`Batch throughput: ${throughput} flows/sec`}
        icon={<Activity className="w-5 h-5" />}
        accent="blue"
      />
      <MetricCard
        label="Total Batch Latency"
        value={formatLatency(result.total_latency_ms)}
        subtext={`Avg / flow: ${formatLatency(result.average_latency_ms)}`}
        icon={<Clock className="w-5 h-5" />}
        accent="purple"
      />
      <MetricCard
        label="Confirmed Attacks"
        value={formatNumber(attackCount)}
        subtext={`${((attackCount / result.total_flows) * 100).toFixed(1)}% of batch volume`}
        icon={<ShieldAlert className="w-5 h-5" />}
        accent={attackCount > 0 ? 'red' : 'emerald'}
      />
      <MetricCard
        label="Statistical Anomalies"
        value={formatNumber(anomalies)}
        subtext="Flagged by α=0.01 threshold"
        icon={<Zap className="w-5 h-5" />}
        accent={anomalies > 0 ? 'amber' : 'emerald'}
      />
    </div>
  );
};
