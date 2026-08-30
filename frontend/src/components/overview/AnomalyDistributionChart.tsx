import React from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { SessionEvaluationRecord } from '../../types/inference';

interface AnomalyDistributionChartProps {
  evaluations: SessionEvaluationRecord[];
}

export const AnomalyDistributionChart: React.FC<AnomalyDistributionChartProps> = ({ evaluations }) => {
  // Group anomaly scores into 5 buckets: 0.0-0.2, 0.2-0.4, 0.4-0.6, 0.6-0.8, 0.8-1.0
  const buckets = [
    { range: '0.0 - 0.2', count: 0, fill: '#10b981' },
    { range: '0.2 - 0.4', count: 0, fill: '#3b82f6' },
    { range: '0.4 - 0.6', count: 0, fill: '#f59e0b' },
    { range: '0.6 - 0.8', count: 0, fill: '#f97316' },
    { range: '0.8 - 1.0', count: 0, fill: '#ef4444' },
  ];

  evaluations.forEach((e) => {
    const score = e.prediction.normalized_anomaly_score;
    if (score < 0.2) buckets[0].count++;
    else if (score < 0.4) buckets[1].count++;
    else if (score < 0.6) buckets[2].count++;
    else if (score < 0.8) buckets[3].count++;
    else buckets[4].count++;
  });

  if (evaluations.length === 0) {
    return (
      <div className="h-64 flex items-center justify-center text-slate-500 text-xs">
        No evaluation data recorded in active session buffer yet.
      </div>
    );
  }

  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={buckets} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
          <XAxis dataKey="range" stroke="#64748b" fontSize={10} />
          <YAxis stroke="#64748b" fontSize={10} allowDecimals={false} />
          <Tooltip
            content={({ active, payload }) => {
              if (active && payload && payload.length) {
                const item = payload[0].payload;
                return (
                  <div className="bg-slate-900 border border-slate-700 p-2 rounded-lg text-xs shadow-xl">
                    <p className="font-bold text-slate-100">Score Range: {item.range}</p>
                    <p className="text-purple-300 font-mono">{item.count} flows</p>
                  </div>
                );
              }
              return null;
            }}
          />
          <Bar dataKey="count" radius={[4, 4, 0, 0]}>
            {buckets.map((b) => (
              <Cell key={b.range} fill={b.fill} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};
