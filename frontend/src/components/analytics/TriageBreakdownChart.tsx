import React from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { SessionEvaluationRecord } from '../../types/inference';

interface TriageBreakdownChartProps {
  evaluations: SessionEvaluationRecord[];
}

export const TriageBreakdownChart: React.FC<TriageBreakdownChartProps> = ({ evaluations }) => {
  const normal = evaluations.filter((e) => e.decision.status === 'NORMAL').length;
  const anomaly = evaluations.filter((e) => e.decision.status === 'UNKNOWN_ANOMALY').length;
  const attack = evaluations.filter((e) => e.decision.status === 'KNOWN_ATTACK').length;

  const data = [
    { name: 'NORMAL', count: normal, fill: '#10b981' },
    { name: 'UNKNOWN ANOMALY', count: anomaly, fill: '#f59e0b' },
    { name: 'KNOWN ATTACK', count: attack, fill: '#ef4444' },
  ];

  if (evaluations.length === 0) {
    return (
      <div className="h-64 flex items-center justify-center text-slate-500 text-xs">
        No triage data recorded in session buffer yet.
      </div>
    );
  }

  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
          <XAxis dataKey="name" stroke="#64748b" fontSize={10} />
          <YAxis stroke="#64748b" fontSize={10} allowDecimals={false} />
          <Tooltip
            content={({ active, payload }) => {
              if (active && payload && payload.length) {
                const item = payload[0].payload;
                return (
                  <div className="bg-slate-900 border border-slate-700 p-2 rounded-lg text-xs shadow-xl">
                    <p className="font-bold text-slate-100">{item.name}</p>
                    <p className="text-slate-300 font-mono">{item.count} flows ({((item.count / evaluations.length) * 100).toFixed(1)}%)</p>
                  </div>
                );
              }
              return null;
            }}
          />
          <Bar dataKey="count" radius={[4, 4, 0, 0]}>
            {data.map((entry) => (
              <Cell key={entry.name} fill={entry.fill} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};
