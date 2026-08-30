import React from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { SessionEvaluationRecord } from '../../types/inference';
import { formatPercent } from '../../utils/formatters';

interface ThreatDistributionChartProps {
  evaluations: SessionEvaluationRecord[];
}

const FAMILY_COLORS: Record<string, string> = {
  BENIGN: '#10b981',
  DOS: '#ef4444',
  DDOS: '#dc2626',
  PORT_SCAN: '#f59e0b',
  BRUTE_FORCE: '#f97316',
  WEB_ATTACK: '#e11d48',
  BOTNET: '#8b5cf6',
  INFILTRATION: '#ec4899',
  HEARTBLEED: '#a855f7',
};

export const ThreatDistributionChart: React.FC<ThreatDistributionChartProps> = ({ evaluations }) => {
  const counts: Record<string, number> = {};
  evaluations.forEach((e) => {
    const fam = e.prediction.predicted_family;
    counts[fam] = (counts[fam] || 0) + 1;
  });

  const data = Object.entries(counts).map(([name, count]) => ({
    name,
    value: count,
  }));

  if (data.length === 0) {
    return (
      <div className="h-64 flex items-center justify-center text-slate-500 text-xs">
        No evaluation data recorded in active session buffer yet.
      </div>
    );
  }

  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={55}
            outerRadius={80}
            paddingAngle={4}
            dataKey="value"
          >
            {data.map((entry) => (
              <Cell key={entry.name} fill={FAMILY_COLORS[entry.name] || '#3b82f6'} />
            ))}
          </Pie>
          <Tooltip
            content={({ active, payload }) => {
              if (active && payload && payload.length) {
                const item = payload[0].payload;
                const pct = ((item.value / evaluations.length) * 100).toFixed(1);
                return (
                  <div className="bg-slate-900 border border-slate-700 p-2.5 rounded-lg text-xs shadow-xl">
                    <p className="font-bold text-slate-100">{item.name}</p>
                    <p className="text-slate-300">{item.value} flows ({pct}%)</p>
                  </div>
                );
              }
              return null;
            }}
          />
          <Legend wrapperStyle={{ fontSize: '11px' }} />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
};
