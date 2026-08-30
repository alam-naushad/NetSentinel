import React from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { SessionEvaluationRecord } from '../../types/inference';
import { formatLatency } from '../../utils/formatters';

interface LatencyTrendChartProps {
  evaluations: SessionEvaluationRecord[];
}

export const LatencyTrendChart: React.FC<LatencyTrendChartProps> = ({ evaluations }) => {
  const data = evaluations
    .slice(0, 30)
    .reverse()
    .map((e, idx) => ({
      index: idx + 1,
      latency: parseFloat(e.prediction.inference_latency_ms.toFixed(3)),
      family: e.prediction.predicted_family,
      time: new Date(e.timestamp).toLocaleTimeString(),
    }));

  if (data.length === 0) {
    return (
      <div className="h-64 flex items-center justify-center text-slate-500 text-xs">
        No latency data recorded in session buffer yet.
      </div>
    );
  }

  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 10, right: 20, left: -10, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
          <XAxis dataKey="index" stroke="#64748b" fontSize={10} label={{ value: 'Evaluation Sequence', position: 'insideBottom', offset: -5, fill: '#64748b', fontSize: 10 }} />
          <YAxis stroke="#64748b" fontSize={10} tickFormatter={(v) => `${v}ms`} />
          <Tooltip
            content={({ active, payload }) => {
              if (active && payload && payload.length) {
                const item = payload[0].payload;
                return (
                  <div className="bg-slate-900 border border-slate-700 p-2.5 rounded-lg text-xs shadow-xl">
                    <p className="font-bold text-slate-100">{item.family} ({item.time})</p>
                    <p className="text-blue-400 font-mono">Latency: {item.latency} ms</p>
                  </div>
                );
              }
              return null;
            }}
          />
          <Line type="monotone" dataKey="latency" stroke="#3b82f6" strokeWidth={2} dot={{ r: 3, fill: '#3b82f6' }} activeDot={{ r: 5 }} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
};
