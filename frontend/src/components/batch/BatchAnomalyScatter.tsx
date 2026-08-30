import React from 'react';
import { ScatterChart, Scatter, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell, ReferenceLine } from 'recharts';
import { FlowPredictionResponse } from '../../types/inference';
import { formatPercent } from '../../utils/formatters';

interface BatchAnomalyScatterProps {
  predictions: FlowPredictionResponse[];
}

const ATTACK_COLORS: Record<string, string> = {
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

export const BatchAnomalyScatter: React.FC<BatchAnomalyScatterProps> = ({ predictions }) => {
  const data = predictions.map((p, idx) => ({
    id: idx + 1,
    confidence: p.class_confidence,
    anomalyScore: p.normalized_anomaly_score,
    family: p.predicted_family,
    isAnomaly: p.is_statistical_anomaly,
    latency: p.inference_latency_ms,
  }));

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg space-y-3">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div>
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200">
            2D Classifier Confidence vs. Statistical Anomaly Score
          </h4>
          <p className="text-[11px] text-slate-400">
            X-Axis: Supervised Confidence | Y-Axis: Isolation Forest Anomaly Score
          </p>
        </div>
        <span className="text-xs font-mono text-slate-400">{predictions.length} Data Points</span>
      </div>

      <div className="h-64 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <ScatterChart margin={{ top: 10, right: 20, bottom: 20, left: 10 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
            <XAxis
              type="number"
              dataKey="confidence"
              name="Confidence"
              domain={[0, 1]}
              tickFormatter={(v) => `${(v * 100).toFixed(0)}%`}
              stroke="#64748b"
              fontSize={10}
              label={{ value: 'Classifier Confidence', position: 'insideBottom', offset: -10, fill: '#94a3b8', fontSize: 10 }}
            />
            <YAxis
              type="number"
              dataKey="anomalyScore"
              name="Anomaly Score"
              domain={[0, 1]}
              stroke="#64748b"
              fontSize={10}
              label={{ value: 'Anomaly Score', angle: -90, position: 'insideLeft', fill: '#94a3b8', fontSize: 10 }}
            />
            <ReferenceLine y={0.7} stroke="#f59e0b" strokeDasharray="4 4" label={{ value: 'Policy Anomaly Gate (0.70)', fill: '#f59e0b', fontSize: 9 }} />
            <ReferenceLine x={0.8} stroke="#3b82f6" strokeDasharray="4 4" label={{ value: 'Known Attack Gate (0.80)', fill: '#3b82f6', fontSize: 9 }} />
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  const pt = payload[0].payload;
                  return (
                    <div className="bg-slate-900 border border-slate-700 p-2.5 rounded-lg text-xs shadow-xl space-y-1">
                      <p className="font-bold text-slate-100">Flow #{pt.id} — <span style={{ color: ATTACK_COLORS[pt.family] || '#3b82f6' }}>{pt.family}</span></p>
                      <p className="text-slate-300">Confidence: <strong className="font-mono text-slate-100">{formatPercent(pt.confidence)}</strong></p>
                      <p className="text-slate-300">Anomaly Score: <strong className="font-mono text-purple-300">{pt.anomalyScore.toFixed(4)}</strong></p>
                      <p className="text-[10px] text-slate-400">Statistical Anomaly: {pt.isAnomaly ? 'YES' : 'NO'}</p>
                    </div>
                  );
                }
                return null;
              }}
            />
            <Scatter data={data}>
              {data.map((entry) => (
                <Cell
                  key={entry.id}
                  fill={ATTACK_COLORS[entry.family] || '#3b82f6'}
                  stroke="#0f172a"
                  strokeWidth={1.5}
                />
              ))}
            </Scatter>
          </ScatterChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};
