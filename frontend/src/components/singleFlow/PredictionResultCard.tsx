import React from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { FlowPredictionResponse } from '../../types/inference';
import { formatPercent, formatLatency } from '../../utils/formatters';
import { ShieldCheck, Crosshair } from 'lucide-react';

interface PredictionResultCardProps {
  prediction: FlowPredictionResponse;
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

export const PredictionResultCard: React.FC<PredictionResultCardProps> = ({ prediction }) => {
  const probData = Object.entries(prediction.class_probabilities)
    .map(([cls, prob]) => ({
      name: cls,
      probability: prob,
      percentage: (prob * 100).toFixed(1),
    }))
    .sort((a, b) => b.probability - a.probability);

  const isBenign = prediction.predicted_family === 'BENIGN';

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <Crosshair className="w-4 h-4 text-blue-400" />
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200">
            Supervised Attack Classification
          </h4>
        </div>
        <span className="text-xs font-mono text-slate-400">
          Latency: <strong className="text-blue-400">{formatLatency(prediction.inference_latency_ms)}</strong>
        </span>
      </div>

      {/* Main Verdict Card */}
      <div className={`p-4 rounded-xl border flex items-center justify-between ${
        isBenign
          ? 'bg-emerald-950/40 border-emerald-700/50'
          : 'bg-red-950/50 border-red-700/60'
      }`}>
        <div>
          <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
            Predicted Attack Family
          </span>
          <div className="text-2xl font-black text-slate-100 tracking-tight mt-0.5">
            {prediction.predicted_family}
          </div>
          <span className="text-xs text-slate-400 font-mono">
            Model: {prediction.supervised_model_key}
          </span>
        </div>
        <div className="text-right">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
            Class Confidence
          </span>
          <div className={`text-2xl font-bold font-mono ${isBenign ? 'text-emerald-400' : 'text-red-400'}`}>
            {formatPercent(prediction.class_confidence)}
          </div>
        </div>
      </div>

      {/* Probability Distribution Chart */}
      <div>
        <div className="flex items-center justify-between text-xs text-slate-300 font-semibold mb-2">
          <span>Multi-Class Softmax Probability Distribution</span>
          <span className="text-[10px] text-slate-400">9-Class Classifier Vector</span>
        </div>
        <div className="h-60 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={probData} layout="vertical" margin={{ top: 5, right: 30, left: 80, bottom: 5 }}>
              <XAxis type="number" domain={[0, 1]} tickFormatter={(v) => `${(v * 100).toFixed(0)}%`} stroke="#64748b" fontSize={10} />
              <YAxis type="category" dataKey="name" stroke="#94a3b8" fontSize={10} width={85} interval={0} />
              <Tooltip
                content={({ active, payload }) => {
                  if (active && payload && payload.length) {
                    const data = payload[0].payload;
                    return (
                      <div className="bg-slate-900 border border-slate-700 p-2 rounded-lg text-xs shadow-xl">
                        <p className="font-bold text-slate-100">{data.name}</p>
                        <p className="text-blue-400 font-mono">{formatPercent(data.probability)} probability</p>
                      </div>
                    );
                  }
                  return null;
                }}
              />
              <Bar dataKey="probability" radius={[0, 4, 4, 0]}>
                {probData.map((entry) => (
                  <Cell key={entry.name} fill={ATTACK_COLORS[entry.name] || '#3b82f6'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
};
