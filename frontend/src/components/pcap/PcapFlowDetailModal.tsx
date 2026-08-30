import React, { useState } from 'react';
import { X, ShieldAlert, Cpu, Activity, Clock, Layers, ArrowRight, CheckCircle2, AlertTriangle } from 'lucide-react';
import { PcapFlowResult } from '../../types/pcap';
import { StatusBadge, SeverityBadge } from '../common/Badge';
import { FEATURE_CATEGORIES, FEATURE_FIELDS_METADATA } from '../../utils/featureMetadata';
import { formatPercent } from '../../utils/formatters';

interface PcapFlowDetailModalProps {
  flow: PcapFlowResult | null;
  onClose: () => void;
}

export const PcapFlowDetailModal: React.FC<PcapFlowDetailModalProps> = ({ flow, onClose }) => {
  const [activeCategory, setActiveCategory] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState('');

  if (!flow) return null;

  const prov = flow.provenance;
  const features = flow.features || {};

  const filteredFeatures = FEATURE_FIELDS_METADATA.filter((meta) => {
    const matchesCategory = activeCategory === 'all' || meta.category === activeCategory;
    const matchesSearch =
      searchTerm === '' ||
      meta.label.toLowerCase().includes(searchTerm.toLowerCase()) ||
      meta.key.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesCategory && matchesSearch;
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-blue-950/80 border border-blue-600/40 flex items-center justify-center text-blue-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-slate-100 font-mono">
                  {prov.src_ip}:{prov.src_port} <ArrowRight className="w-3.5 h-3.5 inline text-slate-500" /> {prov.dst_ip}:{prov.dst_port}
                </h3>
                <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono font-bold">
                  {prov.protocol_name}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Flow ID: <code className="text-slate-300">{prov.flow_id}</code>
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-xl text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* 1. Triage Decision & Provenance Banner */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Triage Decision Card */}
            <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">Triage Verdict</span>
                <StatusBadge status={flow.status} size="sm" />
              </div>
              <div className="flex items-baseline justify-between">
                <div className="text-2xl font-black text-slate-100">
                  Risk {flow.risk_score}<span className="text-xs text-slate-500 font-normal">/100</span>
                </div>
                <SeverityBadge severity={flow.severity} size="sm" />
              </div>
              <p className="text-xs text-slate-300 bg-slate-900/60 p-2.5 rounded-lg border border-slate-800/60 leading-relaxed">
                {flow.explanation}
              </p>
            </div>

            {/* Supervised Prediction Card */}
            <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">Classifier (XGBoost)</span>
                <Cpu className="w-4 h-4 text-blue-400" />
              </div>
              <div className="text-lg font-bold text-slate-100 flex items-center justify-between">
                <span>{flow.predicted_family}</span>
                <span className="text-sm font-semibold text-blue-400">{formatPercent(flow.class_confidence)}</span>
              </div>
              <div className="space-y-1.5 pt-1">
                {Object.entries(flow.class_probabilities)
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 3)
                  .map(([cls, prob]) => (
                    <div key={cls} className="flex items-center justify-between text-xs text-slate-400">
                      <span>{cls}</span>
                      <span className="font-mono text-slate-300">{(prob * 100).toFixed(1)}%</span>
                    </div>
                  ))}
              </div>
            </div>

            {/* Statistical Anomaly Card */}
            <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">Anomaly Detector (IF)</span>
                <Activity className="w-4 h-4 text-purple-400" />
              </div>
              <div className="text-lg font-bold text-slate-100 flex items-center justify-between">
                <span>Score: {flow.normalized_anomaly_score.toFixed(3)}</span>
                {flow.is_statistical_anomaly ? (
                  <span className="text-xs px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-700/50 font-semibold">
                    Flagged (α=0.01)
                  </span>
                ) : (
                  <span className="text-xs px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-700/50">
                    Normal
                  </span>
                )}
              </div>
              <div className="text-xs text-slate-400 space-y-1 pt-1">
                <div className="flex justify-between">
                  <span>Raw Decision Score:</span>
                  <span className="font-mono text-slate-300">{flow.raw_decision_score.toFixed(6)}</span>
                </div>
                <div className="flex justify-between">
                  <span>Duration / Packets:</span>
                  <span className="font-mono text-slate-300">{prov.duration_ms} ms / {prov.total_packets} pkts</span>
                </div>
              </div>
            </div>
          </div>

          {/* 2. Reconstructed 48 Features Inspector */}
          <div className="space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
              <div>
                <h4 className="text-sm font-bold text-slate-200">Reconstructed 48-Feature Canonical Vector</h4>
                <p className="text-xs text-slate-400">Extracted from PCAP packets conforming to CICFlowMeter transport payload semantics.</p>
              </div>
              <input
                type="text"
                placeholder="Search features..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 w-48"
              />
            </div>

            {/* Category Filter Pills */}
            <div className="flex flex-wrap gap-1.5">
              <button
                onClick={() => setActiveCategory('all')}
                className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-colors ${
                  activeCategory === 'all'
                    ? 'bg-blue-600 text-white font-semibold'
                    : 'bg-slate-800/80 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                All (48)
              </button>
              {FEATURE_CATEGORIES.map((cat) => (
                <button
                  key={cat.id}
                  onClick={() => setActiveCategory(cat.id)}
                  className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-colors ${
                    activeCategory === cat.id
                      ? 'bg-blue-600 text-white font-semibold'
                      : 'bg-slate-800/80 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                  }`}
                >
                  {cat.label}
                </button>
              ))}
            </div>

            {/* Features Table */}
            <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-950/40">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-900/60 text-slate-400">
                    <th className="py-2.5 px-4 font-semibold">Feature Name</th>
                    <th className="py-2.5 px-4 font-semibold">Category</th>
                    <th className="py-2.5 px-4 font-semibold text-right">Extracted Value</th>
                    <th className="py-2.5 px-4 font-semibold">Unit / Description</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {filteredFeatures.map((meta) => {
                    const rawVal = features[meta.key];
                    const displayVal = rawVal !== undefined ? rawVal.toLocaleString(undefined, { maximumFractionDigits: 4 }) : '—';

                    return (
                      <tr key={meta.key} className="hover:bg-slate-900/40 transition-colors">
                        <td className="py-2 px-4 text-slate-300 font-sans font-medium">
                          {meta.label}
                          <span className="block text-[10px] text-slate-500 font-mono">{meta.key}</span>
                        </td>
                        <td className="py-2 px-4 text-slate-400 font-sans capitalize">
                          {meta.category.replace('_', ' ')}
                        </td>
                        <td className="py-2 px-4 text-right text-blue-400 font-bold">
                          {displayVal}
                        </td>
                        <td className="py-2 px-4 text-slate-400 font-sans text-[11px]">
                          {meta.unit && <span className="text-slate-500 mr-1.5 font-mono">[{meta.unit}]</span>}
                          {meta.description}
                        </td>
                      </tr>
                    );
                  })}
                  {filteredFeatures.length === 0 && (
                    <tr>
                      <td colSpan={4} className="py-6 text-center text-slate-500 font-sans">
                        No features match search term "{searchTerm}".
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-950/60 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-xl transition-colors"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
