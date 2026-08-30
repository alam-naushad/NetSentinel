import React from 'react';
import { ShieldCheck, Play, Layers, Trash2 } from 'lucide-react';
import { useApp } from '../../context/useApp';
import { TabId } from '../layout/Sidebar';
import { AnomalyDistributionChart } from './AnomalyDistributionChart';
import { OverviewStats } from './OverviewStats';
import { RecentEvaluationsTable } from './RecentEvaluationsTable';
import { ThreatDistributionChart } from './ThreatDistributionChart';

interface OverviewViewProps {
  onNavigateTab: (tab: TabId) => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({ onNavigateTab }) => {
  const { sessionEvaluations, clearSessionEvaluations } = useApp();

  return (
    <div className="space-y-6">
      {/* View Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-black text-slate-100 tracking-tight flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            Security Monitoring Overview
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time hybrid triage intelligence from active session flow evaluations.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {sessionEvaluations.length > 0 && (
            <button
              onClick={clearSessionEvaluations}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-400 hover:text-red-400 hover:border-red-800/50 transition-colors"
            >
              <Trash2 className="w-3.5 h-3.5" />
              Clear Session Buffer
            </button>
          )}

          <button
            onClick={() => onNavigateTab('single')}
            className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-md transition-colors"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            Analyze Single Flow
          </button>
          <button
            onClick={() => onNavigateTab('batch')}
            className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-colors"
          >
            <Layers className="w-3.5 h-3.5" />
            Run Batch Analysis
          </button>
        </div>
      </div>

      {/* Overview Stats */}
      <OverviewStats evaluations={sessionEvaluations} />

      {/* Visual Analytics Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg space-y-2">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200">
              Attack Family Threat Distribution
            </h4>
            <span className="text-[11px] text-slate-400 font-mono">{sessionEvaluations.length} total flows</span>
          </div>
          <ThreatDistributionChart evaluations={sessionEvaluations} />
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg space-y-2">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200">
              Isolation Forest Anomaly Score Distribution
            </h4>
            <span className="text-[11px] text-slate-400 font-mono">Normalized [0.0 - 1.0]</span>
          </div>
          <AnomalyDistributionChart evaluations={sessionEvaluations} />
        </div>
      </div>

      {/* Recent Evaluations Activity Feed */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">
            Recent Session Activity Feed (Latest 10 Flows)
          </h3>
          <span className="text-xs text-slate-400">In-Memory Session Ring Buffer</span>
        </div>
        <RecentEvaluationsTable evaluations={sessionEvaluations} />
      </div>
    </div>
  );
};
