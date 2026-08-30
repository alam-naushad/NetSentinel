import React from 'react';
import { Layers, Clock, FileCheck, ShieldCheck, Database, AlertTriangle } from 'lucide-react';
import { ZeekAnalysisSummary } from '../../types/zeek';
import { formatBytes, formatLatency } from '../../utils/formatters';

interface ZeekSummaryCardsProps {
  summary: ZeekAnalysisSummary;
}

export const ZeekSummaryCards: React.FC<ZeekSummaryCardsProps> = ({ summary }) => {
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
      {/* 1. Connections Parsed */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="flex items-center justify-between text-slate-400 mb-1">
          <span className="text-[11px] font-medium uppercase tracking-wider">Connections Parsed</span>
          <Layers className="w-4 h-4 text-blue-400" />
        </div>
        <div className="text-xl font-bold text-slate-100">
          {summary.total_connections_parsed.toLocaleString()}
        </div>
      </div>

      {/* 2. Connections Persisted */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="flex items-center justify-between text-slate-400 mb-1">
          <span className="text-[11px] font-medium uppercase tracking-wider">Persisted</span>
          <Database className="w-4 h-4 text-emerald-400" />
        </div>
        <div className="text-xl font-bold text-emerald-400">
          {summary.total_connections_persisted.toLocaleString()}
        </div>
      </div>

      {/* 3. Skipped / Malformed */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="flex items-center justify-between text-slate-400 mb-1">
          <span className="text-[11px] font-medium uppercase tracking-wider">Skipped</span>
          <AlertTriangle className="w-4 h-4 text-amber-400" />
        </div>
        <div className="text-xl font-bold text-amber-400">
          {(summary.connections_skipped_malformed + summary.connections_skipped_duplicate).toLocaleString()}
        </div>
        <div className="text-[10px] text-slate-400 mt-0.5">
          {summary.connections_skipped_malformed} malformed, {summary.connections_skipped_duplicate} duplicate
        </div>
      </div>

      {/* 4. Processing Time */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="flex items-center justify-between text-slate-400 mb-1">
          <span className="text-[11px] font-medium uppercase tracking-wider">Latency</span>
          <Clock className="w-4 h-4 text-purple-400" />
        </div>
        <div className="text-xl font-bold text-slate-100">
          {formatLatency(summary.processing_time_ms)}
        </div>
      </div>

      {/* 5. File Metadata */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="flex items-center justify-between text-slate-400 mb-1">
          <span className="text-[11px] font-medium uppercase tracking-wider">File Format</span>
          <FileCheck className="w-4 h-4 text-cyan-400" />
        </div>
        <div className="text-xl font-bold text-slate-100 truncate" title={summary.filename}>
          {summary.filename.split('.').pop()?.toUpperCase() || 'UNKNOWN'}
        </div>
        <div className="text-[10px] text-slate-400 mt-0.5 truncate" title={summary.filename}>
          {formatBytes(summary.file_size_bytes)}
        </div>
      </div>
    </div>
  );
};
