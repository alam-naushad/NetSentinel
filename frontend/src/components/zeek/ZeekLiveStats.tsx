import React from 'react';
import { Activity, Database, Layers, Clock, Cpu } from 'lucide-react';
import { ZeekIngestionStatus } from '../../types/zeek';
import { Card } from '../common/Card';

interface ZeekLiveStatsProps {
  status: ZeekIngestionStatus | null;
  liveSessionCount: number;
}

export const ZeekLiveStats: React.FC<ZeekLiveStatsProps> = ({
  status,
  liveSessionCount,
}) => {
  const counters = status?.counters;
  const latestBatch = status?.latest_batch;

  return (
    <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-6">
      <Card className="bg-slate-900/60 border-slate-800 p-4">
        <div className="flex items-center gap-2 text-slate-400 text-xs font-semibold mb-1">
          <Activity className="w-4 h-4 text-emerald-400" />
          <span>Live Streamed</span>
        </div>
        <div className="text-xl font-bold font-mono text-emerald-400">
          {liveSessionCount.toLocaleString()}
        </div>
        <div className="text-[10px] text-slate-500 mt-0.5">
          Events in current session
        </div>
      </Card>

      <Card className="bg-slate-900/60 border-slate-800 p-4">
        <div className="flex items-center gap-2 text-slate-400 text-xs font-semibold mb-1">
          <Database className="w-4 h-4 text-purple-400" />
          <span>DB Persisted</span>
        </div>
        <div className="text-xl font-bold font-mono text-purple-300">
          {counters ? counters.records_persisted.toLocaleString() : '0'}
        </div>
        <div className="text-[10px] text-slate-500 mt-0.5">
          {counters ? `${counters.batches_persisted} batches` : '-'}
        </div>
      </Card>

      <Card className="bg-slate-900/60 border-slate-800 p-4">
        <div className="flex items-center gap-2 text-slate-400 text-xs font-semibold mb-1">
          <Clock className="w-4 h-4 text-blue-400" />
          <span>Ingestion Lag</span>
        </div>
        <div className="text-xl font-bold font-mono text-blue-300">
          {latestBatch && latestBatch.ingestion_lag_ms > 0
            ? `${(latestBatch.ingestion_lag_ms / 1000).toFixed(2)}s`
            : '< 1.0s'}
        </div>
        <div className="text-[10px] text-slate-500 mt-0.5">
          Flush: {latestBatch ? `${latestBatch.flush_latency_ms.toFixed(1)}ms` : '-'}
        </div>
      </Card>

      <Card className="bg-slate-900/60 border-slate-800 p-4">
        <div className="flex items-center gap-2 text-slate-400 text-xs font-semibold mb-1">
          <Layers className="w-4 h-4 text-amber-400" />
          <span>Queue Depth</span>
        </div>
        <div className="text-xl font-bold font-mono text-amber-300">
          {counters ? counters.queue_depth : '0'}
        </div>
        <div className="text-[10px] text-slate-500 mt-0.5">
          Peak: {counters ? counters.queue_high_watermark : '0'}
        </div>
      </Card>

      <Card className="bg-slate-900/60 border-slate-800 p-4">
        <div className="flex items-center gap-2 text-slate-400 text-xs font-semibold mb-1">
          <Cpu className="w-4 h-4 text-cyan-400" />
          <span>Spool Worker</span>
        </div>
        <div className="text-xl font-bold font-mono text-cyan-300 uppercase text-sm mt-1">
          {status ? status.status : 'Disabled'}
        </div>
        <div className="text-[10px] text-slate-500 mt-1 truncate" title={status?.spool_directory}>
          {status ? `${status.counters.sse_clients_connected} SSE client(s)` : '-'}
        </div>
      </Card>
    </div>
  );
};
