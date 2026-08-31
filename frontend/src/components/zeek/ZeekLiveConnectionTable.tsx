import React, { useState } from 'react';
import { ArrowRight, Search, Pause, Play, Trash2, Filter } from 'lucide-react';
import { ZeekLiveEvent } from '../../types/zeek';

interface ZeekLiveConnectionTableProps {
  events: ZeekLiveEvent[];
  isPaused: boolean;
  onTogglePause: () => void;
  onClear: () => void;
  maxBuffer: number;
}

export const ZeekLiveConnectionTable: React.FC<ZeekLiveConnectionTableProps> = ({
  events,
  isPaused,
  onTogglePause,
  onClear,
  maxBuffer,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [protoFilter, setProtoFilter] = useState<'ALL' | 'TCP' | 'UDP' | 'ICMP'>('ALL');

  const filteredEvents = events.filter((ev) => {
    if (protoFilter !== 'ALL' && ev.proto.toUpperCase() !== protoFilter) {
      return false;
    }
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      ev.src_ip.toLowerCase().includes(term) ||
      ev.dst_ip.toLowerCase().includes(term) ||
      ev.uid.toLowerCase().includes(term) ||
      (ev.service && ev.service.toLowerCase().includes(term)) ||
      ev.src_port.toString().includes(term) ||
      ev.dst_port.toString().includes(term) ||
      (ev.conn_state && ev.conn_state.toLowerCase().includes(term))
    );
  });

  return (
    <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-900/60 shadow-sm space-y-0">
      {/* Controls Bar */}
      <div className="p-3 border-b border-slate-800 bg-slate-950/70 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-3 flex-1 min-w-[240px]">
          <div className="relative flex-1 max-w-xs">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Filter IP, port, service, UID..."
              className="w-full bg-slate-900 border border-slate-700/60 rounded-xl pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="flex items-center gap-1 bg-slate-900 p-1 rounded-xl border border-slate-800">
            {(['ALL', 'TCP', 'UDP', 'ICMP'] as const).map((proto) => (
              <button
                key={proto}
                onClick={() => setProtoFilter(proto)}
                className={`px-2.5 py-1 rounded-lg text-[11px] font-semibold transition-colors ${
                  protoFilter === proto
                    ? 'bg-blue-600 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {proto}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-slate-500 font-mono text-[11px] mr-2">
            Showing {filteredEvents.length} of {events.length} (buffer: {maxBuffer})
          </span>

          <button
            onClick={onTogglePause}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold border transition-all ${
              isPaused
                ? 'bg-amber-950/60 border-amber-600/50 text-amber-300 hover:bg-amber-900/60'
                : 'bg-slate-800 hover:bg-slate-700 border-slate-700 text-slate-300'
            }`}
          >
            {isPaused ? (
              <>
                <Play className="w-3 h-3 fill-current" />
                <span>Resume Stream</span>
              </>
            ) : (
              <>
                <Pause className="w-3 h-3 fill-current" />
                <span>Pause Stream</span>
              </>
            )}
          </button>

          <button
            onClick={onClear}
            className="flex items-center gap-1 px-2.5 py-1.5 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-400 hover:text-slate-200 transition-colors"
            title="Clear rolling buffer"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Clear</span>
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto max-h-[520px] overflow-y-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead className="sticky top-0 bg-slate-950/90 backdrop-blur z-10">
            <tr className="border-b border-slate-800 text-slate-400 font-semibold">
              <th className="py-2.5 px-3 w-16">Seq #</th>
              <th className="py-2.5 px-3">Zeek UID</th>
              <th className="py-2.5 px-4">Network 5-Tuple</th>
              <th className="py-2.5 px-3">Proto / Service</th>
              <th className="py-2.5 px-3">Duration</th>
              <th className="py-2.5 px-3">Bytes (O/R)</th>
              <th className="py-2.5 px-3">Pkts (O/R)</th>
              <th className="py-2.5 px-3">State / History</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/50 font-mono">
            {filteredEvents.map((conn) => (
              <tr
                key={`${conn.session_id}_${conn.sequence_id}_${conn.uid}`}
                className="hover:bg-slate-800/40 transition-colors"
              >
                <td className="py-2 px-3 text-slate-500 font-mono text-[11px]">
                  #{conn.sequence_id}
                </td>
                <td className="py-2 px-3 text-blue-400 font-semibold text-[11px]">
                  {conn.uid}
                </td>
                <td className="py-2 px-4 text-slate-300">
                  <div className="flex items-center gap-1.5">
                    <span className="font-semibold text-slate-200">{conn.src_ip}:{conn.src_port}</span>
                    <ArrowRight className="w-3 h-3 text-slate-500 inline shrink-0" />
                    <span className="text-slate-300">{conn.dst_ip}:{conn.dst_port}</span>
                  </div>
                </td>
                <td className="py-2 px-3">
                  <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-bold text-[10px] mr-1">
                    {conn.proto.toUpperCase()}
                  </span>
                  {conn.service && conn.service !== '-' && (
                    <span className="px-1.5 py-0.5 rounded bg-blue-950/70 text-blue-300 font-semibold text-[10px] border border-blue-800/40">
                      {conn.service}
                    </span>
                  )}
                </td>
                <td className="py-2 px-3 text-slate-300 text-[11px]">
                  {conn.duration_sec !== null && conn.duration_sec !== undefined
                    ? `${conn.duration_sec.toFixed(3)}s`
                    : '-'}
                </td>
                <td className="py-2 px-3 text-slate-300 text-[11px]">
                  {(conn.orig_bytes ?? 0).toLocaleString()} / {(conn.resp_bytes ?? 0).toLocaleString()}
                </td>
                <td className="py-2 px-3 text-slate-300 text-[11px]">
                  {conn.orig_pkts ?? 0} / {conn.resp_pkts ?? 0}
                </td>
                <td className="py-2 px-3 text-slate-300">
                  <div className="flex items-center gap-1.5">
                    <span className="px-1.5 py-0.5 rounded bg-slate-800/80 text-[10px] text-slate-300 font-bold">
                      {conn.conn_state || '-'}
                    </span>
                    {conn.history && (
                      <span className="text-[10px] text-slate-500 truncate max-w-[80px]" title={conn.history}>
                        {conn.history}
                      </span>
                    )}
                  </div>
                </td>
              </tr>
            ))}
            {filteredEvents.length === 0 && (
              <tr>
                <td colSpan={8} className="py-12 text-center text-slate-500 font-sans">
                  {events.length === 0
                    ? 'Waiting for live Zeek connection telemetry from spool stream...'
                    : 'No connections match the current search filters.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
