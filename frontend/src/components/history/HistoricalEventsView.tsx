import React, { useEffect, useState } from 'react';
import { Database, Search, Filter, ArrowRight, Eye, ArrowUpDown, ShieldAlert, Activity, RefreshCw } from 'lucide-react';
import { EventSearchParams, telemetryApi } from '../../api/telemetryApi';
import { SecurityEventDetail, SecurityEventSummary } from '../../types/telemetry';
import { StatusBadge, SeverityBadge } from '../common/Badge';
import { LoadingSpinner } from '../common/LoadingState';
import { ErrorAlert } from '../common/ErrorAlert';
import { PcapFlowDetailModal } from '../pcap/PcapFlowDetailModal';
import { PcapFlowResult } from '../../types/pcap';
import { formatPercent } from '../../utils/formatters';
import { ApiError } from '../../api/client';

export const HistoricalEventsView: React.FC = () => {
  const [events, setEvents] = useState<SecurityEventSummary[]>([]);
  const [totalEvents, setTotalEvents] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(25);
  const [totalPages, setTotalPages] = useState(1);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);

  // Filters
  const [timeWindow, setTimeWindow] = useState<string>('24h');
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [attackFilter, setAttackFilter] = useState<string>('all');
  const [sortField, setSortField] = useState<string>('event_timestamp');
  const [sortAsc, setSortAsc] = useState(false);

  // Detail Modal
  const [selectedEventFlow, setSelectedEventFlow] = useState<PcapFlowResult | null>(null);
  const [isLoadingDetail, setIsLoadingDetail] = useState(false);

  const fetchEvents = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const now = new Date();
      let startTime: string | undefined;

      if (timeWindow === '1h') {
        startTime = new Date(now.getTime() - 60 * 60 * 1000).toISOString();
      } else if (timeWindow === '24h') {
        startTime = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
      } else if (timeWindow === '7d') {
        startTime = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();
      } else if (timeWindow === '30d') {
        startTime = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();
      }

      const params: EventSearchParams = {
        page,
        page_size: pageSize,
        start_time: startTime,
        sort_by: sortField,
        sort_order: sortAsc ? 'asc' : 'desc',
      };

      if (statusFilter !== 'all') params.triage_status = [statusFilter];
      if (severityFilter !== 'all') params.severity = [severityFilter];
      if (attackFilter !== 'all') params.attack_family = [attackFilter];
      if (searchTerm) {
        if (searchTerm.includes('.') || searchTerm.includes(':')) {
          params.src_ip = searchTerm;
        } else {
          params.attack_family = [searchTerm.toUpperCase()];
        }
      }

      const res = await telemetryApi.getEvents(params);
      setEvents(res.items);
      setTotalEvents(res.total);
      setTotalPages(res.total_pages);
    } catch (err: any) {
      setError(err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, [page, timeWindow, statusFilter, severityFilter, attackFilter, sortField, sortAsc]);

  const handleInspectEvent = async (eventId: string) => {
    setIsLoadingDetail(true);
    try {
      const detail = await telemetryApi.getEventDetail(eventId);
      // Map to PcapFlowResult for modal reuse
      const flowRes: PcapFlowResult = {
        provenance: detail.provenance,
        predicted_family: detail.predicted_family,
        class_confidence: detail.class_confidence,
        class_probabilities: detail.class_probabilities,
        raw_decision_score: detail.raw_decision_score,
        is_statistical_anomaly: detail.is_statistical_anomaly,
        normalized_anomaly_score: detail.normalized_anomaly_score,
        risk_score: detail.risk_score,
        severity: detail.severity as any,
        status: detail.triage_status as any,
        explanation: detail.explanation,
        features: detail.feature_vector,
      };
      setSelectedEventFlow(flowRes);
    } catch (err: any) {
      setError(err);
    } finally {
      setIsLoadingDetail(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <Database className="w-5 h-5 text-purple-400" />
              Persistent Security Telemetry Explorer
            </h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-950 text-purple-300 border border-purple-800/60 uppercase tracking-wider">
              PostgreSQL Telemetry
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Query immutable historical detection events and inspect 48-feature vectors across past captures.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-slate-400 bg-slate-900 px-3 py-1.5 rounded-xl border border-slate-800">
            {totalEvents.toLocaleString()} Total Records
          </span>
        </div>
      </div>

      {/* Filter & Search Toolbar */}
      <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          {/* Time Window Pills */}
          <div className="flex items-center gap-1.5 bg-slate-950 p-1 rounded-xl border border-slate-800">
            {['1h', '24h', '7d', '30d', 'all'].map((tw) => (
              <button
                key={tw}
                onClick={() => {
                  setTimeWindow(tw);
                  setPage(1);
                }}
                className={`px-3 py-1 rounded-lg text-xs font-semibold uppercase transition-colors ${
                  timeWindow === tw
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {tw}
              </button>
            ))}
          </div>

          {/* Search Input */}
          <div className="relative flex-1 min-w-[200px] max-w-md">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search by IP, subnet CIDR (e.g. 192.168.10.0/24), or attack family..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && fetchEvents()}
              className="w-full pl-9 pr-4 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <button
            onClick={fetchEvents}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition-colors flex items-center gap-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>

        {/* Dropdown Filters */}
        <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-slate-800/60">
          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setPage(1);
            }}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-blue-500"
          >
            <option value="all">All Statuses</option>
            <option value="NORMAL">NORMAL</option>
            <option value="UNKNOWN_ANOMALY">UNKNOWN_ANOMALY</option>
            <option value="KNOWN_ATTACK">KNOWN_ATTACK</option>
          </select>

          <select
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value);
              setPage(1);
            }}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-blue-500"
          >
            <option value="all">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>

          <select
            value={attackFilter}
            onChange={(e) => {
              setAttackFilter(e.target.value);
              setPage(1);
            }}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-blue-500"
          >
            <option value="all">All Attack Families</option>
            <option value="BENIGN">BENIGN</option>
            <option value="DOS">DOS</option>
            <option value="DDOS">DDOS</option>
            <option value="PORT_SCAN">PORT_SCAN</option>
            <option value="BRUTE_FORCE">BRUTE_FORCE</option>
            <option value="BOT">BOT</option>
          </select>
        </div>
      </div>

      {/* Error Alert */}
      {error && <ErrorAlert error={error} onDismiss={() => setError(null)} />}

      {/* Table & Content */}
      {isLoading ? (
        <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-12 text-center">
          <LoadingSpinner message="Querying PostgreSQL security events..." size="lg" />
        </div>
      ) : (
        <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-900/60 shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 font-semibold">
                  <th className="py-3 px-4">Event Timestamp</th>
                  <th className="py-3 px-4">Network Endpoints (Provenance)</th>
                  <th className="py-3 px-3">Predicted Family</th>
                  <th className="py-3 px-3">Confidence</th>
                  <th className="py-3 px-3">Anomaly Score</th>
                  <th className="py-3 px-3">Risk Score</th>
                  <th className="py-3 px-3">Triage Status</th>
                  <th className="py-3 px-4 text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {events.map((ev) => (
                  <tr
                    key={ev.id}
                    onClick={() => handleInspectEvent(ev.id)}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                  >
                    {/* Timestamp */}
                    <td className="py-3 px-4 text-slate-400 font-sans">
                      <div className="text-slate-200 font-bold">
                        {new Date(ev.event_timestamp).toLocaleTimeString()}
                      </div>
                      <div className="text-[10px] text-slate-500">
                        {new Date(ev.event_timestamp).toLocaleDateString()}
                      </div>
                    </td>

                    {/* Endpoints */}
                    <td className="py-3 px-4 text-slate-300">
                      <div className="font-semibold text-slate-200 flex items-center gap-1.5">
                        <span>{ev.src_ip}:{ev.src_port}</span>
                        <ArrowRight className="w-3 h-3 text-slate-500 inline" />
                        <span>{ev.dst_ip}:{ev.dst_port}</span>
                      </div>
                      <span className="text-[10px] text-slate-500 font-mono">
                        Protocol: {ev.protocol_name} • Channel: {ev.source_channel}
                      </span>
                    </td>

                    {/* Attack Family */}
                    <td className="py-3 px-3 font-sans">
                      <span className={`font-semibold ${ev.predicted_family !== 'BENIGN' ? 'text-red-400' : 'text-slate-300'}`}>
                        {ev.predicted_family}
                      </span>
                      {ev.has_alert && (
                        <span className="ml-1.5 px-1.5 py-0.5 rounded bg-red-950 text-red-400 border border-red-800/60 text-[9px] font-bold">
                          ALERT
                        </span>
                      )}
                    </td>

                    {/* Confidence */}
                    <td className="py-3 px-3">
                      <span className="font-semibold text-slate-300">{formatPercent(ev.class_confidence)}</span>
                    </td>

                    {/* Anomaly Score */}
                    <td className="py-3 px-3">
                      <span className="text-slate-300 font-mono">{ev.normalized_anomaly_score.toFixed(3)}</span>
                      {ev.is_statistical_anomaly && (
                        <span className="ml-1.5 text-[10px] px-1 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800/60 font-bold">
                          α01
                        </span>
                      )}
                    </td>

                    {/* Risk Score & Severity */}
                    <td className="py-3 px-3 font-sans">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-slate-200 font-mono">{ev.risk_score}</span>
                        <SeverityBadge severity={ev.severity} size="sm" />
                      </div>
                    </td>

                    {/* Status */}
                    <td className="py-3 px-3 font-sans">
                      <StatusBadge status={ev.triage_status} size="sm" />
                    </td>

                    {/* Action */}
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleInspectEvent(ev.id);
                        }}
                        className="p-1.5 rounded-lg bg-slate-800 hover:bg-purple-600 text-slate-400 hover:text-white transition-colors"
                        title="Inspect Reconstructed 48 Features"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}

                {events.length === 0 && (
                  <tr>
                    <td colSpan={8} className="py-12 text-center text-slate-500 font-sans">
                      No security events match the current filter criteria.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination Footer */}
          <div className="px-4 py-3 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between text-xs text-slate-400">
            <div>
              Showing {events.length > 0 ? (page - 1) * pageSize + 1 : 0} to{' '}
              {Math.min(page * pageSize, totalEvents)} of {totalEvents.toLocaleString()} events
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="px-3 py-1 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:pointer-events-none rounded-lg text-slate-300"
              >
                Previous
              </button>
              <span className="font-mono">
                Page {page} of {totalPages}
              </span>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="px-3 py-1 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:pointer-events-none rounded-lg text-slate-300"
              >
                Next
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 48-Feature Inspection Modal */}
      <PcapFlowDetailModal
        flow={selectedEventFlow}
        onClose={() => setSelectedEventFlow(null)}
      />
    </div>
  );
};
