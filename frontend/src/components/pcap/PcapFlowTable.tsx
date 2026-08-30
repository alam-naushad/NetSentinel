import React, { useState } from 'react';
import { Search, Filter, ArrowUpDown, Shield, AlertTriangle, Eye, ArrowRight } from 'lucide-react';
import { PcapFlowResult } from '../../types/pcap';
import { StatusBadge, SeverityBadge } from '../common/Badge';
import { formatPercent } from '../../utils/formatters';

interface PcapFlowTableProps {
  flows: PcapFlowResult[];
  onSelectFlow: (flow: PcapFlowResult) => void;
}

export const PcapFlowTable: React.FC<PcapFlowTableProps> = ({ flows, onSelectFlow }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [attackFilter, setAttackFilter] = useState<string>('all');
  const [sortField, setSortField] = useState<'risk_score' | 'confidence' | 'anomaly_score' | 'duration' | 'packets'>('risk_score');
  const [sortAsc, setSortAsc] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 20;

  // Filter flows
  const filteredFlows = flows.filter((f) => {
    const prov = f.provenance;
    const matchesSearch =
      searchTerm === '' ||
      prov.src_ip.includes(searchTerm) ||
      prov.dst_ip.includes(searchTerm) ||
      prov.src_port.toString().includes(searchTerm) ||
      prov.dst_port.toString().includes(searchTerm) ||
      f.predicted_family.toLowerCase().includes(searchTerm.toLowerCase()) ||
      prov.protocol_name.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesStatus = statusFilter === 'all' || f.status === statusFilter;
    const matchesSeverity = severityFilter === 'all' || f.severity === severityFilter;
    const matchesAttack = attackFilter === 'all' || f.predicted_family === attackFilter;

    return matchesSearch && matchesStatus && matchesSeverity && matchesAttack;
  });

  // Sort flows
  const sortedFlows = [...filteredFlows].sort((a, b) => {
    let diff = 0;
    if (sortField === 'risk_score') {
      diff = a.risk_score - b.risk_score;
    } else if (sortField === 'confidence') {
      diff = a.class_confidence - b.class_confidence;
    } else if (sortField === 'anomaly_score') {
      diff = a.normalized_anomaly_score - b.normalized_anomaly_score;
    } else if (sortField === 'duration') {
      diff = a.provenance.duration_ms - b.provenance.duration_ms;
    } else if (sortField === 'packets') {
      diff = a.provenance.total_packets - b.provenance.total_packets;
    }
    return sortAsc ? diff : -diff;
  });

  const totalPages = Math.ceil(sortedFlows.length / pageSize) || 1;
  const paginatedFlows = sortedFlows.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const handleSort = (field: typeof sortField) => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false);
    }
  };

  // Distinct attack families in the result
  const attackFamilies = Array.from(new Set(flows.map((f) => f.predicted_family)));

  return (
    <div className="space-y-4">
      {/* Search & Filter Bar */}
      <div className="flex flex-col md:flex-row gap-3 items-center justify-between">
        <div className="relative flex-1 w-full">
          <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            placeholder="Search by IP, port, protocol, attack family..."
            value={searchTerm}
            onChange={(e) => {
              setSearchTerm(e.target.value);
              setCurrentPage(1);
            }}
            className="w-full pl-9 pr-4 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
          />
        </div>

        <div className="flex flex-wrap gap-2 w-full md:w-auto items-center">
          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-blue-500"
          >
            <option value="all">All Triage Statuses</option>
            <option value="NORMAL">NORMAL</option>
            <option value="UNKNOWN_ANOMALY">UNKNOWN_ANOMALY</option>
            <option value="KNOWN_ATTACK">KNOWN_ATTACK</option>
          </select>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-blue-500"
          >
            <option value="all">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>

          {/* Attack Family Filter */}
          <select
            value={attackFilter}
            onChange={(e) => {
              setAttackFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-blue-500"
          >
            <option value="all">All Attack Families</option>
            {attackFamilies.map((fam) => (
              <option key={fam} value={fam}>{fam}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Results Table */}
      <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-900/60 shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 font-semibold">
                <th className="py-3 px-4">Network 5-Tuple (Provenance)</th>
                <th className="py-3 px-3">Protocol</th>
                <th className="py-3 px-3">Predicted Family</th>
                <th
                  onClick={() => handleSort('confidence')}
                  className="py-3 px-3 cursor-pointer hover:text-slate-200"
                >
                  <div className="flex items-center gap-1">
                    <span>Confidence</span>
                    <ArrowUpDown className="w-3 h-3 text-slate-500" />
                  </div>
                </th>
                <th
                  onClick={() => handleSort('anomaly_score')}
                  className="py-3 px-3 cursor-pointer hover:text-slate-200"
                >
                  <div className="flex items-center gap-1">
                    <span>Anomaly (IF)</span>
                    <ArrowUpDown className="w-3 h-3 text-slate-500" />
                  </div>
                </th>
                <th
                  onClick={() => handleSort('risk_score')}
                  className="py-3 px-3 cursor-pointer hover:text-slate-200"
                >
                  <div className="flex items-center gap-1">
                    <span>Risk Score</span>
                    <ArrowUpDown className="w-3 h-3 text-slate-500" />
                  </div>
                </th>
                <th className="py-3 px-3">Status</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {paginatedFlows.map((flow) => {
                const prov = flow.provenance;
                return (
                  <tr
                    key={prov.flow_id}
                    onClick={() => onSelectFlow(flow)}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                  >
                    {/* Provenance 5-Tuple */}
                    <td className="py-3 px-4 text-slate-300">
                      <div className="font-semibold text-slate-200 flex items-center gap-1.5">
                        <span>{prov.src_ip}:{prov.src_port}</span>
                        <ArrowRight className="w-3 h-3 text-slate-500 inline" />
                        <span>{prov.dst_ip}:{prov.dst_port}</span>
                      </div>
                      <div className="text-[10px] text-slate-500 font-sans mt-0.5">
                        {prov.duration_ms} ms • {prov.total_packets} pkts • {prov.total_bytes} bytes
                      </div>
                    </td>

                    {/* Protocol */}
                    <td className="py-3 px-3">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono font-bold text-[11px]">
                        {prov.protocol_name}
                      </span>
                    </td>

                    {/* Predicted Family */}
                    <td className="py-3 px-3 font-sans">
                      <span className={`font-semibold ${flow.predicted_family !== 'BENIGN' ? 'text-red-400' : 'text-slate-300'}`}>
                        {flow.predicted_family}
                      </span>
                    </td>

                    {/* Confidence */}
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-slate-300">{formatPercent(flow.class_confidence)}</span>
                        <div className="w-12 bg-slate-800 rounded-full h-1.5 overflow-hidden">
                          <div
                            className={`h-full ${
                              flow.predicted_family !== 'BENIGN' ? 'bg-red-500' : 'bg-blue-500'
                            }`}
                            style={{ width: `${flow.class_confidence * 100}%` }}
                          />
                        </div>
                      </div>
                    </td>

                    {/* Anomaly */}
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-1.5 font-sans">
                        <span className="font-mono text-slate-300">{flow.normalized_anomaly_score.toFixed(3)}</span>
                        {flow.is_statistical_anomaly && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800/60 font-semibold font-mono">
                            α01
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Risk Score & Severity */}
                    <td className="py-3 px-3 font-sans">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-slate-200 font-mono">{flow.risk_score}</span>
                        <SeverityBadge severity={flow.severity} size="sm" />
                      </div>
                    </td>

                    {/* Triage Status */}
                    <td className="py-3 px-3 font-sans">
                      <StatusBadge status={flow.status} size="sm" />
                    </td>

                    {/* Action */}
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectFlow(flow);
                        }}
                        className="p-1.5 rounded-lg bg-slate-800 hover:bg-blue-600 text-slate-400 hover:text-white transition-colors"
                        title="Inspect 48 Canonical Features"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                );
              })}

              {paginatedFlows.length === 0 && (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 font-sans">
                    No flows found matching current filter criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        <div className="px-4 py-3 border-t border-slate-800/80 bg-slate-950/60 flex items-center justify-between text-xs text-slate-400">
          <div>
            Showing {paginatedFlows.length > 0 ? (currentPage - 1) * pageSize + 1 : 0} to{' '}
            {Math.min(currentPage * pageSize, sortedFlows.length)} of {sortedFlows.length} flows
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="px-3 py-1 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:pointer-events-none rounded-lg text-slate-300"
            >
              Previous
            </button>
            <span className="font-mono">
              Page {currentPage} of {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              className="px-3 py-1 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:pointer-events-none rounded-lg text-slate-300"
            >
              Next
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
