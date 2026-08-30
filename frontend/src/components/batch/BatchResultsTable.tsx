import React, { useState } from 'react';
import { FlowPredictionResponse } from '../../types/inference';
import { FlowFeaturesInput } from '../../types/flows';
import { StatusBadge } from '../common/Badge';
import { formatPercent, formatLatency } from '../../utils/formatters';
import { Modal } from '../common/Modal';
import { Eye, Search, Filter } from 'lucide-react';

interface BatchResultsTableProps {
  predictions: FlowPredictionResponse[];
  rawFlows?: FlowFeaturesInput[];
}

export const BatchResultsTable: React.FC<BatchResultsTableProps> = ({ predictions, rawFlows }) => {
  const [search, setSearch] = useState('');
  const [filterFamily, setFilterFamily] = useState('ALL');
  const [currentPage, setCurrentPage] = useState(1);
  const [selectedFlowIndex, setSelectedFlowIndex] = useState<number | null>(null);
  const pageSize = 10;

  const families = ['ALL', ...Array.from(new Set(predictions.map((p) => p.predicted_family)))];

  const filtered = predictions.filter((p, idx) => {
    const matchFamily = filterFamily === 'ALL' || p.predicted_family === filterFamily;
    const matchSearch =
      search === '' ||
      p.predicted_family.toLowerCase().includes(search.toLowerCase()) ||
      idx.toString().includes(search);
    return matchFamily && matchSearch;
  });

  const totalPages = Math.ceil(filtered.length / pageSize) || 1;
  const pageItems = filtered.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const selectedPrediction = selectedFlowIndex !== null ? predictions[selectedFlowIndex] : null;
  const selectedRawFlow = selectedFlowIndex !== null && rawFlows ? rawFlows[selectedFlowIndex] : null;

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
      {/* Table Toolbar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search by flow ID or class..."
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setCurrentPage(1);
              }}
              className="bg-slate-950 border border-slate-700/80 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>

          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <Filter className="w-3.5 h-3.5 text-slate-500" />
            <select
              value={filterFamily}
              onChange={(e) => {
                setFilterFamily(e.target.value);
                setCurrentPage(1);
              }}
              className="bg-slate-950 border border-slate-700/80 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:ring-1 focus:ring-blue-500"
            >
              {families.map((f) => (
                <option key={f} value={f}>
                  {f === 'ALL' ? 'All Classes' : f}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="text-xs text-slate-400">
          Showing <strong className="text-slate-200">{filtered.length}</strong> of {predictions.length} flows
        </div>
      </div>

      {/* Table Element */}
      <div className="overflow-x-auto rounded-lg border border-slate-800">
        <table className="w-full text-left text-xs text-slate-300">
          <thead className="bg-slate-950/80 text-[11px] uppercase tracking-wider text-slate-400 border-b border-slate-800">
            <tr>
              <th className="px-4 py-3 font-semibold"># Flow</th>
              <th className="px-4 py-3 font-semibold">Predicted Family</th>
              <th className="px-4 py-3 font-semibold">Confidence</th>
              <th className="px-4 py-3 font-semibold">Norm. Anomaly</th>
              <th className="px-4 py-3 font-semibold">Statistical Anomaly</th>
              <th className="px-4 py-3 font-semibold">Latency</th>
              <th className="px-4 py-3 font-semibold text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            {pageItems.map((p, idx) => {
              const globalIdx = predictions.indexOf(p);
              const isBenign = p.predicted_family === 'BENIGN';

              return (
                <tr key={globalIdx} className="hover:bg-slate-800/40 transition-colors">
                  <td className="px-4 py-2.5 font-bold text-slate-400">#{globalIdx + 1}</td>
                  <td className="px-4 py-2.5 font-sans">
                    <span
                      className={`inline-flex px-2 py-0.5 rounded text-xs font-semibold ${
                        isBenign
                          ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-800/50'
                          : 'bg-red-950/70 text-red-300 border border-red-800/60'
                      }`}
                    >
                      {p.predicted_family}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">{formatPercent(p.class_confidence)}</td>
                  <td className="px-4 py-2.5 text-purple-300">{p.normalized_anomaly_score.toFixed(4)}</td>
                  <td className="px-4 py-2.5 font-sans">
                    {p.is_statistical_anomaly ? (
                      <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-700/50">
                        FLAGGED (α=0.01)
                      </span>
                    ) : (
                      <span className="text-[10px] text-slate-500">Normal</span>
                    )}
                  </td>
                  <td className="px-4 py-2.5 text-slate-400">{formatLatency(p.inference_latency_ms)}</td>
                  <td className="px-4 py-2.5 text-right font-sans">
                    <button
                      onClick={() => setSelectedFlowIndex(globalIdx)}
                      className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors"
                      title="Inspect Flow Telemetry"
                    >
                      <Eye className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Pagination Controls */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between text-xs text-slate-400 pt-2">
          <span>Page {currentPage} of {totalPages}</span>
          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200"
            >
              Previous
            </button>
            <button
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200"
            >
              Next
            </button>
          </div>
        </div>
      )}

      {/* Flow Detail Modal */}
      {selectedPrediction && (
        <Modal
          isOpen={selectedFlowIndex !== null}
          onClose={() => setSelectedFlowIndex(null)}
          title={`Detailed Telemetry — Flow #${selectedFlowIndex! + 1}`}
          maxWidth="3xl"
        >
          <div className="space-y-4 text-xs">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-slate-950 p-3.5 rounded-xl border border-slate-800">
              <div>
                <span className="text-[10px] text-slate-500 uppercase font-semibold">Predicted Class</span>
                <p className="text-sm font-bold text-slate-100 font-sans">{selectedPrediction.predicted_family}</p>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase font-semibold">Confidence</span>
                <p className="text-sm font-bold font-mono text-emerald-400">{formatPercent(selectedPrediction.class_confidence)}</p>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase font-semibold">Normalized Anomaly</span>
                <p className="text-sm font-bold font-mono text-purple-300">{selectedPrediction.normalized_anomaly_score.toFixed(4)}</p>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase font-semibold">Raw Decision Score</span>
                <p className="text-sm font-bold font-mono text-slate-300">{selectedPrediction.raw_decision_score.toFixed(5)}</p>
              </div>
            </div>

            {selectedRawFlow && (
              <div className="space-y-2">
                <span className="font-semibold text-slate-200 uppercase tracking-wider text-[11px]">
                  Raw 48-Feature Input Vector
                </span>
                <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 max-h-64 overflow-y-auto font-mono text-[11px] grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {Object.entries(selectedRawFlow).map(([k, v]) => (
                    <div key={k} className="flex justify-between border-b border-slate-900 pb-1">
                      <span className="text-slate-400">{k}:</span>
                      <span className="text-blue-300 font-bold">{v}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </Modal>
      )}
    </div>
  );
};
