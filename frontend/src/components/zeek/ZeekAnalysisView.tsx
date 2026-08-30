import React, { useState } from 'react';
import { Network, Play, RefreshCw, Info, ArrowRight } from 'lucide-react';
import { zeekApi } from '../../api/zeekApi';
import { ZeekAnalysisResponse, ZeekConnectionSummary } from '../../types/zeek';
import { ZeekUploadZone } from './ZeekUploadZone';
import { ZeekSummaryCards } from './ZeekSummaryCards';
import { LoadingSpinner } from '../common/LoadingState';
import { ErrorAlert } from '../common/ErrorAlert';
import { ApiError } from '../../api/client';
import { Card } from '../common/Card';

export const ZeekAnalysisView: React.FC = () => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<ZeekAnalysisResponse | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 20;

  const handleFileSelected = (file: File) => {
    setSelectedFile(file);
    setError(null);
    setAnalysisResult(null);
    setCurrentPage(1);
  };

  const handleStartAnalysis = async () => {
    if (!selectedFile) return;

    setIsAnalyzing(true);
    setError(null);
    setAnalysisResult(null);

    try {
      const res = await zeekApi.analyzeZeekLog(selectedFile);
      setAnalysisResult(res);
    } catch (err: any) {
      setError(err);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleReset = () => {
    setSelectedFile(null);
    setAnalysisResult(null);
    setError(null);
    setCurrentPage(1);
  };

  const renderDistributionCards = (summary: ZeekAnalysisResponse['summary']) => {
    return (
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <Card title="Protocol Distribution" className="bg-slate-900/60 shadow-sm border-slate-800">
          <div className="space-y-2">
            {Object.entries(summary.protocol_distribution).sort((a, b) => b[1] - a[1]).map(([proto, count]) => (
              <div key={proto} className="flex items-center justify-between text-xs">
                <span className="text-slate-300 font-mono">{proto}</span>
                <span className="text-slate-400">{count}</span>
              </div>
            ))}
            {Object.keys(summary.protocol_distribution).length === 0 && <span className="text-slate-500 text-xs">No data</span>}
          </div>
        </Card>
        
        <Card title="Service Distribution" className="bg-slate-900/60 shadow-sm border-slate-800">
          <div className="space-y-2">
            {Object.entries(summary.service_distribution).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([service, count]) => (
              <div key={service} className="flex items-center justify-between text-xs">
                <span className="text-slate-300 font-mono">{service === '-' ? 'Unknown' : service}</span>
                <span className="text-slate-400">{count}</span>
              </div>
            ))}
            {Object.keys(summary.service_distribution).length === 0 && <span className="text-slate-500 text-xs">No data</span>}
          </div>
        </Card>

        <Card title="Conn State Distribution" className="bg-slate-900/60 shadow-sm border-slate-800">
          <div className="space-y-2">
            {Object.entries(summary.conn_state_distribution).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([state, count]) => (
              <div key={state} className="flex items-center justify-between text-xs">
                <span className="text-slate-300 font-mono">{state}</span>
                <span className="text-slate-400">{count}</span>
              </div>
            ))}
            {Object.keys(summary.conn_state_distribution).length === 0 && <span className="text-slate-500 text-xs">No data</span>}
          </div>
        </Card>
      </div>
    );
  };

  const renderTable = (connections: ZeekConnectionSummary[]) => {
    const totalPages = Math.ceil(connections.length / pageSize) || 1;
    const paginated = connections.slice((currentPage - 1) * pageSize, currentPage * pageSize);

    return (
      <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-900/60 shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 font-semibold">
                <th className="py-3 px-4">Zeek UID</th>
                <th className="py-3 px-4">Network 5-Tuple</th>
                <th className="py-3 px-3">Protocol / Service</th>
                <th className="py-3 px-3">Duration (sec)</th>
                <th className="py-3 px-3">Bytes (O/R)</th>
                <th className="py-3 px-3">Pkts (O/R)</th>
                <th className="py-3 px-3">State / History</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {paginated.map((conn) => (
                <tr key={conn.zeek_uid} className="hover:bg-slate-800/40 transition-colors">
                  <td className="py-3 px-4 text-blue-400 font-semibold">{conn.zeek_uid}</td>
                  <td className="py-3 px-4 text-slate-300">
                    <div className="flex items-center gap-1.5">
                      <span>{conn.src_ip}:{conn.src_port}</span>
                      <ArrowRight className="w-3 h-3 text-slate-500 inline" />
                      <span>{conn.dst_ip}:{conn.dst_port}</span>
                    </div>
                  </td>
                  <td className="py-3 px-3">
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-bold text-[11px] mr-1">
                      {conn.proto.toUpperCase()}
                    </span>
                    {conn.service && conn.service !== '-' && (
                      <span className="px-2 py-0.5 rounded bg-blue-950/50 text-blue-300 font-semibold text-[11px]">
                        {conn.service}
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-3 text-slate-300">
                    {conn.duration_sec !== null ? conn.duration_sec.toFixed(4) : '-'}
                  </td>
                  <td className="py-3 px-3 text-slate-300">
                    {conn.orig_bytes ?? 0} / {conn.resp_bytes ?? 0}
                  </td>
                  <td className="py-3 px-3 text-slate-300">
                    {conn.orig_pkts ?? 0} / {conn.resp_pkts ?? 0}
                  </td>
                  <td className="py-3 px-3 text-slate-300">
                    <div className="flex flex-col gap-1">
                      <span className="text-[11px]">{conn.conn_state || '-'}</span>
                      {conn.history && <span className="text-[10px] text-slate-500">{conn.history}</span>}
                    </div>
                  </td>
                </tr>
              ))}
              {paginated.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 font-sans">
                    No connections parsed.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        
        <div className="px-4 py-3 border-t border-slate-800/80 bg-slate-950/60 flex items-center justify-between text-xs text-slate-400">
          <div>
            Showing {paginated.length > 0 ? (currentPage - 1) * pageSize + 1 : 0} to{' '}
            {Math.min(currentPage * pageSize, connections.length)} of {connections.length} connections
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
    );
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <Network className="w-5 h-5 text-blue-400" />
              Zeek Native Telemetry Integration
            </h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-950 text-blue-300 border border-blue-600/40 uppercase tracking-wider">
              Stage 8
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Ingest and parse native Zeek connection logs. Connection metadata is extracted without ML classification scoring.
          </p>
        </div>

        {selectedFile && (
          <div className="flex items-center gap-2">
            <button
              onClick={handleReset}
              disabled={isAnalyzing}
              className="px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition-colors disabled:opacity-50"
            >
              Upload Different File
            </button>
            {!analysisResult && (
              <button
                onClick={handleStartAnalysis}
                disabled={isAnalyzing}
                className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-lg shadow-blue-600/20 transition-all flex items-center gap-2 disabled:opacity-50"
              >
                {isAnalyzing ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    Processing Log...
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5 fill-current" />
                    Parse Zeek Log
                  </>
                )}
              </button>
            )}
          </div>
        )}
      </div>

      {/* Upload Zone */}
      {!analysisResult && (
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 shadow-sm space-y-4">
          <ZeekUploadZone
            onFileSelected={handleFileSelected}
            isAnalyzing={isAnalyzing}
          />

          {selectedFile && !isAnalyzing && (
            <div className="flex justify-end pt-2">
              <button
                onClick={handleStartAnalysis}
                className="px-5 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-lg shadow-blue-600/20 transition-all flex items-center gap-2"
              >
                <Play className="w-4 h-4 fill-current" />
                Parse {selectedFile.name}
              </button>
            </div>
          )}
        </div>
      )}

      {/* Error Alert */}
      {error && <ErrorAlert error={error} onDismiss={() => setError(null)} />}

      {/* Loading State */}
      {isAnalyzing && (
        <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-12 text-center">
          <LoadingSpinner
            message="Parsing Zeek connection logs and validating telemetry fields..."
            size="lg"
          />
        </div>
      )}

      {/* Results View */}
      {analysisResult && (
        <div className="space-y-6 animate-in fade-in duration-200">
          
          {/* Telemetry-Only Banner */}
          <div className="flex items-start gap-3 p-3.5 bg-blue-950/40 border border-blue-800/40 rounded-xl text-blue-300 text-xs">
            <Info className="w-4 h-4 shrink-0 mt-0.5 text-blue-400" />
            <div className="space-y-0.5">
              <p className="font-semibold text-blue-200">Telemetry Only — ML Classification Not Performed</p>
              <p className="text-blue-300/80 leading-relaxed">
                This view displays native Zeek connection metadata. No attack classification, risk score, or anomaly detection has been applied to these connections.
              </p>
            </div>
          </div>

          <ZeekSummaryCards summary={analysisResult.summary} />

          {renderDistributionCards(analysisResult.summary)}

          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-slate-100">Zeek Connections</h3>
                <p className="text-xs text-slate-400">Parsed native connection logs.</p>
              </div>
              <span className="text-xs font-mono text-slate-400 bg-slate-900 px-3 py-1.5 rounded-xl border border-slate-800">
                {analysisResult.connections.length} connections
              </span>
            </div>

            {renderTable(analysisResult.connections)}
          </div>
        </div>
      )}
    </div>
  );
};
