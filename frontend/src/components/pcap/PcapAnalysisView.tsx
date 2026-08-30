import React, { useState } from 'react';
import { FileCode2, Play, RefreshCw, AlertCircle, Info, Download } from 'lucide-react';
import { pcapApi } from '../../api/pcapApi';
import { PcapAnalysisResponse, PcapFlowResult } from '../../types/pcap';
import { PcapUploadZone } from './PcapUploadZone';
import { PcapSummaryCards } from './PcapSummaryCards';
import { PcapFlowTable } from './PcapFlowTable';
import { PcapFlowDetailModal } from './PcapFlowDetailModal';
import { LoadingSpinner } from '../common/LoadingState';
import { ErrorAlert } from '../common/ErrorAlert';
import { ApiError } from '../../api/client';

export const PcapAnalysisView: React.FC = () => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<PcapAnalysisResponse | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [selectedFlowForModal, setSelectedFlowForModal] = useState<PcapFlowResult | null>(null);

  const handleFileSelected = (file: File) => {
    setSelectedFile(file);
    setError(null);
    setAnalysisResult(null);
  };

  const handleStartAnalysis = async () => {
    if (!selectedFile) return;

    setIsAnalyzing(true);
    setError(null);
    setAnalysisResult(null);

    try {
      const res = await pcapApi.analyzePcap(selectedFile);
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
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <FileCode2 className="w-5 h-5 text-blue-400" />
              PCAP File Analysis Engine
            </h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-950 text-blue-300 border border-blue-600/40 uppercase tracking-wider">
              Stage 6B
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Reconstruct stateful bidirectional network flows from raw packet captures, extract 48 canonical CICFlowMeter features, and run automated ML threat triage.
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
                    Analyzing PCAP...
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5 fill-current" />
                    Run Pipeline Analysis
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
          <PcapUploadZone
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
                Analyze {selectedFile.name}
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
            message="Parsing raw packets, accumulating bidirectional state, extracting canonical 48 features, and executing XGBoost + Isolation Forest inference..."
            size="lg"
          />
        </div>
      )}

      {/* Results View */}
      {analysisResult && (
        <div className="space-y-6 animate-in fade-in duration-200">
          {/* Summary KPIs */}
          <PcapSummaryCards summary={analysisResult.summary} />

          {/* Validation Notice Banner */}
          <div className="flex items-start gap-3 p-3.5 bg-blue-950/40 border border-blue-800/40 rounded-xl text-blue-300 text-xs">
            <Info className="w-4 h-4 shrink-0 mt-0.5 text-blue-400" />
            <div className="space-y-0.5">
              <p className="font-semibold text-blue-200">Validated Stage 6A Reconstruction Engine</p>
              <p className="text-blue-300/80 leading-relaxed">
                Reconstructed flow features conform to verified transport payload semantics (Stage 6A 617-flow / 99.84% XGBoost empirical compatibility). Isolation Forest provides unsupervised anomaly scoring.
              </p>
            </div>
          </div>

          {/* Flow Table */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-slate-100">Reconstructed Network Flows</h3>
                <p className="text-xs text-slate-400">Click any row to inspect the full 48 canonical feature vector.</p>
              </div>
              <span className="text-xs font-mono text-slate-400 bg-slate-900 px-3 py-1.5 rounded-xl border border-slate-800">
                {analysisResult.flows.length} analyzed flows
              </span>
            </div>

            <PcapFlowTable
              flows={analysisResult.flows}
              onSelectFlow={(flow) => setSelectedFlowForModal(flow)}
            />
          </div>
        </div>
      )}

      {/* Flow Detail Modal */}
      <PcapFlowDetailModal
        flow={selectedFlowForModal}
        onClose={() => setSelectedFlowForModal(null)}
      />
    </div>
  );
};
