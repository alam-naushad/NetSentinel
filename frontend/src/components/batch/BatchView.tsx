import React, { useState } from 'react';
import { Layers, Play, Database } from 'lucide-react';
import { inferenceApi } from '../../api/inferenceApi';
import { useApp } from '../../context/useApp';
import { FlowFeaturesInput } from '../../types/flows';
import { BatchFlowInferenceResponse } from '../../types/inference';
import { FLOW_PRESETS } from '../../utils/flowPresets';
import { ErrorAlert } from '../common/ErrorAlert';
import { LoadingSpinner } from '../common/LoadingState';
import { BatchAnomalyScatter } from './BatchAnomalyScatter';
import { BatchPresetLoader } from './BatchPresetLoader';
import { BatchResultsTable } from './BatchResultsTable';
import { BatchSummaryStats } from './BatchSummaryStats';

export const BatchView: React.FC = () => {
  const { selectedSupervisedKey, selectedAnomalyKey, addSessionBatchEvaluations, modelsCatalog, setSelectedSupervisedKey, setSelectedAnomalyKey } = useApp();
  const [batchFlows, setBatchFlows] = useState<FlowFeaturesInput[]>(FLOW_PRESETS.slice(0, 4).map((p) => p.flow));
  const [batchLabel, setBatchLabel] = useState<string>('4-Flow Authentic Dataset Benchmark');
  const [isExecuting, setIsExecuting] = useState(false);
  const [batchResult, setBatchResult] = useState<BatchFlowInferenceResponse | null>(null);
  const [error, setError] = useState<any>(null);

  const handleLoadBatch = (flows: FlowFeaturesInput[], label: string) => {
    setBatchFlows(flows);
    setBatchLabel(label);
    setBatchResult(null);
    setError(null);
  };

  const handleExecuteBatch = async () => {
    if (batchFlows.length === 0) return;
    setIsExecuting(true);
    setError(null);

    try {
      const res = await inferenceApi.predictBatch({
        flows: batchFlows,
        supervised_model_key: selectedSupervisedKey,
        anomaly_model_key: selectedAnomalyKey,
      });
      setBatchResult(res);

      // Record batch evaluations into session buffer
      const sessionRecords = res.predictions.map((p, idx) => ({
        id: `batch-${Date.now()}-${idx}`,
        timestamp: new Date().toISOString(),
        flow: batchFlows[idx],
        context: {},
        prediction: p,
        decision: {
          status: (p.predicted_family !== 'BENIGN' && p.class_confidence >= 0.80)
            ? ('KNOWN_ATTACK' as const)
            : (p.normalized_anomaly_score >= 0.70 || p.is_statistical_anomaly)
            ? ('UNKNOWN_ANOMALY' as const)
            : ('NORMAL' as const),
          severity: p.predicted_family !== 'BENIGN' ? ('HIGH' as const) : ('LOW' as const),
          risk_score: p.predicted_family !== 'BENIGN' ? 75 : 15,
          explanation: `Batch prediction for ${p.predicted_family}`,
          policy_version: 'batch-preview-v1.0',
        },
      }));
      addSessionBatchEvaluations(sessionRecords);
    } catch (err: any) {
      setError(err);
    } finally {
      setIsExecuting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-black text-slate-100 tracking-tight flex items-center gap-2">
            <Layers className="w-5 h-5 text-blue-400" />
            Vectorized Batch Flow Analysis
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Process high-volume network flow batches (up to 5,000 flows) with SIMD-vectorized multi-model execution.
          </p>
        </div>

        {/* Model Selectors */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 text-xs">
            <span className="text-slate-400">Classifier:</span>
            <select
              value={selectedSupervisedKey}
              onChange={(e) => setSelectedSupervisedKey(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:ring-1 focus:ring-blue-500"
            >
              {modelsCatalog?.models
                .filter((m) => m.model_role === 'SUPERVISED_CLASSIFIER')
                .map((m) => (
                  <option key={m.model_key} value={m.model_key}>
                    {m.model_key}
                  </option>
                ))}
            </select>
          </div>

          <div className="flex items-center gap-2 text-xs">
            <span className="text-slate-400">Anomaly Detector:</span>
            <select
              value={selectedAnomalyKey}
              onChange={(e) => setSelectedAnomalyKey(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:ring-1 focus:ring-purple-500"
            >
              {modelsCatalog?.models
                .filter((m) => m.model_role === 'STATISTICAL_ANOMALY_DETECTOR')
                .map((m) => (
                  <option key={m.model_key} value={m.model_key}>
                    {m.model_key}
                  </option>
                ))}
            </select>
          </div>
        </div>
      </div>

      {/* Preset & File Loader */}
      <BatchPresetLoader onLoadBatch={handleLoadBatch} isLoading={isExecuting} />

      {/* Action Toolbar */}
      <div className="flex items-center justify-between bg-slate-900/80 border border-slate-800 p-4 rounded-xl">
        <div>
          <span className="text-xs font-bold text-slate-200 uppercase tracking-wider">Active Batch</span>
          <p className="text-xs text-blue-400 font-medium">{batchLabel} ({batchFlows.length} flows loaded)</p>
        </div>

        <button
          onClick={handleExecuteBatch}
          disabled={isExecuting || batchFlows.length === 0}
          className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold shadow-lg shadow-blue-600/30 transition-all disabled:opacity-50"
        >
          {isExecuting ? (
            <>
              <LoadingSpinner size="sm" />
              <span>Executing Batch ({batchFlows.length} flows)...</span>
            </>
          ) : (
            <>
              <Play className="w-4 h-4 fill-current" />
              <span>Execute Vectorized Batch Inference</span>
            </>
          )}
        </button>
      </div>

      {/* Error Alert */}
      {error && <ErrorAlert error={error} onDismiss={() => setError(null)} />}

      {/* Results Display */}
      {batchResult && (
        <div className="space-y-6">
          <BatchSummaryStats result={batchResult} />
          <BatchAnomalyScatter predictions={batchResult.predictions} />
          <BatchResultsTable predictions={batchResult.predictions} rawFlows={batchFlows} />
        </div>
      )}
    </div>
  );
};
