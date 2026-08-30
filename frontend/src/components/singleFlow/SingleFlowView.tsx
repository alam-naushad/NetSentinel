import React, { useState } from 'react';
import { Play, RotateCcw, Copy, Check, SlidersHorizontal } from 'lucide-react';
import { inferenceApi } from '../../api/inferenceApi';
import { useApp } from '../../context/useApp';
import { ContextualSignals, FlowFeaturesInput } from '../../types/flows';
import { EvaluateFlowResponse } from '../../types/inference';
import { FLOW_PRESETS, FlowPreset } from '../../utils/flowPresets';
import { ErrorAlert } from '../common/ErrorAlert';
import { LoadingSpinner } from '../common/LoadingState';
import { ContextualSignalsForm } from './ContextualSignalsForm';
import { FlowFeatureEditor } from './FlowFeatureEditor';
import { HybridDecisionBanner } from './HybridDecisionBanner';
import { PredictionResultCard } from './PredictionResultCard';
import { AnomalyScoreVisualizer } from './AnomalyScoreVisualizer';
import { PresetSelector } from './PresetSelector';

export const SingleFlowView: React.FC = () => {
  const { selectedSupervisedKey, selectedAnomalyKey, addSessionEvaluation, modelsCatalog, setSelectedSupervisedKey, setSelectedAnomalyKey } = useApp();
  const [selectedPresetId, setSelectedPresetId] = useState<string | null>(FLOW_PRESETS[0].id);
  const [features, setFeatures] = useState<FlowFeaturesInput>({ ...FLOW_PRESETS[0].flow });
  const [context, setContext] = useState<ContextualSignals>({ repeated_source_events: 0, targets_sensitive_service: false });
  const [isEvaluating, setIsEvaluating] = useState(false);
  const [evaluationResult, setEvaluationResult] = useState<EvaluateFlowResponse | null>(null);
  const [error, setError] = useState<any>(null);
  const [copied, setCopied] = useState(false);

  const handleSelectPreset = (preset: FlowPreset) => {
    setSelectedPresetId(preset.id);
    setFeatures({ ...preset.flow });
    setError(null);
  };

  const handleFeatureChange = (key: keyof FlowFeaturesInput, value: number) => {
    setFeatures((prev) => ({ ...prev, [key]: value }));
    setSelectedPresetId(null);
  };

  const handleEvaluate = async () => {
    setIsEvaluating(true);
    setError(null);
    try {
      const res = await inferenceApi.evaluateDecision({
        flow: features,
        context,
        supervised_model_key: selectedSupervisedKey,
        anomaly_model_key: selectedAnomalyKey,
      });
      setEvaluationResult(res);
      addSessionEvaluation({
        id: `eval-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
        timestamp: new Date().toISOString(),
        flow: features,
        context,
        prediction: res.prediction,
        decision: res.decision,
      });
    } catch (err: any) {
      setError(err);
    } finally {
      setIsEvaluating(false);
    }
  };

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(features, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-black text-slate-100 tracking-tight flex items-center gap-2">
            <SlidersHorizontal className="w-5 h-5 text-blue-400" />
            Single-Flow Telemetry Analysis
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Inspect canonical 48-feature network flow vectors, execute model inference, and evaluate hybrid risk triage.
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

      {/* Preset Selector */}
      <PresetSelector selectedPresetId={selectedPresetId} onSelectPreset={handleSelectPreset} />

      {/* Error Alert */}
      {error && <ErrorAlert error={error} onDismiss={() => setError(null)} />}

      {/* Action Toolbar */}
      <div className="flex items-center justify-between bg-slate-900/80 border border-slate-800 p-3 rounded-xl">
        <div className="flex items-center gap-2">
          <button
            onClick={handleCopyJson}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition-colors"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
            {copied ? 'Copied JSON' : 'Copy Flow JSON'}
          </button>
        </div>

        <button
          onClick={handleEvaluate}
          disabled={isEvaluating}
          className="flex items-center gap-2 px-5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold shadow-lg shadow-blue-600/30 transition-all disabled:opacity-50"
        >
          {isEvaluating ? (
            <>
              <LoadingSpinner size="sm" />
              <span>Evaluating Models...</span>
            </>
          ) : (
            <>
              <Play className="w-4 h-4 fill-current" />
              <span>Execute ML Inference &amp; Evaluate Triage</span>
            </>
          )}
        </button>
      </div>

      {/* Evaluation Results Banner & Cards */}
      {evaluationResult && (
        <div className="space-y-6">
          <HybridDecisionBanner decision={evaluationResult.decision} />
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <PredictionResultCard prediction={evaluationResult.prediction} />
            <AnomalyScoreVisualizer prediction={evaluationResult.prediction} />
          </div>
        </div>
      )}

      {/* Contextual Signals Modifier Form */}
      <ContextualSignalsForm context={context} onChange={setContext} />

      {/* 48-Feature Editor */}
      <div className="space-y-2">
        <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">
          Flow Telemetry Vector (48 Model Features)
        </h3>
        <FlowFeatureEditor features={features} onChange={handleFeatureChange} />
      </div>
    </div>
  );
};
