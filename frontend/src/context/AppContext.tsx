import React, { createContext, useContext, useEffect, useState } from 'react';
import { healthApi } from '../api/healthApi';
import { modelsApi } from '../api/modelsApi';
import { SessionEvaluationRecord } from '../types/inference';
import { ModelCatalogResponse, ModelMetadata } from '../types/models';

interface AppContextType {
  backendConnected: boolean;
  serviceInfo: string | null;
  modelsCatalog: ModelCatalogResponse | null;
  selectedSupervisedKey: string;
  selectedAnomalyKey: string;
  setSelectedSupervisedKey: (key: string) => void;
  setSelectedAnomalyKey: (key: string) => void;
  sessionEvaluations: SessionEvaluationRecord[];
  addSessionEvaluation: (record: SessionEvaluationRecord) => void;
  addSessionBatchEvaluations: (records: SessionEvaluationRecord[]) => void;
  clearSessionEvaluations: () => void;
  refreshHealth: () => Promise<void>;
  refreshModels: () => Promise<void>;
  isLoadingCatalog: boolean;
}

const AppContext = createContext<AppContextType | undefined>(undefined);

const MAX_SESSION_BUFFER = 500;

export const AppProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [backendConnected, setBackendConnected] = useState(false);
  const [serviceInfo, setServiceInfo] = useState<string | null>(null);
  const [modelsCatalog, setModelsCatalog] = useState<ModelCatalogResponse | null>(null);
  const [selectedSupervisedKey, setSelectedSupervisedKey] = useState<string>('protocol_a_xgboost_k48');
  const [selectedAnomalyKey, setSelectedAnomalyKey] = useState<string>('protocol_a_isolationforest_k48');
  const [sessionEvaluations, setSessionEvaluations] = useState<SessionEvaluationRecord[]>([]);
  const [isLoadingCatalog, setIsLoadingCatalog] = useState(true);

  const refreshHealth = async () => {
    try {
      const res = await healthApi.getHealth();
      setBackendConnected(res.status === 'ok');
      setServiceInfo(res.service);
    } catch {
      setBackendConnected(false);
      setServiceInfo(null);
    }
  };

  const refreshModels = async () => {
    setIsLoadingCatalog(true);
    try {
      const cat = await modelsApi.getCatalog();
      setModelsCatalog(cat);
      if (cat.default_supervised_model && !selectedSupervisedKey) {
        setSelectedSupervisedKey(cat.default_supervised_model);
      }
      if (cat.default_anomaly_model && !selectedAnomalyKey) {
        setSelectedAnomalyKey(cat.default_anomaly_model);
      }
      setBackendConnected(true);
    } catch {
      setBackendConnected(false);
    } finally {
      setIsLoadingCatalog(false);
    }
  };

  useEffect(() => {
    refreshHealth();
    refreshModels();
    const interval = setInterval(refreshHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  const addSessionEvaluation = (record: SessionEvaluationRecord) => {
    setSessionEvaluations((prev) => [record, ...prev].slice(0, MAX_SESSION_BUFFER));
  };

  const addSessionBatchEvaluations = (records: SessionEvaluationRecord[]) => {
    setSessionEvaluations((prev) => [...records, ...prev].slice(0, MAX_SESSION_BUFFER));
  };

  const clearSessionEvaluations = () => {
    setSessionEvaluations([]);
  };

  return (
    <AppContext.Provider
      value={{
        backendConnected,
        serviceInfo,
        modelsCatalog,
        selectedSupervisedKey,
        selectedAnomalyKey,
        setSelectedSupervisedKey,
        setSelectedAnomalyKey,
        sessionEvaluations,
        addSessionEvaluation,
        addSessionBatchEvaluations,
        clearSessionEvaluations,
        refreshHealth,
        refreshModels,
        isLoadingCatalog,
      }}
    >
      {children}
    </AppContext.Provider>
  );
};

export const useApp = (): AppContextType => {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error('useApp must be used within an AppProvider');
  }
  return context;
};
