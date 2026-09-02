import React, { useState } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { AppProvider } from './context/AppContext';
import { Layout } from './components/layout/Layout';
import { TabId } from './components/layout/Sidebar';
import { LoginView } from './components/auth/LoginView';
import { OverviewView } from './components/overview/OverviewView';
import { SingleFlowView } from './components/singleFlow/SingleFlowView';
import { BatchView } from './components/batch/BatchView';
import { ModelsView } from './components/models/ModelsView';
import { AnalyticsView } from './components/analytics/AnalyticsView';
import { PcapAnalysisView } from './components/pcap/PcapAnalysisView';
import { ZeekAnalysisView } from './components/zeek/ZeekAnalysisView';
import { ZeekLiveView } from './components/zeek/ZeekLiveView';
import { AlertsView } from './components/alerts/AlertsView';
import { HistoricalEventsView } from './components/history/HistoricalEventsView';
import { ShieldAlert, Loader2 } from 'lucide-react';

function AppContent() {
  const { isAuthenticated, isLoading } = useAuth();
  const [activeTab, setActiveTab] = useState<TabId>('overview');

  if (isLoading) {
    return (
      <div className="min-h-screen w-full bg-slate-950 flex flex-col items-center justify-center p-4">
        <div className="flex flex-col items-center gap-4 text-center">
          <div className="p-4 rounded-2xl bg-blue-600/10 border border-blue-500/20 text-blue-400 animate-pulse">
            <ShieldAlert className="w-10 h-10" />
          </div>
          <div className="flex items-center gap-2 text-slate-300 text-sm font-semibold">
            <Loader2 className="w-4 h-4 animate-spin text-blue-400" />
            <span>Validating SOC Security Clearance...</span>
          </div>
          <p className="text-xs text-slate-500 font-mono">NetSentinel Hybrid Detection Platform</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <LoginView />;
  }

  return (
    <AppProvider>
      <Layout activeTab={activeTab} onSelectTab={setActiveTab}>
        {activeTab === 'overview' && <OverviewView onNavigateTab={setActiveTab} />}
        {activeTab === 'alerts' && <AlertsView />}
        {activeTab === 'single' && <SingleFlowView />}
        {activeTab === 'batch' && <BatchView />}
        {activeTab === 'pcap' && <PcapAnalysisView />}
        {activeTab === 'zeek' && <ZeekAnalysisView />}
        {activeTab === 'zeek-live' && <ZeekLiveView />}
        {activeTab === 'history' && <HistoricalEventsView />}
        {activeTab === 'models' && <ModelsView />}
        {activeTab === 'analytics' && <AnalyticsView />}
      </Layout>
    </AppProvider>
  );
}

export function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}

export default App;
