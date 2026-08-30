import React, { useState } from 'react';
import { AppProvider } from './context/AppContext';
import { Layout } from './components/layout/Layout';
import { TabId } from './components/layout/Sidebar';
import { OverviewView } from './components/overview/OverviewView';
import { SingleFlowView } from './components/singleFlow/SingleFlowView';
import { BatchView } from './components/batch/BatchView';
import { ModelsView } from './components/models/ModelsView';
import { AnalyticsView } from './components/analytics/AnalyticsView';
import { PcapAnalysisView } from './components/pcap/PcapAnalysisView';
import { ZeekAnalysisView } from './components/zeek/ZeekAnalysisView';
import { AlertsView } from './components/alerts/AlertsView';
import { HistoricalEventsView } from './components/history/HistoricalEventsView';

export function App() {
  const [activeTab, setActiveTab] = useState<TabId>('overview');

  return (
    <AppProvider>
      <Layout activeTab={activeTab} onSelectTab={setActiveTab}>
        {activeTab === 'overview' && <OverviewView onNavigateTab={setActiveTab} />}
        {activeTab === 'alerts' && <AlertsView />}
        {activeTab === 'single' && <SingleFlowView />}
        {activeTab === 'batch' && <BatchView />}
        {activeTab === 'pcap' && <PcapAnalysisView />}
        {activeTab === 'zeek' && <ZeekAnalysisView />}
        {activeTab === 'history' && <HistoricalEventsView />}
        {activeTab === 'models' && <ModelsView />}
        {activeTab === 'analytics' && <AnalyticsView />}
      </Layout>
    </AppProvider>
  );
}

export default App;
