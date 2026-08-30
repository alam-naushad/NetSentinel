import React from 'react';
import { Header } from './Header';
import { Sidebar, TabId } from './Sidebar';

interface LayoutProps {
  activeTab: TabId;
  onSelectTab: (tab: TabId) => void;
  children: React.ReactNode;
}

export const Layout: React.FC<LayoutProps> = ({ activeTab, onSelectTab, children }) => {
  return (
    <div className="min-h-screen bg-[#0a0e17] text-slate-100 flex flex-col">
      <Header />
      <div className="flex flex-1">
        <Sidebar activeTab={activeTab} onSelectTab={onSelectTab} />
        <main className="flex-1 p-6 lg:p-8 max-w-7xl mx-auto w-full overflow-y-auto">
          {children}
        </main>
      </div>
    </div>
  );
};
