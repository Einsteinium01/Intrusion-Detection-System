import React, { useState } from 'react';
import { MonitoringProvider } from './context/MonitoringContext';
import Sidebar from './components/Sidebar';
import TopBar from './components/TopBar';
import DashboardPage from './pages/DashboardPage';
import LiveTrafficPage from './pages/LiveTrafficPage';
import ThreatsPage from './pages/ThreatsPage';
import NetworkFlowsPage from './pages/NetworkFlowsPage';
import AnalyticsPage from './pages/AnalyticsPage';
import LogsPage from './pages/LogsPage';
import SettingsPage from './pages/SettingsPage';
import AiChatOverlay from './components/AiChatOverlay';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');

  const renderActiveModule = () => {
    switch (activeTab) {
      case 'dashboard':
        return <DashboardPage />;
      case 'live-traffic':
        return <LiveTrafficPage />;
      case 'threats':
        return <ThreatsPage />;
      case 'flows':
        return <NetworkFlowsPage />;
      case 'analytics':
        return <AnalyticsPage />;
      case 'logs':
        return <LogsPage />;
      case 'settings':
      case 'support':
        return <SettingsPage />;
      default:
        return <DashboardPage />;
    }
  };

  return (
    <MonitoringProvider>
      <div className="h-screen w-screen bg-[#090D13] text-[#F4F7FB] flex overflow-hidden antialiased">
        {/* Fixed Left Sidebar (248px) */}
        <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />

        {/* Main Viewport Container */}
        <div className="flex-1 ml-[248px] flex flex-col h-full min-w-0 overflow-hidden">
          {/* Sticky TopBar */}
          <TopBar setActiveTab={setActiveTab} />

          {/* Main Content Canvas */}
          <main className="flex-1 p-4 lg:p-5 overflow-hidden flex flex-col min-h-0">
            {renderActiveModule()}
          </main>
        </div>

        {/* Global Floating AI Security Copilot Overlay */}
        <AiChatOverlay />
      </div>
    </MonitoringProvider>
  );
}

