import { useState } from 'react'
import { useGateway } from './hooks/useGateway'
import TopBar from './components/TopBar'
import StatsStrip from './components/StatsStrip'
import MonitorPage from './pages/MonitorPage'
import ScanPage from './pages/ScanPage'
import SettingsPage from './pages/SettingsPage'
import AboutPage from './pages/AboutPage'
import FeedbackPage from './pages/FeedbackPage'
import './index.css'

function App() {
  const [activeTab, setActiveTab] = useState('monitor')
  const { detections, stats, connected } = useGateway()

  return (
    <div className="app">
      <TopBar connected={connected} activeTab={activeTab} setActiveTab={setActiveTab} />
      <StatsStrip stats={stats} />
      <div style={{flex:1, overflow:'hidden', display:'flex'}}>
        {activeTab === 'monitor'  && <MonitorPage detections={detections} />}
        {activeTab === 'scan'     && <ScanPage />}
        {activeTab === 'settings' && <SettingsPage />}
        {activeTab === 'about'    && <AboutPage />}
        {activeTab === 'feedback' && <FeedbackPage />}
      </div>
    </div>
  )
}

export default App
