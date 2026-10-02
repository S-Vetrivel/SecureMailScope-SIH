import { useState, useEffect } from "react";
import Sidebar from "../components/Sidebar";
import { Play, Square, Activity, Wifi, ShieldAlert, CheckCircle, Database } from "lucide-react";
import { fetchCaptureStatus, fetchInterfaces, startCapture, stopCapture, WS_URL } from "../lib/api";

export default function LiveSensorPage() {
  const [status, setStatus] = useState(null);
  const [interfaces, setInterfaces] = useState([]);
  const [selectedIface, setSelectedIface] = useState("");
  const [events, setEvents] = useState([]);
  const [error, setError] = useState(null);
  
  const refreshStatus = () => {
    fetchCaptureStatus().then(res => setStatus(res)).catch(console.error);
  };

  useEffect(() => {
    fetchInterfaces().then(res => {
      setInterfaces(res.interfaces || []);
      if (res.interfaces && res.interfaces.length > 0) {
        setSelectedIface(res.interfaces[0].name);
      }
    }).catch(console.error);
    refreshStatus();
    const interval = setInterval(refreshStatus, 2000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const ws = new WebSocket(`${WS_URL}/analyses/live/events`);
    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type) {
           setEvents(prev => [msg, ...prev].slice(0, 100)); // Keep last 100 events
        }
      } catch (err) {}
    };
    return () => ws.close();
  }, []);

  const handleStart = async () => {
    try {
      await startCapture(selectedIface);
      refreshStatus();
    } catch (e) {
      setError(e.message || "Failed to start capture");
    }
  };

  const handleStop = async () => {
    try {
      await stopCapture();
      refreshStatus();
    } catch (e) {
      setError(e.message || "Failed to stop capture");
    }
  };

  const isCapturing = status?.status === "ACTIVE";

  return (
    <div className="app-layout">
      <Sidebar />
      <main className="main-content">
        <header className="app-header">
          <div>
            <h2 className="header-title">Live Sensor</h2>
            <p className="header-breadcrumb">Production Passive Network Capture</p>
          </div>
          <div className="header-actions">
            {isCapturing ? (
              <span className="status-badge ACTIVE"><span className="status-dot" />CAPTURING</span>
            ) : (
              <span className="status-badge"><span className="status-dot" style={{background: 'gray'}}/>STOPPED</span>
            )}
          </div>
        </header>

        <div className="page-content animate-in">
          {error && (
             <div className="card" style={{borderColor: 'var(--accent-red)', marginBottom: 20}}>
               <div style={{color: 'var(--accent-red)'}}>{error}</div>
             </div>
          )}

          <div className="card" style={{ marginBottom: 24, display: 'flex', gap: 16, alignItems: 'flex-end' }}>
             <div style={{ flex: 1 }}>
               <label style={{ display: 'block', marginBottom: 8, fontSize: 14, color: 'var(--text-muted)' }}>Capture Interface</label>
               <select 
                 value={selectedIface} 
                 onChange={e => setSelectedIface(e.target.value)}
                 disabled={isCapturing}
                 style={{ width: '100%', padding: '10px 12px', background: 'var(--card-bg)', border: '1px solid var(--border)', color: 'white', borderRadius: 6 }}
               >
                 {interfaces.map(i => <option key={i.name} value={i.name}>{i.name} ({i.type})</option>)}
               </select>
             </div>
             <div>
               {!isCapturing ? (
                 <button className="btn btn-primary" onClick={handleStart} style={{ height: 42, display: 'flex', alignItems: 'center', gap: 8 }}>
                   <Play size={16} /> START LIVE CAPTURE
                 </button>
               ) : (
                 <button className="btn" onClick={handleStop} style={{ height: 42, background: 'var(--accent-red)', color: 'white', display: 'flex', alignItems: 'center', gap: 8 }}>
                   <Square size={16} /> STOP LIVE CAPTURE
                 </button>
               )}
             </div>
          </div>

          <div className="stats-grid" style={{ marginBottom: 24 }}>
            <div className="card">
              <div className="card-header">
                <span className="card-title">Status</span>
                <Activity size={20} color={isCapturing ? "#10b981" : "#6b7280"} />
              </div>
              <div className="card-value" style={{ color: isCapturing ? "#10b981" : "#6b7280" }}>{status?.status || "UNKNOWN"}</div>
              <div className="card-subtitle">Interface: {status?.interface || "-"}</div>
            </div>
            
            <div className="card">
              <div className="card-header">
                <span className="card-title">Packets Captured</span>
                <Database size={20} color="#3b82f6" />
              </div>
              <div className="card-value">{status?.packets_captured || 0}</div>
              <div className="card-subtitle">{(status?.packets_per_sec || 0)} packets/sec</div>
            </div>

            <div className="card">
              <div className="card-header">
                <span className="card-title">Bytes Captured</span>
                <Wifi size={20} color="#8b5cf6" />
              </div>
              <div className="card-value">{( (status?.bytes_captured || 0) / 1024 / 1024 ).toFixed(2)} MB</div>
              <div className="card-subtitle">Current Chunk: {status?.current_chunk || "-"}</div>
            </div>

            <div className="card">
              <div className="card-header">
                <span className="card-title">Analysis Queue</span>
                <CheckCircle size={20} color="#f59e0b" />
              </div>
              <div className="card-value">{status?.queue_depth || 0}</div>
              <div className="card-subtitle">{status?.analyzer_workers || 0} workers active</div>
            </div>
          </div>

          <div className="card">
             <div className="card-header">
               <span className="card-title">Real-Time Event Feed</span>
             </div>
             <div style={{ background: '#0f172a', borderRadius: 8, padding: 16, height: 400, overflowY: 'auto', fontFamily: 'monospace', fontSize: 13 }}>
               {events.length === 0 ? (
                 <div style={{ color: 'var(--text-muted)', textAlign: 'center', marginTop: 100 }}>No live events yet.</div>
               ) : (
                 events.map((evt, idx) => (
                   <div key={idx} style={{ marginBottom: 8, paddingBottom: 8, borderBottom: '1px solid #1e293b' }}>
                     <span style={{ color: '#3b82f6' }}>[{new Date().toLocaleTimeString()}]</span>{" "}
                     <strong style={{ color: '#f1f5f9' }}>{evt.type}</strong>{" "}
                     <span style={{ color: '#94a3b8' }}>{JSON.stringify(evt.data)}</span>
                   </div>
                 ))
               )}
             </div>
          </div>

        </div>
      </main>
    </div>
  );
}
