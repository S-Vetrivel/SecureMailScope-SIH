import { useEffect, useState } from "react";
import Sidebar from "../components/Sidebar";
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  RadialBarChart,
  RadialBar,
} from "recharts";
import {
  ShieldAlert,
  Activity,
  Lock,
  AlertTriangle,
  TrendingUp,
  Wifi,
  Cpu,
} from "lucide-react";
import { fetchDashboardSummary, fetchAIStatus } from "../lib/api";



const SEVERITY_COLORS = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#22c55e",
  INFO: "#3b82f6",
};

const TLS_COLORS = {
  "TLS 1.3": "#10b981",
  "TLS 1.2": "#3b82f6",
  "TLS 1.1": "#f59e0b",
  "TLS 1.0": "#f97316",
  SSLv3: "#ef4444",
};

function scoreColor(score) {
  if (score >= 8) return "#ef4444";
  if (score >= 6) return "#f97316";
  if (score >= 4) return "#eab308";
  if (score >= 2) return "#22c55e";
  return "#3b82f6";
}

export default function DashboardPage() {
  const [data, setData] = useState(null);
  const [aiStatus, setAiStatus] = useState(null);
  const [isLive, setIsLive] = useState(true);
  const [error, setError] = useState(false);

  useEffect(() => {
    Promise.all([fetchDashboardSummary(), fetchAIStatus().catch(() => null)])
      .then(([d, ai]) => {
        setData(d);
        if (ai) setAiStatus(ai);
        setIsLive(true);
        setError(false);
      })
      .catch(() => {
        setIsLive(false);
        setError(true);
      });
  }, []);

  if (error) {
    return (
      <div className="app-layout">
        <Sidebar />
        <main className="main-content" style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "100vh" }}>
          <div style={{ textAlign: "center", color: "var(--text-muted)" }}>
            <AlertTriangle size={48} style={{ color: "var(--accent-red)", marginBottom: 16 }} />
            <h2>Backend Offline</h2>
            <p>No live analysis data available.</p>
          </div>
        </main>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="app-layout">
        <Sidebar />
        <main className="main-content" style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "100vh" }}>
          <div className="loading-shimmer" style={{ width: 300, height: 24 }} />
        </main>
      </div>
    );
  }

  const sevData = Object.entries(data.severity_breakdown || {}).map(([name, value]) => ({
    name,
    value,
    color: SEVERITY_COLORS[name] || "#6b7280",
  }));

  const tlsData = Object.entries(data.tls_version_breakdown || {}).map(([name, value]) => ({
    name,
    value,
    color: TLS_COLORS[name] || "#6b7280",
  }));

  const protoData = Object.entries(data.protocol_breakdown || {}).map(([name, value]) => ({
    name,
    value,
  }));

  const gaugeData = [
    {
      name: "Score",
      value: data.average_score || 0,
      fill: scoreColor(data.average_score || 0),
    },
  ];

  return (
    <div className="app-layout">
      <Sidebar />
      <main className="main-content">
        <header className="app-header">
          <div>
            <h2 className="header-title">Security Dashboard</h2>
            <p className="header-breadcrumb">
              Cryptographic Security Posture Overview
            </p>
          </div>
          {/* <div className="header-actions">
            <span
              className={`status-badge ${isLive ? "completed" : "pending"}`}
            >
              <span className="status-dot" />
             {isLive ? "API Connected" : "Offline"}
            </span>
          </div> */}
        </header>

        <div className="page-content animate-in">
          {/* ====== AI Status Panel ====== */}
          {aiStatus && (
            <div className="card" style={{ marginBottom: 24, borderLeft: aiStatus.active_provider === 'none' ? '4px solid #ef4444' : aiStatus.fallback_active ? '4px solid #f97316' : '4px solid #10b981' }}>
              <div className="card-header">
                <span className="card-title">AI STATUS</span>
                <Cpu size={20} color={aiStatus.active_provider === 'none' ? '#ef4444' : aiStatus.fallback_active ? '#f97316' : '#10b981'} />
              </div>
              <div style={{ paddingBottom: 16 }}>
                {aiStatus.active_provider === 'remote' && (
                  <>
                    <h3 style={{ color: '#10b981', display: 'flex', alignItems: 'center', gap: 8 }}><span className="status-dot" style={{ background: '#10b981'}}/> Remote GPU Online</h3>
                    <p style={{ color: 'var(--text-muted)' }}>Provider: Remote Ollama</p>
                    <p style={{ color: 'var(--text-muted)' }}>Model: {aiStatus.remote.model}</p>
                    <p style={{ color: 'var(--text-muted)' }}>Latency: {aiStatus.remote.latency_ms} ms</p>
                  </>
                )}
                {aiStatus.active_provider === 'local' && (
                  <>
                    <h3 style={{ color: '#f97316', display: 'flex', alignItems: 'center', gap: 8 }}><span className="status-dot" style={{ background: '#f97316'}}/> Local Fallback Active</h3>
                    <p style={{ color: 'var(--text-muted)' }}>Provider: VPS Ollama</p>
                    <p style={{ color: 'var(--text-muted)' }}>Model: {aiStatus.local.model}</p>
                    <p style={{ color: 'var(--text-muted)' }}>Latency: {aiStatus.local.latency_ms} ms</p>
                  </>
                )}
                {aiStatus.active_provider === 'none' && (
                  <>
                    <h3 style={{ color: '#ef4444', display: 'flex', alignItems: 'center', gap: 8 }}><span className="status-dot" style={{ background: '#ef4444'}}/> AI Unavailable</h3>
                    <p style={{ color: 'var(--text-muted)' }}>Deterministic forensic analysis remains active.</p>
                  </>
                )}
              </div>
            </div>
          )}

          {/* ====== Stats Row ====== */}
          <div className="stats-grid">
            <div className="card">
              <div className="card-header">
                <span className="card-title">Security Score</span>
                <ShieldAlert
                  size={20}
                  color={scoreColor(data.average_score)}
                />
              </div>
              <div
                className="card-value"
                style={{ color: scoreColor(data.average_score) }}
              >
                {(data.average_score || 0).toFixed(1)}
              </div>
              <div className="card-subtitle">out of 10.0 (lower is better)</div>
            </div>

            <div className="card">
              <div className="card-header">
                <span className="card-title">Total Sessions</span>
                <Activity size={20} color="#3b82f6" />
              </div>
              <div className="card-value">{data.total_sessions}</div>
              <div className="card-subtitle">
                across {data.total_analyses} analyses
              </div>
            </div>

            <div className="card">
              <div className="card-header">
                <span className="card-title">Forward Secrecy</span>
                <Lock size={20} color="#10b981" />
              </div>
              <div className="card-value" style={{ color: "#10b981" }}>
                {(data.forward_secrecy_pct || 0).toFixed(1)}%
              </div>
              <div className="card-subtitle">of sessions use PFS</div>
            </div>

            <div className="card">
              <div className="card-header">
                <span className="card-title">Anomalies</span>
                <AlertTriangle size={20} color="#f59e0b" />
              </div>
              <div className="card-value" style={{ color: "#f59e0b" }}>
                {data.total_anomalies}
              </div>
              <div className="card-subtitle">
                flagged by Isolation Forest
              </div>
            </div>
          </div>

          {/* ====== Charts ====== */}
          <div className="charts-grid">
            {/* Posture Gauge */}
            <div className="card">
              <div className="card-header">
                <span className="card-title">Overall Posture</span>
                <TrendingUp size={18} color="var(--text-muted)" />
              </div>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  height: 220,
                }}
              >
                <ResponsiveContainer width="100%" height="100%">
                  <RadialBarChart
                    innerRadius="70%"
                    outerRadius="100%"
                    data={gaugeData}
                    startAngle={180}
                    endAngle={0}
                  >
                    <RadialBar
                      dataKey="value"
                      cornerRadius={10}
                      background={{ fill: "rgba(42, 48, 80, 0.3)" }}
                    />
                  </RadialBarChart>
                </ResponsiveContainer>
                <div
                  className="score-gauge"
                  style={{ position: "absolute" }}
                >
                  <div
                    className="gauge-value"
                    style={{ color: scoreColor(data.average_score) }}
                  >
                    {(data.average_score || 0).toFixed(1)}
                  </div>
                  <div className="gauge-label">Risk Score</div>
                </div>
              </div>
            </div>

            {/* TLS Version Breakdown */}
            <div className="card">
              <div className="card-header">
                <span className="card-title">TLS Version Distribution</span>
                <Wifi size={18} color="var(--text-muted)" />
              </div>
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie
                    data={tlsData}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={85}
                    paddingAngle={3}
                    dataKey="value"
                    label={({ name, percent }) =>
                      `${name} ${(percent * 100).toFixed(0)}%`
                    }
                    labelLine={false}
                  >
                    {tlsData.map((entry, idx) => (
                      <Cell key={idx} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: "#1a1f35",
                      border: "1px solid #2a3050",
                      borderRadius: "8px",
                      color: "#f1f5f9",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>

            {/* Severity Breakdown */}
            <div className="card">
              <div className="card-header">
                <span className="card-title">Risk Severity Distribution</span>
              </div>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={sevData} layout="vertical">
                  <XAxis type="number" hide />
                  <YAxis
                    type="category"
                    dataKey="name"
                    width={70}
                    tick={{ fill: "#94a3b8", fontSize: 12 }}
                  />
                  <Tooltip
                    contentStyle={{
                      background: "#1a1f35",
                      border: "1px solid #2a3050",
                      borderRadius: "8px",
                      color: "#f1f5f9",
                    }}
                  />
                  <Bar dataKey="value" radius={[0, 6, 6, 0]}>
                    {sevData.map((entry, idx) => (
                      <Cell key={idx} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            {/* Protocol Breakdown */}
            <div className="card">
              <div className="card-header">
                <span className="card-title">Protocol Distribution</span>
              </div>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={protoData}>
                  <XAxis
                    dataKey="name"
                    tick={{ fill: "#94a3b8", fontSize: 12 }}
                  />
                  <YAxis tick={{ fill: "#94a3b8", fontSize: 12 }} />
                  <Tooltip
                    contentStyle={{
                      background: "#1a1f35",
                      border: "1px solid #2a3050",
                      borderRadius: "8px",
                      color: "#f1f5f9",
                    }}
                  />
                  <Bar
                    dataKey="value"
                    fill="#3b82f6"
                    radius={[6, 6, 0, 0]}
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* ====== Recent Analyses Table ====== */}
          <div className="card" style={{ marginBottom: 24 }}>
            <div className="card-header">
              <span className="card-title">Recent Analyses</span>
            </div>
            <table className="data-table">
              <thead>
                <tr>
                  <th>PCAP File</th>
                  <th>Status</th>
                  <th>Score</th>
                  <th>Severity</th>
                  <th>Sessions</th>
                  <th>Anomalies</th>
                  <th>Date</th>
                </tr>
              </thead>
              <tbody>
                {data.recent_analyses?.map((a) => (
                  <tr key={a.id}>
                    <td className="mono">{a.pcap_filename}</td>
                    <td>
                      <span className={`status-badge ${a.status}`}>
                        <span className="status-dot" />
                        {a.status}
                      </span>
                    </td>
                    <td
                      style={{
                        fontWeight: 700,
                        color: scoreColor(a.overall_score),
                      }}
                    >
                      {(a.overall_score || 0).toFixed(1)}
                    </td>
                    <td>
                      <span
                        className={`severity-badge ${(a.overall_severity || "INFO").toLowerCase()}`}
                      >
                        {a.overall_severity || "INFO"}
                      </span>
                    </td>
                    <td>{a.total_sessions}</td>
                    <td>{a.anomaly_count}</td>
                    <td style={{ color: "var(--text-muted)", fontSize: 13 }}>
                      {new Date(a.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </main>
    </div>
  );
}
