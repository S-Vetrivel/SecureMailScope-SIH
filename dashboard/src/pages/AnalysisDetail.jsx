import { useEffect, useState } from "react";
import Sidebar from "../components/Sidebar";
import { useParams } from "react-router-dom";
import {
  Shield,
  AlertTriangle,
  Lock,
  Unlock,
  ChevronDown,
  ChevronRight,
  FileJson,
  FileText,
  Bug,
  Wrench,
} from "lucide-react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  Radar,
} from "recharts";
import { fetchAnalysis, fetchAnalysisSessions, getReportURL } from "../lib/api";

const SEV_COLORS = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#22c55e",
  INFO: "#3b82f6",
};

function scoreColor(score) {
  if (score >= 8) return "#ef4444";
  if (score >= 6) return "#f97316";
  if (score >= 4) return "#eab308";
  if (score >= 2) return "#22c55e";
  return "#3b82f6";
}

export default function AnalysisDetailPage() {
  const { id } = useParams();
  const [data, setData] = useState(null);
  const [sessions, setSessions] = useState([]);
  const [expanded, setExpanded] = useState({});
  const [activeTab, setActiveTab] = useState("sessions");

  useEffect(() => {
    fetchAnalysis(id)
      .then((d) => {
        setData(d);
      })
      .catch(() => {});

    fetchAnalysisSessions(id)
      .then((d) => {
        const sessList = Array.isArray(d) ? d : d.sessions || [];
        setSessions(sessList);
      })
      .catch(() => {});
  }, [id]);

  const toggleExpand = (sessionId) => {
    setExpanded((prev) => ({ ...prev, [sessionId]: !prev[sessionId] }));
  };

  // All findings across sessions
  const allFindings = sessions.flatMap((s) =>
    (s.findings || []).map((f) => ({ ...f, session_id: s.session_id }))
  );

  // Radar chart data from average scores
  const radarData =
    sessions.length > 0
      ? [
          { subject: "TLS Version", value: avg(sessions, (s) => s.scores?.tls_version || 0) * 10 },
          { subject: "Cipher Strength", value: avg(sessions, (s) => s.scores?.cipher_strength || 0) * 10 },
          { subject: "Key Exchange", value: avg(sessions, (s) => s.scores?.key_exchange || 0) * 10 },
          { subject: "Certificate", value: avg(sessions, (s) => s.scores?.certificate_key || 0) * 10 },
          { subject: "Signature", value: avg(sessions, (s) => s.scores?.signature_algorithm || 0) * 10 },
        ]
      : [];

  if (!data) {
    return (
      <div className="app-layout">
        <Sidebar />
        <main className="main-content">
          <div className="page-content" style={{ textAlign: "center", padding: 80 }}>
            <div className="loading-shimmer" style={{ width: 300, height: 24, margin: "0 auto 16px" }} />
            <div className="loading-shimmer" style={{ width: 200, height: 16, margin: "0 auto" }} />
          </div>
        </main>
      </div>
    );
  }

  return (
    <div className="app-layout">
      <Sidebar />
      <main className="main-content">
        <header className="app-header">
          <div>
            <h2 className="header-title">Analysis Detail</h2>
            <p className="header-breadcrumb">
              {data.pcap_filename} — {data.total_sessions} sessions
            </p>
          </div>
          <div className="header-actions">
            <a
              href={getReportURL(id, "json")}
              className="btn btn-secondary"
              style={{ fontSize: 13 }}
            >
              <FileJson size={14} /> JSON
            </a>
            <a
              href={getReportURL(id, "html")}
              className="btn btn-secondary"
              style={{ fontSize: 13 }}
            >
              <FileText size={14} /> HTML
            </a>
          </div>
        </header>

        <div className="page-content animate-in">
          {/* Summary Cards */}
          <div className="stats-grid">
            <div className="card">
              <div className="card-header">
                <span className="card-title">Risk Score</span>
                <Shield size={20} color={scoreColor(data.overall_score || 0)} />
              </div>
              <div className="card-value" style={{ color: scoreColor(data.overall_score || 0) }}>
                {(data.overall_score || 0).toFixed(1)}
              </div>
              <span className={`severity-badge ${(data.overall_severity || "INFO").toLowerCase()}`}>
                {data.overall_severity || "INFO"}
              </span>
            </div>

            <div className="card">
              <div className="card-header">
                <span className="card-title">Forward Secrecy</span>
                <Lock size={20} color="#10b981" />
              </div>
              <div className="card-value" style={{ color: "#10b981" }}>
                {(data.forward_secrecy_pct || 0).toFixed(0)}%
              </div>
              <div className="card-subtitle">of sessions use ECDHE/DHE</div>
            </div>

            <div className="card">
              <div className="card-header">
                <span className="card-title">Anomalies</span>
                <AlertTriangle size={20} color="#f59e0b" />
              </div>
              <div className="card-value" style={{ color: "#f59e0b" }}>
                {data.anomaly_count || 0}
              </div>
              <div className="card-subtitle">statistically unusual sessions</div>
            </div>

            <div className="card">
              <div className="card-header">
                <span className="card-title">Findings</span>
                <Bug size={20} color="#ef4444" />
              </div>
              <div className="card-value" style={{ color: "#ef4444" }}>
                {allFindings.length}
              </div>
              <div className="card-subtitle">vulnerabilities detected</div>
            </div>
          </div>

          {/* Charts Row */}
          <div className="charts-grid">
            {radarData.length > 0 && (
              <div className="card">
                <div className="card-header">
                  <span className="card-title">Security Radar</span>
                </div>
                <ResponsiveContainer width="100%" height={260}>
                  <RadarChart data={radarData}>
                    <PolarGrid stroke="#2a3050" />
                    <PolarAngleAxis
                      dataKey="subject"
                      tick={{ fill: "#94a3b8", fontSize: 12 }}
                    />
                    <Radar
                      dataKey="value"
                      stroke="#3b82f6"
                      fill="#3b82f6"
                      fillOpacity={0.2}
                      strokeWidth={2}
                    />
                  </RadarChart>
                </ResponsiveContainer>
              </div>
            )}

            <div className="card">
              <div className="card-header">
                <span className="card-title">Severity Breakdown</span>
              </div>
              <ResponsiveContainer width="100%" height={260}>
                {(() => {
                  const breakdown = data.severity_breakdown && Object.keys(data.severity_breakdown).length > 0
                    ? data.severity_breakdown
                    : { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
                  const chartData = Object.entries(breakdown).map(([name, value]) => ({
                    name,
                    value,
                    color: SEV_COLORS[name] || "#6b7280",
                  }));
                  return (
                    <BarChart data={chartData}>
                      <XAxis dataKey="name" tick={{ fill: "#94a3b8", fontSize: 12 }} />
                      <YAxis tick={{ fill: "#94a3b8", fontSize: 12 }} allowDecimals={false} />
                      <Tooltip
                        contentStyle={{
                          background: "#1a1f35",
                          border: "1px solid #2a3050",
                          borderRadius: "8px",
                          color: "#f1f5f9",
                        }}
                      />
                      <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                        {chartData.map((entry, idx) => (
                          <Cell key={idx} fill={entry.color} />
                        ))}
                      </Bar>
                    </BarChart>
                  );
                })()}
              </ResponsiveContainer>
            </div>
          </div>

          {/* Tabs */}
          <div style={{ display: "flex", gap: 4, marginBottom: 16 }}>
            {["sessions", "findings", "remediation"].map((tab) => (
              <button
                key={tab}
                className={`btn ${activeTab === tab ? "btn-primary" : "btn-secondary"}`}
                onClick={() => setActiveTab(tab)}
                style={{ textTransform: "capitalize", fontSize: 13 }}
              >
                {tab === "sessions" && <Shield size={14} />}
                {tab === "findings" && <Bug size={14} />}
                {tab === "remediation" && <Wrench size={14} />}
                {tab} ({tab === "sessions" ? sessions.length : tab === "findings" ? allFindings.length : sessions.filter((s) => s.remediations?.length).length})
              </button>
            ))}
          </div>

          {/* Sessions Tab */}
          {activeTab === "sessions" && (
            <div className="card">
              {sessions.map((s) => (
                <div key={s.session_id} className="finding-item">
                  <div
                    className="finding-header"
                    style={{ cursor: "pointer" }}
                    onClick={() => toggleExpand(s.session_id)}
                  >
                    {expanded[s.session_id] ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                    <span className={`severity-badge ${(s.severity || "INFO").toLowerCase()}`}>{s.severity || "INFO"}</span>
                    <span className="mono" style={{ fontSize: 13, fontWeight: 600 }}>{s.protocol}</span>
                    <span style={{ color: "var(--text-muted)", fontSize: 13 }}>
                      {s.src_ip} → {s.dst_ip}
                    </span>
                    {s.tls_version && (
                      <span className="cve-tag" style={{ background: "rgba(59, 130, 246, 0.15)", color: "#60a5fa", border: "1px solid rgba(59, 130, 246, 0.3)" }}>
                        {s.tls_version}
                      </span>
                    )}
                    {s.signature_algorithm && (
                      <span className="cve-tag" style={{ background: "rgba(168, 85, 247, 0.15)", color: "#c084fc", border: "1px solid rgba(168, 85, 247, 0.3)" }}>
                        {s.signature_algorithm}
                      </span>
                    )}
                    <span style={{ marginLeft: "auto", fontWeight: 700, color: scoreColor(s.risk_score || 0) }}>
                      {(s.risk_score || 0).toFixed(1)}
                    </span>
                    {s.is_anomalous && (
                      <AlertTriangle size={14} color="#f59e0b" title="Anomalous session" />
                    )}
                    {s.has_forward_secrecy ? (
                      <Lock size={14} color="#10b981" title="Forward secrecy (ECDHE/DHE)" />
                    ) : (
                      <Unlock size={14} color="#f97316" title="No forward secrecy" />
                    )}
                  </div>

                  {expanded[s.session_id] && (
                    <div style={{ paddingLeft: 28, marginTop: 12 }}>
                      <div
                        style={{
                          display: "grid",
                          gridTemplateColumns: "repeat(4, 1fr)",
                          gap: 12,
                          marginBottom: 16,
                          background: "rgba(15, 23, 42, 0.4)",
                          padding: 12,
                          borderRadius: 8,
                          border: "1px solid var(--border-color)",
                        }}
                      >
                        <div>
                          <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>
                            Encryption Status
                          </div>
                          <div className="mono" style={{ fontSize: 13, color: (s.tls_version || s.tls?.version) ? "#60a5fa" : "#f97316", fontWeight: 600 }}>
                            {s.tls_version || s.tls?.version ? `${s.tls_version || s.tls?.version} (Encrypted)` : "Unencrypted Plaintext"}
                          </div>
                        </div>
                        <div>
                          <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>
                            Cipher Suite
                          </div>
                          <div className="mono" style={{ fontSize: 12, wordBreak: "break-all", color: "#e2e8f0" }}>
                            {s.negotiated_cipher || s.tls?.cipher_suite || "None (Plaintext Traffic)"}
                          </div>
                        </div>
                        <div>
                          <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>
                            Signature Algorithm
                          </div>
                          <div className="mono" style={{ fontSize: 13, color: "#c084fc" }}>
                            {s.signature_algorithm || s.tls?.signature_algorithm || "None (Unencrypted)"}
                          </div>
                        </div>
                        <div>
                          <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>
                            Key Exchange & PFS
                          </div>
                          <div className="mono" style={{ fontSize: 13, color: s.has_forward_secrecy ? "#34d399" : "#fb923c" }}>
                            {s.tls?.key_exchange ? s.tls.key_exchange : s.has_forward_secrecy ? "ECDHE / PFS" : "None (Plaintext / No TLS)"}
                          </div>
                        </div>
                        <div>
                          <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>
                            Certificate Subject
                          </div>
                          <div className="mono" style={{ fontSize: 12, color: "#94a3b8" }}>
                            {s.certificate?.subject || "Not Applicable (No TLS Cert)"}
                          </div>
                        </div>
                        <div>
                          <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>
                            Certificate Issuer
                          </div>
                          <div className="mono" style={{ fontSize: 12, color: "#94a3b8" }}>
                            {s.certificate?.issuer || "Not Applicable (No TLS Cert)"}
                          </div>
                        </div>
                        <div>
                          <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>
                            Cert Key Length / Alg
                          </div>
                          <div className="mono" style={{ fontSize: 13, color: "#38bdf8" }}>
                            {s.certificate?.public_key_algorithm ? `${s.certificate.public_key_algorithm} (${s.certificate.key_length} bits)` : "None"}
                          </div>
                        </div>
                        <div>
                          <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>
                            Packet Count
                          </div>
                          <div className="mono" style={{ fontSize: 13, color: "#f87171", fontWeight: 600 }}>
                            {s.packet_count || 0} packets
                          </div>
                        </div>
                        <div>
                          <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>
                            Client / Server Bytes
                          </div>
                          <div className="mono" style={{ fontSize: 13, color: "#38bdf8" }}>
                            {s.client_bytes || 0} B / {s.server_bytes || 0} B
                          </div>
                        </div>
                        <div>
                          <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>
                            Stream Completion / Gaps
                          </div>
                          <div className="mono" style={{ fontSize: 13, color: s.stream_complete ? "#34d399" : "#f59e0b" }}>
                            {s.stream_complete ? "Complete" : "Incomplete"} {s.reassembly_gap ? "(Gaps Detected)" : "(No Gaps)"}
                          </div>
                        </div>
                        <div>
                          <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>
                            Session Duration
                          </div>
                          <div className="mono" style={{ fontSize: 12, color: "#94a3b8" }}>
                            {s.start_time ? new Date(s.start_time).toLocaleTimeString() : "N/A"} - {s.end_time ? new Date(s.end_time).toLocaleTimeString() : "N/A"}
                          </div>
                        </div>
                      </div>

                      {s.findings?.length > 0 && (
                        <div>
                          <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-secondary)", marginBottom: 8 }}>
                            Findings ({s.findings.length})
                          </div>
                          {s.findings.map((f, i) => (
                            <div key={i} style={{ marginBottom: 10, paddingLeft: 12, borderLeft: `2px solid ${SEV_COLORS[f.severity] || "#6b7280"}` }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                <span className={`severity-badge ${(f.severity || "INFO").toLowerCase()}`} style={{ fontSize: 10 }}>{f.severity}</span>
                                <span style={{ fontWeight: 600, fontSize: 13 }}>{f.title}</span>
                              </div>
                              <div className="finding-desc" style={{ marginTop: 4 }}>{f.description}</div>
                              {f.cve_ids?.length ? (
                                <div className="finding-cves">
                                  {f.cve_ids.map((cve) => (
                                    <span key={cve} className="cve-tag">{cve}</span>
                                  ))}
                                </div>
                              ) : null}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* Findings Tab */}
          {activeTab === "findings" && (
            <div className="card">
              {allFindings.length === 0 ? (
                <div style={{ padding: 40, textAlign: "center", color: "var(--text-muted)" }}>
                  No findings detected — all sessions appear secure.
                </div>
              ) : (
                allFindings.map((f, i) => (
                  <div key={i} className="finding-item">
                    <div className="finding-header">
                      <span className={`severity-badge ${(f.severity || "INFO").toLowerCase()}`}>{f.severity}</span>
                      <span className="finding-title">{f.title}</span>
                      <span className="mono" style={{ fontSize: 11, color: "var(--text-muted)", marginLeft: "auto" }}>
                        {f.id}
                      </span>
                    </div>
                    <div className="finding-desc">{f.description}</div>
                    {f.cve_ids?.length ? (
                      <div className="finding-cves">
                        {f.cve_ids.map((cve) => (
                          <span key={cve} className="cve-tag">{cve}</span>
                        ))}
                      </div>
                    ) : null}
                    {f.remediation && (
                      <div style={{ marginTop: 8, fontSize: 13, color: "var(--accent-green)" }}>
                        💡 {f.remediation}
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          )}

          {/* Remediation Tab */}
          {activeTab === "remediation" && (
            <div className="card">
              {sessions
                .filter((s) => s.remediations?.length)
                .map((s) => (
                  <div key={s.session_id} style={{ marginBottom: 24 }}>
                    <h4 style={{ fontSize: 14, marginBottom: 12, color: "var(--text-secondary)" }}>
                      {s.protocol} — {s.src_ip} → {s.dst_ip}
                    </h4>
                    {s.remediations.map((r, i) => (
                      <div key={i} className="finding-item">
                        <div className="finding-header">
                          <Wrench size={14} color="var(--accent-cyan)" />
                          <span style={{ fontWeight: 600, fontSize: 14 }}>{r.finding_title}</span>
                          <span
                            className="severity-badge"
                            style={{
                              marginLeft: "auto",
                              background: "rgba(6,182,212,0.12)",
                              color: "var(--accent-cyan)",
                            }}
                          >
                            {r.priority}
                          </span>
                        </div>
                        <div className="finding-desc" style={{ marginBottom: 8 }}>
                          {r.remediation_text}
                        </div>
                        {Object.entries(r.config_snippets || {}).map(([server, snippet]) => (
                          <div key={server} className="config-snippet">
                            <div className="snippet-header">{server}</div>
                            <pre>{snippet}</pre>
                          </div>
                        ))}
                      </div>
                    ))}
                  </div>
                ))}
              {sessions.filter((s) => s.remediations?.length).length === 0 && (
                <div style={{ padding: 40, textAlign: "center", color: "var(--text-muted)" }}>
                  No remediation recommendations — all configurations appear secure.
                </div>
              )}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

function avg(arr, fn) {
  if (arr.length === 0) return 0;
  return arr.reduce((sum, s) => sum + fn(s), 0) / arr.length;
}
