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
  Clock,
  Terminal,
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
  const [globalAIAssessment, setGlobalAIAssessment] = useState("");
  const [isStreamingAI, setIsStreamingAI] = useState(false);

  useEffect(() => {
    let timeoutId;
    const loadData = () => {
      fetchAnalysis(id)
        .then((d) => {
          setData(d);
          if (d && d.status !== "COMPLETED" && d.status !== "FAILED") {
            timeoutId = setTimeout(loadData, 1000);
          } else {
            // Once completed, fetch the sessions which will now have findings
            fetchAnalysisSessions(id)
              .then((sessData) => {
                const sessList = Array.isArray(sessData) ? sessData : sessData.sessions || [];
                setSessions(sessList);
              })
              .catch(() => {});
          }
        })
        .catch(() => {});
    };

    loadData();

    const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${wsProtocol}//${window.location.host}/api/v1/analyses/${id}/events`);
    
    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.event === "ai_stream_start") {
          setGlobalAIAssessment("");
          setIsStreamingAI(true);
          // auto switch tab to ai_insights to show progress!
          setActiveTab("ai_insights");
        } else if (msg.event === "ai_stream") {
          setGlobalAIAssessment((prev) => prev + msg.chunk);
        } else if (msg.event === "ai_stream_end") {
          setIsStreamingAI(false);
        }
      } catch (e) {
        // regular progress event
      }
    };

    return () => {
      if (timeoutId) clearTimeout(timeoutId);
      ws.close();
    };
  }, [id]);

  const toggleExpand = (sessionId) => {
    setExpanded((prev) => ({ ...prev, [sessionId]: !prev[sessionId] }));
  };

  // All findings across sessions
  const allFindings = sessions.flatMap((s) =>
    (s.findings || []).map((f) => ({ ...f, session_id: s.session_id }))
  );

  // Calculate sub-scores deterministically for the Radar chart
  const getScore = (s, category) => {
    if (category === "tls_version") {
      if (!s.tls_version) return 0;
      if (s.tls_version === "TLS 1.3") return 10;
      if (s.tls_version === "TLS 1.2") return 8;
      return 3;
    }
    if (category === "cipher") {
      const c = s.negotiated_cipher || "";
      if (!c) return 0;
      if (c.includes("GCM") || c.includes("CHACHA20")) return 10;
      if (c.includes("CBC")) return 6;
      if (c.includes("RC4") || c.includes("NULL")) return 1;
      return 5;
    }
    if (category === "kex") {
      return s.has_forward_secrecy ? 10 : (s.tls_version ? 4 : 0);
    }
    if (category === "cert") {
      const bits = s.certificate?.key_length || 0;
      if (bits >= 4096) return 10;
      if (bits >= 2048) return 8;
      if (bits >= 1024) return 4;
      return 0;
    }
    if (category === "sig") {
      const sig = s.certificate?.signature_algorithm?.toLowerCase() || "";
      if (sig.includes("sha384") || sig.includes("sha512") || sig.includes("ecdsa")) return 10;
      if (sig.includes("sha256")) return 8;
      if (sig.includes("sha1")) return 3;
      if (sig.includes("md5")) return 1;
      return 0;
    }
    return 0;
  };

  const radarData =
    sessions.length > 0
      ? [
          { subject: "TLS Version", value: avg(sessions, (s) => getScore(s, "tls_version")) * 10 },
          { subject: "Cipher Strength", value: avg(sessions, (s) => getScore(s, "cipher")) * 10 },
          { subject: "Key Exchange", value: avg(sessions, (s) => getScore(s, "kex")) * 10 },
          { subject: "Certificate", value: avg(sessions, (s) => getScore(s, "cert")) * 10 },
          { subject: "Signature", value: avg(sessions, (s) => getScore(s, "sig")) * 10 },
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
            <a
              href={getReportURL(id, "pdf")}
              className="btn btn-secondary"
              style={{ fontSize: 13 }}
            >
              <FileText size={14} /> PDF
            </a>
          </div>
        </header>

        <div className="page-content animate-in">
          {/* Summary Cards */}
          <div className="stats-grid">
            {(() => {
              const isLoading = data.status !== "COMPLETED" && data.status !== "FAILED";
              const maxSessionScore = sessions.reduce((max, s) => Math.max(max, s.risk_score || 0), 0);
              const score = (data.overall_score && data.overall_score > 0) ? data.overall_score : maxSessionScore;
              let severity = data.overall_severity || "INFO";
              if (score >= 9) severity = "CRITICAL";
              else if (score >= 7) severity = "HIGH";
              else if (score >= 5) severity = "MEDIUM";
              else if (score >= 3) severity = "LOW";
              return (
                <div className="card">
                  <div className="card-header">
                    <span className="card-title">Risk Score</span>
                    <Shield size={20} color={isLoading ? "#475569" : scoreColor(score)} />
                  </div>
                  <div className="card-value" style={{ color: isLoading ? "#475569" : scoreColor(score) }}>
                    {isLoading ? <div className="loading-shimmer" style={{ width: 60, height: 32, borderRadius: 4 }} /> : score.toFixed(1)}
                  </div>
                  {isLoading ? (
                    <div className="loading-shimmer" style={{ width: 80, height: 20, borderRadius: 12, marginTop: 4 }} />
                  ) : (
                    <span className={`severity-badge ${severity.toLowerCase()}`}>
                      {severity}
                    </span>
                  )}
                </div>
              );
            })()}

            <div className="card">
              <div className="card-header">
                <span className="card-title">Forward Secrecy</span>
                <Lock size={20} color={data.status !== "COMPLETED" && data.status !== "FAILED" ? "#475569" : "#10b981"} />
              </div>
              <div className="card-value" style={{ color: data.status !== "COMPLETED" && data.status !== "FAILED" ? "#475569" : "#10b981" }}>
                {data.status !== "COMPLETED" && data.status !== "FAILED" ? (
                  <div className="loading-shimmer" style={{ width: 60, height: 32, borderRadius: 4 }} />
                ) : (
                  `${(data.forward_secrecy_pct || 0).toFixed(0)}%`
                )}
              </div>
              <div className="card-subtitle">
                {data.status !== "COMPLETED" && data.status !== "FAILED" ? (
                  <div className="loading-shimmer" style={{ width: 140, height: 14, borderRadius: 4, marginTop: 6 }} />
                ) : (
                  "of sessions use ECDHE/DHE"
                )}
              </div>
            </div>

            <div className="card">
              <div className="card-header">
                <span className="card-title">Anomalies</span>
                <AlertTriangle size={20} color={data.status !== "COMPLETED" && data.status !== "FAILED" ? "#475569" : "#f59e0b"} />
              </div>
              <div className="card-value" style={{ color: data.status !== "COMPLETED" && data.status !== "FAILED" ? "#475569" : "#f59e0b" }}>
                {data.status !== "COMPLETED" && data.status !== "FAILED" ? (
                  <div className="loading-shimmer" style={{ width: 40, height: 32, borderRadius: 4 }} />
                ) : (
                  data.anomaly_count || 0
                )}
              </div>
              <div className="card-subtitle">
                {data.status !== "COMPLETED" && data.status !== "FAILED" ? (
                  <div className="loading-shimmer" style={{ width: 160, height: 14, borderRadius: 4, marginTop: 6 }} />
                ) : (
                  "statistically unusual sessions"
                )}
              </div>
            </div>

            <div className="card">
              <div className="card-header">
                <span className="card-title">Findings</span>
                <Bug size={20} color={data.status !== "COMPLETED" && data.status !== "FAILED" ? "#475569" : "#ef4444"} />
              </div>
              <div className="card-value" style={{ color: data.status !== "COMPLETED" && data.status !== "FAILED" ? "#475569" : "#ef4444" }}>
                {data.status !== "COMPLETED" && data.status !== "FAILED" ? (
                  <div className="loading-shimmer" style={{ width: 40, height: 32, borderRadius: 4 }} />
                ) : (
                  allFindings.length
                )}
              </div>
              <div className="card-subtitle">
                {data.status !== "COMPLETED" && data.status !== "FAILED" ? (
                  <div className="loading-shimmer" style={{ width: 140, height: 14, borderRadius: 4, marginTop: 6 }} />
                ) : (
                  "vulnerabilities detected"
                )}
              </div>
            </div>
          </div>

          {/* Charts Row */}
          <div className="charts-grid">
            {data.status !== "COMPLETED" && data.status !== "FAILED" ? (
              <>
                <div className="card">
                  <div className="card-header">
                    <span className="card-title">Security Radar</span>
                  </div>
                  <div style={{ display: "flex", justifyContent: "center", alignItems: "center", height: 260 }}>
                    <div className="loading-spinner" style={{ width: 40, height: 40, border: "2px solid rgba(59, 130, 246, 0.3)", borderTopColor: "#3b82f6", borderRadius: "50%", animation: "spin 1s linear infinite" }}></div>
                  </div>
                </div>
                <div className="card">
                  <div className="card-header">
                    <span className="card-title">Severity Breakdown</span>
                  </div>
                  <div style={{ padding: 20 }}>
                    <div className="loading-shimmer" style={{ width: "100%", height: 220, borderRadius: 8 }}></div>
                  </div>
                </div>
              </>
            ) : (
              <>
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
                      let breakdown = data.severity_breakdown;
                      if (!breakdown || Object.keys(breakdown).length === 0) {
                        if (allFindings.length > 0) {
                          breakdown = {};
                          allFindings.forEach((f) => {
                            const sev = f.severity || "INFO";
                            breakdown[sev] = (breakdown[sev] || 0) + 1;
                          });
                        } else {
                          breakdown = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
                        }
                      }
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
              </>
            )}
          </div>

          {/* Tabs */}
          <div style={{ display: "flex", gap: 4, marginBottom: 16 }}>
            {["sessions", "findings", "remediation", "ai_insights"].map((tab) => (
              <button
                key={tab}
                className={`btn ${activeTab === tab ? "btn-primary" : "btn-secondary"}`}
                onClick={() => setActiveTab(tab)}
                style={{ textTransform: "capitalize", fontSize: 13 }}
              >
                {tab === "sessions" && <Shield size={14} />}
                {tab === "findings" && <Bug size={14} />}
                {tab === "remediation" && <Wrench size={14} />}
                {tab === "ai_insights" && <span>🤖</span>}
                {tab === "ai_insights" ? "AI Insights" : tab} ({tab === "sessions" ? sessions.length : tab === "findings" ? allFindings.length : tab === "remediation" ? sessions.filter((s) => s.remediations?.length).length : tab === "ai_insights" ? (isStreamingAI ? "Streaming..." : "1") : 0})
              </button>
            ))}
          </div>

          {/* Sessions Tab */}
          {activeTab === "sessions" && (
            <div className="card">
              {data.status !== "COMPLETED" && data.status !== "FAILED" ? (
                <div style={{ padding: 40, display: "flex", flexDirection: "column", gap: 16 }}>
                  <div className="loading-shimmer" style={{ width: "100%", height: 60, borderRadius: 8 }}></div>
                  <div className="loading-shimmer" style={{ width: "100%", height: 60, borderRadius: 8 }}></div>
                  <div className="loading-shimmer" style={{ width: "100%", height: 60, borderRadius: 8 }}></div>
                </div>
              ) : sessions.length === 0 ? (
                <div style={{ padding: 40, textAlign: "center", color: "var(--text-muted)" }}>
                  No sessions extracted from this PCAP.
                </div>
              ) : (
                sessions.map((s) => (
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

                      {s.ai_assessment && (
                        <div style={{ marginTop: 14, padding: "12px 16px", background: "rgba(59, 130, 246, 0.08)", borderRadius: 8, border: "1px solid rgba(59, 130, 246, 0.2)" }}>
                          <div style={{ fontSize: 11, fontWeight: 700, color: "#60a5fa", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.08em", display: "flex", alignItems: "center", gap: 6 }}>
                            <span>🤖</span> AI Security Assessment
                          </div>
                          <div style={{ fontSize: 13, color: "#cbd5e1", lineHeight: 1.6 }}>{s.ai_assessment}</div>
                        </div>
                      )}

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
                              {f.evidence?.length > 0 && (
                                <div style={{ marginTop: 8, padding: 8, background: "rgba(0,0,0,0.2)", borderRadius: 4, border: "1px solid rgba(255,255,255,0.05)" }}>
                                  <div style={{ fontSize: 11, fontWeight: 600, color: "var(--text-muted)", marginBottom: 4, textTransform: "uppercase" }}>Forensic Evidence</div>
                                  <ul style={{ margin: 0, paddingLeft: 16, fontSize: 12, color: "#cbd5e1" }}>
                                    {f.evidence.map((ev, idx) => (
                                      <li key={idx} style={{ marginBottom: 2 }}>{ev}</li>
                                    ))}
                                  </ul>
                                </div>
                              )}
                              {f.recommendation && (
                                <div style={{ marginTop: 6, fontSize: 12, color: "#34d399" }}>
                                  💡 {f.recommendation}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                      
                      {(!s.findings || s.findings.length === 0) && (
                        <div style={{ marginTop: 12, padding: "10px 14px", background: "rgba(16, 185, 129, 0.08)", borderRadius: 8, border: "1px solid rgba(16, 185, 129, 0.2)", fontSize: 13, color: "#34d399" }}>
                          ✅ No vulnerabilities detected in this session. All cryptographic parameters meet security policy requirements.
                        </div>
                      )}
                      
                      {s.protocol_events?.length > 0 && (
                        <div style={{ marginTop: 16 }}>
                          <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-secondary)", marginBottom: 8, display: "flex", alignItems: "center", gap: 6 }}>
                            <Terminal size={14} /> Protocol Timeline
                          </div>
                          <div style={{ background: "#0f172a", borderRadius: 8, padding: 12, border: "1px solid var(--border-color)", maxHeight: 300, overflowY: "auto" }}>
                            {s.protocol_events.map((ev, i) => (
                              <div key={i} style={{ display: "flex", gap: 12, marginBottom: 8, fontSize: 12, fontFamily: "monospace" }}>
                                <div style={{ color: "var(--text-muted)", width: 85, flexShrink: 0 }}>
                                  {new Date(ev.timestamp).toISOString().substring(11, 23)}
                                </div>
                                <div style={{ color: ev.direction === "client_to_server" ? "#38bdf8" : "#a78bfa", width: 40, flexShrink: 0 }}>
                                  {ev.direction === "client_to_server" ? "C→S" : "S→C"}
                                </div>
                                <div style={{ color: ev.direction === "client_to_server" ? "#e2e8f0" : "#94a3b8", wordBreak: "break-all" }}>
                                  {ev.command || ev.response}
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )))}
            </div>
          )}

          {/* Findings Tab */}
          {activeTab === "findings" && (
            <div className="card">
              {data.status !== "COMPLETED" && data.status !== "FAILED" ? (
                <div style={{ padding: 40, display: "flex", flexDirection: "column", gap: 16 }}>
                  <div className="loading-shimmer" style={{ width: "100%", height: 60, borderRadius: 8 }}></div>
                  <div className="loading-shimmer" style={{ width: "100%", height: 60, borderRadius: 8 }}></div>
                </div>
              ) : allFindings.length === 0 ? (
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
                    
                    {f.evidence?.length > 0 && (
                      <div style={{ marginTop: 12, padding: 12, background: "rgba(0,0,0,0.2)", borderRadius: 6, border: "1px solid rgba(255,255,255,0.05)" }}>
                        <div style={{ fontSize: 11, fontWeight: 600, color: "var(--text-muted)", marginBottom: 6, textTransform: "uppercase" }}>Forensic Evidence</div>
                        <ul style={{ margin: 0, paddingLeft: 18, fontSize: 13, color: "#e2e8f0" }}>
                          {f.evidence.map((ev, idx) => (
                            <li key={idx} style={{ marginBottom: 4 }}>{ev}</li>
                          ))}
                        </ul>
                      </div>
                    )}

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
          {activeTab === "remediation" && data.status !== "COMPLETED" && data.status !== "FAILED" && (
            <div className="card">
              <div style={{ padding: 40, display: "flex", flexDirection: "column", gap: 16 }}>
                <div className="loading-shimmer" style={{ width: "100%", height: 100, borderRadius: 8 }}></div>
                <div className="loading-shimmer" style={{ width: "100%", height: 100, borderRadius: 8 }}></div>
              </div>
            </div>
          )}
          {activeTab === "remediation" && data.status === "COMPLETED" && sessions.filter((s) => s.remediations?.length).length === 0 && (
            <div className="card">
              <div style={{ padding: 40, textAlign: "center" }}>
                <div style={{ fontSize: 48, marginBottom: 16 }}>🛡️</div>
                <h3 style={{ marginBottom: 8, color: "#34d399" }}>All Clear — No Remediation Required</h3>
                <p style={{ color: "var(--text-muted)", maxWidth: 400, margin: "0 auto 24px" }}>
                  All sessions use strong cryptographic configurations. No remediation actions are recommended.
                </p>
              </div>
            </div>
          )}
          {activeTab === "remediation" && data.status === "COMPLETED" && sessions.filter((s) => s.remediations?.length).length > 0 && (
            <div className="card">
              {sessions.filter((s) => s.remediations?.length).map((s) => (
                <div key={s.session_id} style={{ marginBottom: 32 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12, paddingBottom: 10, borderBottom: "1px solid var(--border-color)" }}>
                    <span className={`severity-badge ${(s.severity || "INFO").toLowerCase()}`}>{s.severity || "INFO"}</span>
                    <h4 style={{ fontSize: 14, color: "var(--text-secondary)", margin: 0 }}>
                      {s.protocol} — {s.src_ip} → {s.dst_ip}
                    </h4>
                  </div>
                  {s.remediations.map((r, i) => (
                    <div key={i} className="finding-item" style={{ marginBottom: 16 }}>
                      <div className="finding-header">
                        <Wrench size={14} color="var(--accent-cyan)" />
                        <span style={{ fontWeight: 600, fontSize: 14 }}>{r.finding_title || r.title || "Remediation"}</span>
                        <span className="severity-badge" style={{ marginLeft: "auto", background: "rgba(6,182,212,0.12)", color: "var(--accent-cyan)" }}>
                          {r.priority || "RECOMMENDED"}
                        </span>
                      </div>
                      <div className="finding-desc" style={{ marginBottom: 8 }}>
                        {r.remediation_text || r.description || r.recommendation}
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
            </div>
          )}

          {/* AI Insights Tab */}
          {activeTab === "ai_insights" && (
            <div className="card" style={{ minHeight: 300 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 20, borderBottom: "1px solid rgba(59, 130, 246, 0.2)", paddingBottom: 12 }}>
                <div style={{ background: "rgba(59, 130, 246, 0.1)", padding: 8, borderRadius: 8 }}>
                  <span style={{ fontSize: 24 }}>🤖</span>
                </div>
                <div>
                  <h3 style={{ margin: 0, color: "#60a5fa" }}>AI Security Posture Assessment</h3>
                  <div style={{ fontSize: 13, color: "var(--text-muted)", marginTop: 4 }}>
                    Holistic analysis of the entire PCAP file powered by LLM
                  </div>
                </div>
                {isStreamingAI && (
                  <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 8, color: "#38bdf8" }}>
                    <div className="loading-shimmer" style={{ width: 12, height: 12, borderRadius: "50%" }}></div>
                    <span style={{ fontSize: 13, fontWeight: 600 }}>Streaming Insights...</span>
                  </div>
                )}
              </div>
              
              <div style={{ color: "#e2e8f0", lineHeight: 1.7, fontSize: 14, whiteSpace: "pre-wrap", fontFamily: "system-ui, -apple-system, sans-serif" }}>
                {globalAIAssessment || data?.global_ai_assessment || (
                  <div style={{ padding: "10px 0" }}>
                    {isStreamingAI ? (
                      <div style={{ color: "var(--text-muted)", textAlign: "center", padding: 40 }}>Waiting for AI engine to initialize...</div>
                    ) : data?.status !== "COMPLETED" && data?.status !== "FAILED" ? (
                      <div>
                        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 24 }}>
                          <div className="loading-spinner" style={{ width: 20, height: 20, border: "2px solid rgba(59, 130, 246, 0.3)", borderTopColor: "#3b82f6", borderRadius: "50%", animation: "spin 1s linear infinite" }}></div>
                          <div style={{ color: "#60a5fa", fontSize: 14, fontWeight: 500 }}>AI is reasoning about network behavior...</div>
                          <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
                        </div>
                        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                          <div className="loading-shimmer" style={{ width: "100%", height: 14, borderRadius: 4 }}></div>
                          <div className="loading-shimmer" style={{ width: "95%", height: 14, borderRadius: 4 }}></div>
                          <div className="loading-shimmer" style={{ width: "85%", height: 14, borderRadius: 4 }}></div>
                          <div className="loading-shimmer" style={{ width: "90%", height: 14, borderRadius: 4 }}></div>
                        </div>
                        <div style={{ display: "flex", flexDirection: "column", gap: 12, marginTop: 24 }}>
                          <div className="loading-shimmer" style={{ width: "100%", height: 14, borderRadius: 4 }}></div>
                          <div className="loading-shimmer" style={{ width: "75%", height: 14, borderRadius: 4 }}></div>
                        </div>
                      </div>
                    ) : (
                      <div style={{ textAlign: "center", padding: 40, color: "var(--text-muted)" }}>No global AI assessment available for this analysis.</div>
                    )}
                  </div>
                )}
              </div>
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
