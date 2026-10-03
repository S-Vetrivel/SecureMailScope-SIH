import { useEffect, useState, useRef } from "react";
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
  RefreshCw,
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
import { fetchAnalysis, fetchAnalysisSessions, getReportURL, startAnalysis } from "../lib/api";

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
  const [isReanalysing, setIsReanalysing] = useState(false);
  const [packets, setPackets] = useState([]);
  const [loadingPackets, setLoadingPackets] = useState(false);
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [packetDetail, setPacketDetail] = useState("");
  const [loadingPacketDetail, setLoadingPacketDetail] = useState(false);
  const timeoutIdRef = useRef(null);

  const loadData = () => {
    fetchAnalysis(id)
        .then((d) => {
          setData(d);
          if (d && d.status !== "COMPLETED" && d.status !== "FAILED") {
            timeoutIdRef.current = setTimeout(loadData, 1000);
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

  useEffect(() => {
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
        } else if (msg.event === "global_ai_assessment_complete") {
          loadData();
          setIsStreamingAI(false);
          setActiveTab("ai_insights");
        }
      } catch (e) {
        // regular progress event
      }
    };

    return () => {
      if (timeoutIdRef.current) clearTimeout(timeoutIdRef.current);
      ws.close();
    };
  }, [id]);

  useEffect(() => {
    if (activeTab === "packets" && packets.length === 0) {
      setLoadingPackets(true);
      fetch(`/api/v1/analyses/${id}/packets`)
        .then((res) => res.json())
        .then((data) => {
          setPackets(data.packets || []);
          setLoadingPackets(false);
        })
        .catch(() => setLoadingPackets(false));
    }
  }, [activeTab, id, packets.length]);

  const loadPacketDetail = (packetNum) => {
    setSelectedPacket(packetNum);
    setPacketDetail("");
    setLoadingPacketDetail(true);
    fetch(`/api/v1/analyses/${id}/packets/${packetNum}`)
      .then((res) => res.text())
      .then((text) => {
        setPacketDetail(text);
        setLoadingPacketDetail(false);
      })
      .catch(() => setLoadingPacketDetail(false));
  };

  const toggleExpand = (sessionId) => {
    setExpanded((prev) => ({ ...prev, [sessionId]: !prev[sessionId] }));
  };

  // All findings across sessions
  const allFindings = sessions.flatMap((s) =>
    (s.findings || []).map((f) => ({ ...f, session_id: s.session_id }))
  );

  const radarData =
    sessions.length > 0
      ? [
          { subject: "TLS Version", value: avg(sessions, (s) => (s.scores?.tls_version || 0) * 100) },
          { subject: "Cipher Strength", value: avg(sessions, (s) => (s.scores?.cipher_strength || 0) * 100) },
          { subject: "Key Exchange", value: avg(sessions, (s) => (s.scores?.key_exchange || 0) * 100) },
          { subject: "Certificate", value: avg(sessions, (s) => (s.scores?.certificate || 0) * 100) },
          { subject: "Signature", value: avg(sessions, (s) => (s.scores?.signature_algorithm || 0) * 100) },
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

  const handleReanalyse = async () => {
    setIsReanalysing(true);
    setIsStreamingAI(true);
    setGlobalAIAssessment("");
    try {
      await startAnalysis(id);
      setTimeout(() => {
        loadData();
        setIsReanalysing(false);
      }, 1000);
    } catch (error) {
      console.error("Failed to reanalyse", error);
      setIsReanalysing(false);
      setIsStreamingAI(false);
    }
  };

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
            <button
              onClick={handleReanalyse}
              disabled={isReanalysing}
              className="btn btn-primary"
              style={{ fontSize: 13, display: "flex", gap: "6px", alignItems: "center" }}
            >
              <RefreshCw size={14} className={isReanalysing ? "animate-spin" : ""} />
              {isReanalysing ? "Reanalysing..." : "Reanalyse AI"}
            </button>
            <a
              href={`/api/v1/analyses/${id}/pcap`}
              className="btn btn-secondary"
              style={{ fontSize: 13 }}
              download
            >
              <FileText size={14} /> Download PCAP
            </a>
            <button
              onClick={() => setActiveTab("packets")}
              className={`btn ${activeTab === "packets" ? "btn-primary" : "btn-secondary"}`}
              style={{ fontSize: 13 }}
            >
              <FileText size={14} /> View Packets
            </button>
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
            {["sessions", "findings", "packets", "remediation", "ai_insights"].map((tab) => (
              <button
                key={tab}
                className={`btn ${activeTab === tab ? "btn-primary" : "btn-secondary"}`}
                onClick={() => setActiveTab(tab)}
                style={{ textTransform: "capitalize", fontSize: 13 }}
              >
                {tab === "sessions" && <Shield size={14} />}
                {tab === "findings" && <Bug size={14} />}
                {tab === "packets" && <FileText size={14} />}
                {tab === "remediation" && <Wrench size={14} />}
                {tab === "ai_insights" && <span>🤖</span>}
                <span style={{ textTransform: "capitalize" }}>{tab === "ai_insights" ? "AI Insights" : tab}</span> 
                {tab !== "packets" && ` (${tab === "sessions" ? sessions.length : tab === "findings" ? allFindings.length : tab === "remediation" ? sessions.filter((s) => s.ai_assessment_structured?.recommended_actions?.length || s.remediations?.length).length : tab === "ai_insights" ? (isStreamingAI ? "Streaming..." : "1") : 0})`}
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
                    <div style={{ paddingLeft: 28, marginTop: 12, display: "flex", flexDirection: "column", gap: 16 }}>
                      
                      {/* FORENSIC EVIDENCE & CRYPTOGRAPHIC PARAMETERS */}
                      <div style={{ background: "rgba(15, 23, 42, 0.4)", borderRadius: 8, border: "1px solid var(--border-color)", overflow: "hidden" }}>
                        <div style={{ padding: "10px 14px", background: "rgba(255, 255, 255, 0.03)", borderBottom: "1px solid var(--border-color)", fontWeight: 600, fontSize: 13, color: "var(--text-secondary)" }}>
                          FORENSIC EVIDENCE
                          <span style={{ fontSize: 11, fontWeight: 400, color: "var(--text-muted)", marginLeft: 8 }}>Directly observed and parsed from the network capture</span>
                        </div>
                        <div style={{ padding: 14, display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}>
                          <div>
                            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>Protocol</div>
                            <div className="mono" style={{ fontSize: 13, color: "#e2e8f0" }}>{s.protocol}</div>
                          </div>
                          <div>
                            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>STARTTLS</div>
                            <div className="mono" style={{ fontSize: 13, color: "#e2e8f0" }}>{s.starttls?.accepted ? "Accepted" : s.starttls?.requested ? "Requested" : "None"}</div>
                          </div>
                          <div>
                            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>TLS Version</div>
                            <div className="mono" style={{ fontSize: 13, color: s.tls?.version ? "#60a5fa" : "#f97316" }}>{s.tls?.version || "Unknown"}</div>
                          </div>
                          <div>
                            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>Cipher Suite</div>
                            <div className="mono" style={{ fontSize: 13, color: s.tls?.cipher_suite ? "#60a5fa" : "#f97316" }}>{s.tls?.cipher_suite || "Unknown"}</div>
                          </div>
                          <div>
                            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>Key Exchange</div>
                            <div className="mono" style={{ fontSize: 13, color: "#e2e8f0" }}>{s.tls?.key_exchange || "Unknown"}</div>
                          </div>
                          <div>
                            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>Public Key</div>
                            <div className="mono" style={{ fontSize: 13, color: "#e2e8f0" }}>{s.certificate?.public_key_algorithm ? `${s.certificate.public_key_algorithm} ${s.certificate.key_length}-bit` : "Unknown"}</div>
                          </div>
                          <div>
                            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>Signature</div>
                            <div className="mono" style={{ fontSize: 13, color: "#e2e8f0" }}>{s.certificate?.signature_algorithm || "Unknown"}</div>
                          </div>
                          <div>
                            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>Forward Secrecy</div>
                            <div className="mono" style={{ fontSize: 13, color: s.has_forward_secrecy ? "#34d399" : "#f87171" }}>{s.has_forward_secrecy ? "Yes" : "No"}</div>
                          </div>
                          <div>
                            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>Handshake</div>
                            <div className="mono" style={{ fontSize: 13, color: s.tls?.handshake_completed ? "#34d399" : s.tls?.handshake_failed ? "#f87171" : "Unknown" }}>
                              {s.tls?.handshake_completed ? "Completed" : s.tls?.handshake_failed ? "Failed" : "Unknown"}
                            </div>
                          </div>
                          <div>
                            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>Application Data</div>
                            <div className="mono" style={{ fontSize: 13, color: s.tls?.app_data_observed ? "#34d399" : "#f97316" }}>
                              {s.tls?.app_data_observed ? "Observed" : "Not Observed"}
                            </div>
                          </div>
                          <div>
                            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>Capture Completeness</div>
                            <div className="mono" style={{ fontSize: 13, color: s.stream_complete ? "#34d399" : "#f59e0b" }}>
                              {s.stream_complete ? "Complete" : "Incomplete (Gap Detected)"}
                            </div>
                          </div>
                        </div>
                      </div>
                    
                      {/* SECURITY FINDINGS */}
                      <div style={{ background: "rgba(15, 23, 42, 0.4)", borderRadius: 8, border: "1px solid var(--border-color)", overflow: "hidden" }}>
                        <div style={{ padding: "10px 14px", background: "rgba(255, 255, 255, 0.03)", borderBottom: "1px solid var(--border-color)", fontWeight: 600, fontSize: 13, color: "var(--text-secondary)" }}>
                          DETERMINISTIC SECURITY FINDINGS
                        </div>
                        <div style={{ padding: 14 }}>
                          {s.findings?.length > 0 ? (
                            s.findings.map((f, i) => (
                              <div key={i} style={{ marginBottom: 12, paddingLeft: 12, borderLeft: `2px solid ${SEV_COLORS[f.severity] || "#6b7280"}` }}>
                                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                                  <span className={`severity-badge ${(f.severity || "INFO").toLowerCase()}`} style={{ fontSize: 10 }}>{f.severity}</span>
                                  {f.confidence && (
                                    <span style={{ fontSize: 10, padding: "2px 6px", borderRadius: 4, background: "rgba(255,255,255,0.1)", color: "#cbd5e1" }}>
                                      {f.confidence} CONFIDENCE
                                    </span>
                                  )}
                                  <span style={{ fontWeight: 600, fontSize: 13 }}>{f.title}</span>
                                </div>
                                <div className="finding-desc" style={{ marginBottom: 6 }}>{f.description}</div>
                                {f.evidence ? (
                                  <div style={{ padding: 8, background: "rgba(0,0,0,0.2)", borderRadius: 4, border: "1px solid rgba(255,255,255,0.05)", marginBottom: 6 }}>
                                    <div style={{ fontSize: 11, fontWeight: 600, color: "var(--text-muted)", marginBottom: 4, textTransform: "uppercase" }}>Forensic Evidence</div>
                                    <ul style={{ margin: 0, paddingLeft: 16, fontSize: 12, color: "#cbd5e1" }}>
                                      {Array.isArray(f.evidence) ? f.evidence.map((ev, idx) => <li key={idx}>{ev}</li>) : (
                                        <>
                                          {f.evidence.details && <li>{f.evidence.details}</li>}
                                          {f.evidence.packet_numbers?.length > 0 && <li>Packets: {f.evidence.packet_numbers.join(", ")}</li>}
                                          {f.evidence.pcap && <li>PCAP: {f.evidence.pcap}</li>}
                                        </>
                                      )}
                                    </ul>
                                  </div>
                                ) : null}
                                {f.recommendation && <div style={{ fontSize: 12, color: "#34d399" }}>💡 {f.recommendation}</div>}
                              </div>
                            ))
                          ) : (
                            <div style={{ color: "#34d399", fontSize: 13 }}>✅ No vulnerabilities detected. All cryptographic parameters meet security policy requirements.</div>
                          )}
                        </div>
                      </div>
                    
                      {/* ML ANOMALY ANALYSIS */}
                      <div style={{ background: "rgba(15, 23, 42, 0.4)", borderRadius: 8, border: "1px solid var(--border-color)", overflow: "hidden" }}>
                        <div style={{ padding: "10px 14px", background: "rgba(255, 255, 255, 0.03)", borderBottom: "1px solid var(--border-color)", fontWeight: 600, fontSize: 13, color: "var(--text-secondary)" }}>
                          ML ANOMALY ANALYSIS
                        </div>
                        <div style={{ padding: 14 }}>
                          {s.is_anomalous ? (
                            <div>
                              <div style={{ display: "flex", gap: 16, marginBottom: 8 }}>
                                <div>
                                  <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 2 }}>Anomaly Score</div>
                                  <div className="mono" style={{ fontSize: 16, color: "#f87171", fontWeight: 700 }}>{s.anomaly_score?.toFixed(2) || "N/A"}</div>
                                </div>
                                <div>
                                  <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 2 }}>Classification</div>
                                  <div className="mono" style={{ fontSize: 14, color: "#f87171" }}>ANOMALOUS</div>
                                </div>
                                <div>
                                  <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 2 }}>Model</div>
                                  <div className="mono" style={{ fontSize: 13, color: "#e2e8f0" }}>Isolation Forest</div>
                                </div>
                              </div>
                              <div style={{ fontSize: 12, color: "var(--text-muted)" }}>This score represents statistical deviation from the observed traffic baseline. It is not itself proof of a vulnerability.</div>
                            </div>
                          ) : (
                            <div style={{ color: "var(--text-muted)", fontSize: 13 }}>Model: Isolation Forest — Not anomalous. Consistent with baseline traffic.</div>
                          )}
                        </div>
                      </div>
                    
                      {/* AI SECURITY ANALYSIS */}
                      {s.ai_assessment_structured ? (
                        <div style={{ background: "rgba(59, 130, 246, 0.08)", borderRadius: 8, border: "1px solid rgba(59, 130, 246, 0.2)", overflow: "hidden" }}>
                          <div style={{ padding: "10px 14px", background: "rgba(59, 130, 246, 0.15)", borderBottom: "1px solid rgba(59, 130, 246, 0.2)", fontWeight: 600, fontSize: 13, color: "#60a5fa", display: "flex", gap: 8, alignItems: "center" }}>
                            <span>🤖</span> AI SECURITY ANALYSIS
                            <span style={{ fontSize: 11, fontWeight: 400, color: "rgba(255,255,255,0.5)", marginLeft: "auto" }}>LLM-assisted interpretation of observed forensic evidence</span>
                          </div>
                          <div style={{ padding: 14, display: "flex", flexDirection: "column", gap: 12 }}>
                            
                            {/* Executive Interpretation */}
                            <div>
                              <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 4 }}>Executive Interpretation</div>
                              <div style={{ fontSize: 13, color: "#e2e8f0", lineHeight: 1.5 }}>
                                <span style={{ display: "inline-block", padding: "2px 6px", background: "rgba(255,255,255,0.1)", borderRadius: 4, fontSize: 10, marginRight: 8, verticalAlign: "middle" }}>INFERRED</span>
                                {s.ai_assessment_structured.executive_interpretation}
                              </div>
                            </div>
                    
                            {/* Evidence Correlation */}
                            {s.ai_assessment_structured.evidence_correlation?.length > 0 && (
                              <div>
                                <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 6 }}>Evidence Correlation</div>
                                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, border: "1px solid rgba(255,255,255,0.1)" }}>
                                  <thead>
                                    <tr style={{ background: "rgba(255,255,255,0.05)", textAlign: "left" }}>
                                      <th style={{ padding: "6px 8px", borderBottom: "1px solid rgba(255,255,255,0.1)" }}>Evidence</th>
                                      <th style={{ padding: "6px 8px", borderBottom: "1px solid rgba(255,255,255,0.1)" }}>Observation</th>
                                      <th style={{ padding: "6px 8px", borderBottom: "1px solid rgba(255,255,255,0.1)" }}>Security Implication</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {s.ai_assessment_structured.evidence_correlation.map((ec, idx) => (
                                      <tr key={idx} style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                                        <td style={{ padding: "6px 8px", color: "#94a3b8" }}>{ec.evidence_name}</td>
                                        <td style={{ padding: "6px 8px", color: "#e2e8f0", fontWeight: 500 }}>
                                          <span style={{ display: "inline-block", padding: "1px 4px", background: "rgba(52, 211, 153, 0.1)", color: "#34d399", borderRadius: 3, fontSize: 9, marginRight: 6 }}>OBSERVED</span>
                                          {ec.observation}
                                        </td>
                                        <td style={{ padding: "6px 8px", color: "#fb923c" }}>{ec.security_implication}</td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            )}
                    
                            {/* Reasoning */}
                            <div>
                              <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 4 }}>AI Reasoning</div>
                              <div style={{ fontSize: 13, color: "#cbd5e1", lineHeight: 1.5 }}>
                                <span style={{ display: "inline-block", padding: "2px 6px", background: "rgba(255,255,255,0.1)", borderRadius: 4, fontSize: 10, marginRight: 8, verticalAlign: "middle" }}>INFERRED</span>
                                {s.ai_assessment_structured.ai_reasoning}
                              </div>
                            </div>
                    
                            {/* Priority & Recommendations */}
                            <div style={{ display: "flex", gap: 24, marginTop: 4 }}>
                              <div>
                                <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 4 }}>Priority</div>
                                <div className="mono" style={{ fontSize: 13, fontWeight: 700, color: SEV_COLORS[s.ai_assessment_structured.priority] || "#e2e8f0" }}>
                                  {s.ai_assessment_structured.priority}
                                </div>
                              </div>
                              {s.ai_assessment_structured.recommended_actions?.length > 0 && (
                                <div style={{ flex: 1 }}>
                                  <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 4 }}>Recommended Actions</div>
                                  <ul style={{ margin: 0, paddingLeft: 16, fontSize: 12, color: "#34d399" }}>
                                    {s.ai_assessment_structured.recommended_actions.map((act, idx) => (
                                      <li key={idx} style={{ marginBottom: 2 }}>
                                        <span style={{ display: "inline-block", padding: "1px 4px", background: "rgba(56, 189, 248, 0.1)", color: "#38bdf8", borderRadius: 3, fontSize: 9, marginRight: 6 }}>RECOMMENDED</span>
                                        {act}
                                      </li>
                                    ))}
                                  </ul>
                                </div>
                              )}
                            </div>
                            
                            {/* Evidence Completeness */}
                            <div style={{ marginTop: 8, paddingTop: 12, borderTop: "1px dashed rgba(255,255,255,0.1)" }}>
                              <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 4 }}>Evidence Completeness</div>
                              <div style={{ fontSize: 12, color: s.stream_complete ? "#34d399" : "#fb923c" }}>
                                {s.stream_complete ? "HIGH — Full capture available. Observations are reliable." : "PARTIAL — Reassembly gaps detected. Some conclusions may be limited."}
                              </div>
                            </div>
                          </div>
                        </div>
                      ) : s.ai_assessment ? (
                        <div style={{ background: "rgba(59, 130, 246, 0.08)", borderRadius: 8, border: "1px solid rgba(59, 130, 246, 0.2)", padding: 14 }}>
                          <div style={{ fontSize: 11, fontWeight: 700, color: "#60a5fa", marginBottom: 6, textTransform: "uppercase", display: "flex", alignItems: "center", gap: 6 }}>
                            <span>🤖</span> AI Security Assessment
                          </div>
                          <div style={{ fontSize: 13, color: "#cbd5e1", lineHeight: 1.6 }}>{s.ai_assessment}</div>
                        </div>
                      ) : null}
                    
                      {/* PROTOCOL TIMELINE */}
                      {s.protocol_events?.length > 0 && (
                        <div style={{ background: "rgba(15, 23, 42, 0.4)", borderRadius: 8, border: "1px solid var(--border-color)", overflow: "hidden" }}>
                          <div style={{ padding: "10px 14px", background: "rgba(255, 255, 255, 0.03)", borderBottom: "1px solid var(--border-color)", fontWeight: 600, fontSize: 13, color: "var(--text-secondary)", display: "flex", gap: 8, alignItems: "center" }}>
                            <Terminal size={14} /> RAW PROTOCOL TIMELINE
                          </div>
                          <div style={{ background: "#0f172a", padding: 12, maxHeight: 300, overflowY: "auto" }}>
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
                    
                      {/* RAW DATA BUTTON */}
                      <div style={{ textAlign: "right" }}>
                        <button 
                          onClick={(e) => {
                            e.stopPropagation();
                            const jsonStr = JSON.stringify(s, null, 2);
                            const win = window.open("", "_blank");
                            win.document.write(`<pre style="background:#0f172a;color:#e2e8f0;padding:20px;font-size:12px;">${jsonStr}</pre>`);
                          }}
                          style={{ background: "transparent", border: "1px solid var(--border-color)", color: "var(--text-muted)", fontSize: 11, padding: "4px 8px", borderRadius: 4, cursor: "pointer" }}>
                          VIEW RAW JSON
                        </button>
                      </div>
                    
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
                      {f.confidence && (
                        <span style={{ fontSize: 11, padding: "2px 6px", borderRadius: 4, background: "rgba(255,255,255,0.1)", color: "#cbd5e1" }}>
                          {f.confidence} CONFIDENCE
                        </span>
                      )}
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
                    
                    {f.evidence ? (
                      <div style={{ marginTop: 12, padding: 12, background: "rgba(0,0,0,0.2)", borderRadius: 6, border: "1px solid rgba(255,255,255,0.05)" }}>
                        <div style={{ fontSize: 11, fontWeight: 600, color: "var(--text-muted)", marginBottom: 6, textTransform: "uppercase" }}>Forensic Evidence</div>
                        <ul style={{ margin: 0, paddingLeft: 18, fontSize: 13, color: "#e2e8f0" }}>
                          {Array.isArray(f.evidence) ? f.evidence.map((ev, idx) => <li key={idx} style={{ marginBottom: 4 }}>{ev}</li>) : (
                            <>
                              {f.evidence.details && <li style={{ marginBottom: 4 }}>{f.evidence.details}</li>}
                              {f.evidence.packet_numbers?.length > 0 && <li style={{ marginBottom: 4 }}>Packets: {f.evidence.packet_numbers.join(", ")}</li>}
                              {f.evidence.pcap && <li style={{ marginBottom: 4 }}>PCAP: {f.evidence.pcap}</li>}
                            </>
                          )}
                        </ul>
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

          {/* Packets Tab */}
          {activeTab === "packets" && (
            <div className="card">
              <div style={{ padding: 20 }}>
                {loadingPackets ? (
                  <div style={{ padding: 40, display: "flex", flexDirection: "column", gap: 16 }}>
                    <div className="loading-shimmer" style={{ width: "100%", height: 32, borderRadius: 4 }}></div>
                    <div className="loading-shimmer" style={{ width: "100%", height: 32, borderRadius: 4 }}></div>
                    <div className="loading-shimmer" style={{ width: "100%", height: 32, borderRadius: 4 }}></div>
                  </div>
                ) : packets.length === 0 ? (
                  <div style={{ padding: 40, textAlign: "center", color: "var(--text-muted)" }}>
                    No packets found or failed to load.
                  </div>
                ) : (
                  <>
                  <div style={{ maxHeight: selectedPacket ? 300 : 600, overflowY: "auto", borderBottom: selectedPacket ? "1px solid var(--border-color)" : "none" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                    <thead>
                      <tr style={{ borderBottom: "1px solid var(--border-color)", textAlign: "left", color: "var(--text-muted)" }}>
                        <th style={{ padding: "8px 12px" }}>No.</th>
                        <th style={{ padding: "8px 12px" }}>Time</th>
                        <th style={{ padding: "8px 12px" }}>Source</th>
                        <th style={{ padding: "8px 12px" }}>Destination</th>
                        <th style={{ padding: "8px 12px" }}>Protocol</th>
                        <th style={{ padding: "8px 12px" }}>Length</th>
                        <th style={{ padding: "8px 12px" }}>Info</th>
                      </tr>
                    </thead>
                    <tbody>
                      {packets.map((pkt, i) => (
                        <tr key={i} onClick={() => loadPacketDetail(pkt.packet_number)} style={{ borderBottom: "1px solid rgba(255,255,255,0.05)", cursor: "pointer", background: selectedPacket === pkt.packet_number ? "rgba(59, 130, 246, 0.15)" : "transparent" }} onMouseEnter={(e) => { if(selectedPacket !== pkt.packet_number) e.currentTarget.style.background = "rgba(255,255,255,0.05)"; }} onMouseLeave={(e) => { if(selectedPacket !== pkt.packet_number) e.currentTarget.style.background = "transparent"; }}>
                          <td style={{ padding: "8px 12px", color: "var(--text-muted)" }}>{pkt.packet_number}</td>
                          <td style={{ padding: "8px 12px", fontFamily: "monospace", color: "#e2e8f0" }}>{pkt.timestamp}</td>
                          <td style={{ padding: "8px 12px", color: "#38bdf8" }}>{pkt.source}</td>
                          <td style={{ padding: "8px 12px", color: "#a78bfa" }}>{pkt.destination}</td>
                          <td style={{ padding: "8px 12px", fontWeight: 600, color: "#60a5fa" }}>{pkt.protocol}</td>
                          <td style={{ padding: "8px 12px", color: "var(--text-muted)" }}>{pkt.length}</td>
                          <td style={{ padding: "8px 12px", color: "#cbd5e1" }}>{pkt.summary}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  </div>
                  {selectedPacket && (
                    <div style={{ marginTop: 24, borderTop: "1px solid var(--border-color)", paddingTop: 16 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
                        <h3 style={{ margin: 0, fontSize: 14, color: "#e2e8f0" }}>Packet {selectedPacket} Details</h3>
                        <button onClick={() => setSelectedPacket(null)} style={{ background: "transparent", border: "none", color: "var(--text-muted)", cursor: "pointer", padding: "4px 8px" }}>Close</button>
                      </div>
                      {loadingPacketDetail ? (
                        <div className="loading-shimmer" style={{ width: "100%", height: 200, borderRadius: 4 }}></div>
                      ) : (
                        <pre style={{ background: "#0f172a", padding: 16, borderRadius: 6, color: "#cbd5e1", fontSize: 12, overflowX: "auto", maxHeight: 400 }}>
                          {packetDetail}
                        </pre>
                      )}
                    </div>
                  )}
                </>
              )}
              </div>
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
          {activeTab === "remediation" && data.status === "COMPLETED" && sessions.filter((s) => s.ai_assessment_structured?.recommended_actions?.length || s.remediations?.length).length === 0 && (
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
          {activeTab === "remediation" && data.status === "COMPLETED" && sessions.filter((s) => s.ai_assessment_structured?.recommended_actions?.length || s.remediations?.length).length > 0 && (
            <div className="card">
              {sessions.filter((s) => s.ai_assessment_structured?.recommended_actions?.length || s.remediations?.length).map((s) => (
                <div key={s.session_id} style={{ marginBottom: 32 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12, paddingBottom: 10, borderBottom: "1px solid var(--border-color)" }}>
                    <span className={`severity-badge ${(s.severity || "INFO").toLowerCase()}`}>{s.severity || "INFO"}</span>
                    <h4 style={{ fontSize: 14, color: "var(--text-secondary)", margin: 0 }}>
                      {s.protocol} — {s.src_ip} → {s.dst_ip}
                    </h4>
                  </div>
                  
                  {/* AI Structured Recommendations */}
                  {s.ai_assessment_structured?.recommended_actions?.length > 0 && (
                    <div className="finding-item" style={{ marginBottom: 16 }}>
                      <div className="finding-header">
                        <span style={{ fontSize: 18 }}>🤖</span>
                        <span style={{ fontWeight: 600, fontSize: 14, color: "#60a5fa" }}>AI Recommended Actions</span>
                        <span className="severity-badge" style={{ marginLeft: "auto", background: "rgba(59, 130, 246, 0.12)", color: "#60a5fa" }}>
                          {s.ai_assessment_structured.priority || "RECOMMENDED"}
                        </span>
                      </div>
                      <div className="finding-desc" style={{ marginBottom: 12, paddingBottom: 12, borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                        <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 6 }}>AI Reasoning</div>
                        <div style={{ color: "#cbd5e1" }}>{s.ai_assessment_structured.ai_reasoning}</div>
                      </div>
                      <div>
                        <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 6 }}>Actions</div>
                        <ul style={{ margin: 0, paddingLeft: 16, fontSize: 13, color: "#34d399" }}>
                          {s.ai_assessment_structured.recommended_actions.map((act, idx) => (
                            <li key={idx} style={{ marginBottom: 6 }}>{act}</li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  )}

                  {/* Legacy Remediations */}
                  {s.remediations?.map((r, i) => (
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
