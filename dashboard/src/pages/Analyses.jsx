import { useEffect, useState } from "react";
import Sidebar from "../components/Sidebar";
import { Link } from "react-router-dom";
import { FileSearch, ExternalLink } from "lucide-react";
import { fetchAnalyses } from "../lib/api";

function scoreColor(score) {
  if (score >= 8) return "#ef4444";
  if (score >= 6) return "#f97316";
  if (score >= 4) return "#eab308";
  if (score >= 2) return "#22c55e";
  return "#3b82f6";
}

export default function AnalysesPage() {
  const [analyses, setAnalyses] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchAnalyses()
      .then((d) => {
        setAnalyses(d.analyses || []);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  return (
    <div className="app-layout">
      <Sidebar />
      <main className="main-content">
        <header className="app-header">
          <div>
            <h2 className="header-title">Analyses</h2>
            <p className="header-breadcrumb">
              All PCAP analysis runs and their results
            </p>
          </div>
          <Link to="/upload" className="btn btn-primary">
            <FileSearch size={16} /> New Analysis
          </Link>
        </header>

        <div className="page-content animate-in">
          <div className="card">
            {loading ? (
              <div style={{ padding: 40, textAlign: "center", color: "var(--text-muted)" }}>
                Loading analyses...
              </div>
            ) : analyses.length === 0 ? (
              <div style={{ padding: 40, textAlign: "center" }}>
                <FileSearch size={48} color="var(--text-muted)" style={{ marginBottom: 16 }} />
                <h3 style={{ marginBottom: 8 }}>No analyses yet</h3>
                <p style={{ color: "var(--text-muted)", marginBottom: 20 }}>
                  Upload a PCAP file to get started.
                </p>
                <Link to="/upload" className="btn btn-primary">
                  Upload PCAP
                </Link>
              </div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>PCAP File</th>
                    <th>Status</th>
                    <th>Risk Score</th>
                    <th>Severity</th>
                    <th>Sessions</th>
                    <th>Anomalies</th>
                    <th>Date</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {analyses.map((a) => (
                    <tr key={a.id}>
                      <td className="mono">{a.pcap_filename}</td>
                      <td>
                        <span className={`status-badge ${a.status}`}>
                          <span className="status-dot" />
                          {a.status}
                        </span>
                      </td>
                      <td style={{ fontWeight: 700, color: scoreColor(a.overall_score) }}>
                        {(a.overall_score || 0).toFixed(1)}
                      </td>
                      <td>
                        <span className={`severity-badge ${(a.overall_severity || "INFO").toLowerCase()}`}>
                          {a.overall_severity || "INFO"}
                        </span>
                      </td>
                      <td>{a.total_sessions}</td>
                      <td>{a.anomaly_count}</td>
                      <td style={{ color: "var(--text-muted)", fontSize: 13 }}>
                        {new Date(a.created_at).toLocaleString()}
                      </td>
                      <td>
                        {a.status === "completed" && (
                          <Link
                            to={`/analysis/${a.id}`}
                            style={{ color: "var(--accent-blue)" }}
                          >
                            <ExternalLink size={16} />
                          </Link>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
