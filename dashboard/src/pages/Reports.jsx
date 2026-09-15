import { useEffect, useState } from "react";
import Sidebar from "../components/Sidebar";
import { fetchAnalyses, getReportURL } from "../lib/api";
import { FileJson, FileText, Download, FileSearch } from "lucide-react";
import { Link } from "react-router-dom";

function scoreColor(score) {
  if (score >= 8) return "#ef4444";
  if (score >= 6) return "#f97316";
  if (score >= 4) return "#eab308";
  if (score >= 2) return "#22c55e";
  return "#3b82f6";
}

export default function ReportsPage() {
  const [analyses, setAnalyses] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchAnalyses()
      .then((d) => {
        setAnalyses((d.analyses || []).filter((a) => a.status === "completed"));
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
            <h2 className="header-title">Reports</h2>
            <p className="header-breadcrumb">
              Export forensic reports in JSON and HTML formats
            </p>
          </div>
        </header>

        <div className="page-content animate-in">
          {loading ? (
            <div style={{ textAlign: "center", padding: 60, color: "var(--text-muted)" }}>
              Loading completed analyses...
            </div>
          ) : analyses.length === 0 ? (
            <div className="card" style={{ textAlign: "center", padding: 60 }}>
              <FileSearch size={48} color="var(--text-muted)" style={{ marginBottom: 16 }} />
              <h3 style={{ marginBottom: 8 }}>No completed analyses</h3>
              <p style={{ color: "var(--text-muted)", marginBottom: 20 }}>
                Upload and analyze a PCAP file to generate exportable reports.
              </p>
              <Link to="/upload" className="btn btn-primary">
                Upload PCAP
              </Link>
            </div>
          ) : (
            <div style={{ display: "grid", gap: 16 }}>
              {analyses.map((a) => (
                <div key={a.id} className="card">
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                    }}
                  >
                    <div>
                      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
                        <span className="mono" style={{ fontSize: 16, fontWeight: 600 }}>
                          {a.pcap_filename}
                        </span>
                        <span className={`severity-badge ${(a.overall_severity || "INFO").toLowerCase()}`}>
                          {a.overall_severity || "INFO"}
                        </span>
                      </div>
                      <div style={{ display: "flex", gap: 24, fontSize: 13, color: "var(--text-muted)" }}>
                        <span>
                          Score:{" "}
                          <strong style={{ color: scoreColor(a.overall_score || 0) }}>
                            {(a.overall_score || 0).toFixed(1)}
                          </strong>
                        </span>
                        <span>Sessions: {a.total_sessions}</span>
                        <span>Anomalies: {a.anomaly_count}</span>
                        <span>{new Date(a.created_at).toLocaleString()}</span>
                      </div>
                    </div>

                    <div style={{ display: "flex", gap: 8 }}>
                      <a
                        href={getReportURL(a.id, "json")}
                        className="btn btn-secondary"
                        style={{ fontSize: 13 }}
                      >
                        <FileJson size={14} />
                        JSON
                        <Download size={12} />
                      </a>
                      <a
                        href={getReportURL(a.id, "html")}
                        className="btn btn-secondary"
                        style={{ fontSize: 13 }}
                      >
                        <FileText size={14} />
                        HTML
                        <Download size={12} />
                      </a>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Report format info */}
          <div className="card" style={{ marginTop: 24 }}>
            <div className="card-header">
              <span className="card-title">Report Formats</span>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 20 }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                  <FileJson size={20} color="var(--accent-blue)" />
                  <strong style={{ fontSize: 14 }}>JSON</strong>
                </div>
                <p style={{ fontSize: 13, color: "var(--text-secondary)" }}>
                  Machine-readable format. Includes all session details, findings,
                  risk scores, anomaly data, and remediation snippets. Ideal for
                  SIEM integration.
                </p>
              </div>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                  <FileText size={20} color="var(--accent-green)" />
                  <strong style={{ fontSize: 14 }}>HTML</strong>
                </div>
                <p style={{ fontSize: 13, color: "var(--text-secondary)" }}>
                  Professional forensic report with styled tables and dark theme.
                  Print-ready — use browser&apos;s Print to PDF for PDF export.
                </p>
              </div>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                  <Download size={20} color="var(--accent-purple)" />
                  <strong style={{ fontSize: 14 }}>PDF</strong>
                </div>
                <p style={{ fontSize: 13, color: "var(--text-secondary)" }}>
                  Download the HTML report and use Ctrl+P (Print to PDF) for a
                  professional PDF document suitable for management reporting.
                </p>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
