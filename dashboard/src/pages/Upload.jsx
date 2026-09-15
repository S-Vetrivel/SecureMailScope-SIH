import { useState, useRef, useCallback } from "react";
import Sidebar from "../components/Sidebar";
import { Upload, FileUp, CheckCircle, Loader, AlertCircle } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { uploadPCAP, createAnalysis, startAnalysis } from "../lib/api";

export default function UploadPage() {
  const [state, setState] = useState("idle");
  const [dragOver, setDragOver] = useState(false);
  const [fileName, setFileName] = useState("");
  const [progress, setProgress] = useState(0);
  const [analysisId, setAnalysisId] = useState("");
  const [errorMsg, setErrorMsg] = useState("");
  const fileRef = useRef(null);
  const navigate = useNavigate();

  const handleUpload = useCallback(
    async (file) => {
      if (!file.name.endsWith(".pcap") && !file.name.endsWith(".pcapng")) {
        setErrorMsg("Only .pcap and .pcapng files are accepted");
        setState("error");
        return;
      }

      setFileName(file.name);
      setState("uploading");
      setProgress(0);

      // Simulate progress for UX
      const interval = setInterval(() => {
        setProgress((p) => Math.min(p + Math.random() * 15, 90));
      }, 300);

      try {
        const uploadRes = await uploadPCAP(file);
        const analysis = await createAnalysis(uploadRes.pcap_path);
        await startAnalysis(analysis.id);

        clearInterval(interval);
        setAnalysisId(analysis.id);
        setProgress(100);
        setState("success");
      } catch (err) {
        clearInterval(interval);
        setErrorMsg(
          "Upload failed. Make sure the backend server is running on port 8080."
        );
        setState("error");
      }
    },
    []
  );

  const handleDrop = useCallback(
    (e) => {
      e.preventDefault();
      setDragOver(false);
      const file = e.dataTransfer.files[0];
      if (file) handleUpload(file);
    },
    [handleUpload]
  );

  return (
    <div className="app-layout">
      <Sidebar />
      <main className="main-content">
        <header className="app-header">
          <div>
            <h2 className="header-title">Upload PCAP</h2>
            <p className="header-breadcrumb">
              Upload a packet capture file for cryptographic analysis
            </p>
          </div>
        </header>

        <div className="page-content animate-in">
          <div style={{ maxWidth: 720, margin: "0 auto" }}>
            {state === "idle" && (
              <div
                className={`dropzone ${dragOver ? "drag-over" : ""}`}
                onDragOver={(e) => {
                  e.preventDefault();
                  setDragOver(true);
                }}
                onDragLeave={() => setDragOver(false)}
                onDrop={handleDrop}
                onClick={() => fileRef.current?.click()}
              >
                <input
                  ref={fileRef}
                  type="file"
                  accept=".pcap,.pcapng"
                  style={{ display: "none" }}
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (f) handleUpload(f);
                  }}
                />
                <div className="drop-icon">
                  <Upload size={48} color="var(--accent-blue)" />
                </div>
                <h3>Drop your PCAP file here</h3>
                <p>
                  or click to browse — supports .pcap and .pcapng files
                </p>
                <p style={{ marginTop: 16, fontSize: 12, color: "var(--text-muted)" }}>
                  The file will be analyzed for SMTP, IMAP, and POP3
                  cryptographic security
                </p>
              </div>
            )}

            {state === "uploading" && (
              <div className="card" style={{ textAlign: "center", padding: 48 }}>
                <Loader
                  size={48}
                  color="var(--accent-blue)"
                  style={{
                    animation: "spin 1s linear infinite",
                    marginBottom: 20,
                  }}
                />
                <h3 style={{ marginBottom: 8 }}>Uploading & Analyzing</h3>
                <p className="mono" style={{ color: "var(--text-secondary)", marginBottom: 20 }}>
                  {fileName}
                </p>
                <div
                  style={{
                    width: "100%",
                    height: 6,
                    background: "var(--border)",
                    borderRadius: 3,
                    overflow: "hidden",
                  }}
                >
                  <div
                    style={{
                      width: `${progress}%`,
                      height: "100%",
                      background: "var(--gradient-brand)",
                      borderRadius: 3,
                      transition: "width 0.3s ease",
                    }}
                  />
                </div>
                <p
                  style={{
                    marginTop: 12,
                    fontSize: 13,
                    color: "var(--text-muted)",
                  }}
                >
                  {progress < 50
                    ? "Uploading file..."
                    : progress < 90
                      ? "Processing PCAP..."
                      : "Finalizing..."}
                </p>
                <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
              </div>
            )}

            {state === "success" && (
              <div className="card" style={{ textAlign: "center", padding: 48 }}>
                <CheckCircle
                  size={56}
                  color="var(--accent-green)"
                  style={{ marginBottom: 20 }}
                />
                <h3 style={{ marginBottom: 8, color: "var(--accent-green)" }}>
                  Upload Successful!
                </h3>
                <p style={{ color: "var(--text-secondary)", marginBottom: 8 }}>
                  <span className="mono">{fileName}</span> has been submitted
                  for analysis.
                </p>
                <p
                  style={{
                    fontSize: 13,
                    color: "var(--text-muted)",
                    marginBottom: 24,
                  }}
                >
                  Analysis ID:{" "}
                  <span className="mono">{analysisId.slice(0, 8)}...</span>
                </p>
                <div style={{ display: "flex", gap: 12, justifyContent: "center" }}>
                  <button
                    className="btn btn-primary"
                    onClick={() =>
                      navigate(`/analysis/${analysisId}`)
                    }
                  >
                    <FileUp size={16} />
                    View Analysis
                  </button>
                  <button
                    className="btn btn-secondary"
                    onClick={() => {
                      setState("idle");
                      setProgress(0);
                    }}
                  >
                    Upload Another
                  </button>
                </div>
              </div>
            )}

            {state === "error" && (
              <div className="card" style={{ textAlign: "center", padding: 48 }}>
                <AlertCircle
                  size={56}
                  color="var(--severity-critical)"
                  style={{ marginBottom: 20 }}
                />
                <h3
                  style={{
                    marginBottom: 8,
                    color: "var(--severity-critical)",
                  }}
                >
                  Upload Failed
                </h3>
                <p style={{ color: "var(--text-secondary)", marginBottom: 24 }}>
                  {errorMsg}
                </p>
                <button
                  className="btn btn-primary"
                  onClick={() => {
                    setState("idle");
                    setErrorMsg("");
                  }}
                >
                  Try Again
                </button>
              </div>
            )}

            {/* How it works */}
            <div className="card" style={{ marginTop: 24 }}>
              <div className="card-header">
                <span className="card-title">How It Works</span>
              </div>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(4, 1fr)",
                  gap: 20,
                  textAlign: "center",
                }}
              >
                {[
                  { step: "1", title: "Upload", desc: "Submit PCAP file" },
                  {
                    step: "2",
                    title: "Parse",
                    desc: "Go engine extracts TLS metadata",
                  },
                  {
                    step: "3",
                    title: "Analyze",
                    desc: "AI scores risks & anomalies",
                  },
                  {
                    step: "4",
                    title: "Report",
                    desc: "View findings & remediation",
                  },
                ].map((s) => (
                  <div key={s.step}>
                    <div
                      style={{
                        width: 36,
                        height: 36,
                        borderRadius: "50%",
                        background: "var(--gradient-brand)",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        fontWeight: 700,
                        fontSize: 14,
                        margin: "0 auto 10px",
                      }}
                    >
                      {s.step}
                    </div>
                    <div
                      style={{ fontWeight: 600, fontSize: 14, marginBottom: 4 }}
                    >
                      {s.title}
                    </div>
                    <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                      {s.desc}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
