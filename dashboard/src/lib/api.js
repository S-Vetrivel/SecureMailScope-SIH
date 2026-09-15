export const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8080/api/v1";

export async function fetchHealth() {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error("Failed to fetch backend health");
  return res.json();
}

export async function fetchDashboardSummary() {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error("Failed to fetch dashboard summary");
  return res.json();
}

export async function fetchAnalyses() {
  const res = await fetch(`${API_BASE}/analyses`);
  if (!res.ok) throw new Error("Failed to fetch analyses");
  return res.json();
}

export async function fetchAnalysis(id) {
  const res = await fetch(`${API_BASE}/analyses/${id}`);
  if (!res.ok) throw new Error("Failed to fetch analysis");
  return res.json();
}

export async function createAnalysis(pcapPath) {
  const res = await fetch(`${API_BASE}/analyses`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pcap_path: pcapPath }),
  });
  if (!res.ok) throw new Error("Failed to create analysis");
  return res.json();
}

export async function startAnalysis(id) {
  const res = await fetch(`${API_BASE}/analyses/${id}/start`, {
    method: "POST",
  });
  if (!res.ok) throw new Error("Failed to start analysis");
  return res.json();
}

export async function fetchAnalysisSessions(id) {
  const res = await fetch(`${API_BASE}/analyses/${id}/sessions`);
  if (!res.ok) throw new Error("Failed to fetch sessions");
  return res.json();
}

export async function fetchSessionDetail(id) {
  const res = await fetch(`${API_BASE}/sessions/${id}`);
  if (!res.ok) throw new Error("Failed to fetch session detail");
  return res.json();
}

export async function fetchAnalysisFindings(id) {
  const res = await fetch(`${API_BASE}/analyses/${id}/findings`);
  if (!res.ok) throw new Error("Failed to fetch findings");
  return res.json();
}

export async function fetchAnalysisSummary(id) {
  const res = await fetch(`${API_BASE}/analyses/${id}/summary`);
  if (!res.ok) throw new Error("Failed to fetch analysis summary");
  return res.json();
}

export async function uploadPCAP(file) {
  const formData = new FormData();
  formData.append("pcap", file);
  const res = await fetch(`${API_BASE}/pcaps`, {
    method: "POST",
    body: formData,
  });
  if (!res.ok) throw new Error("Upload failed");
  return res.json();
}

export function getReportURL(analysisId, format = "json") {
  return `${API_BASE}/analyses/${analysisId}/summary?format=${format}`;
}
