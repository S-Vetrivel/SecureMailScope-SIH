export const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8080/api";

export async function fetchDashboardSummary() {
  const res = await fetch(`${API_BASE}/dashboard/summary`);
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

export async function fetchAnalysisSessions(id) {
  const res = await fetch(`${API_BASE}/analyses/${id}/sessions`);
  if (!res.ok) throw new Error("Failed to fetch sessions");
  return res.json();
}

export async function uploadPCAP(file) {
  const formData = new FormData();
  formData.append("pcap", file);
  const res = await fetch(`${API_BASE}/upload`, {
    method: "POST",
    body: formData,
  });
  if (!res.ok) throw new Error("Upload failed");
  return res.json();
}

export function getReportURL(analysisId, format) {
  return `${API_BASE}/analyses/${analysisId}/report?format=${format}`;
}
