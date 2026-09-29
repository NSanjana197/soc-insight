const API_BASE = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`${res.status} ${res.statusText}: ${text}`);
  }
  const contentType = res.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return res.json();
  }
  return res;
}

export const api = {
  getDashboardSummary: () => request("/dashboard/summary"),
  getIncidents: () => request("/incidents/"),
  getIncident: (id) => request(`/incidents/${id}`),
  updateIncidentStatus: (id, status) =>
    request(`/incidents/${id}/status?status=${encodeURIComponent(status)}`, {
      method: "PATCH",
    }),
  getReportUrl: (id) => `${API_BASE}/incidents/${id}/report.pdf`,
  runSimulation: () => request("/simulate", { method: "POST" }),
  getAlerts: () => request("/alerts/"),
};

export { API_BASE };
