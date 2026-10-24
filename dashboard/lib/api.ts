// Minimal typed client for the Autonomous Security Agent Platform API.
export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";

async function j<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText} for ${path}`);
  return (await res.json()) as T;
}

export interface Overview {
  projects: number; assets: number; vulnerabilities: number;
  lab_confirmed: number; confirmed_authorized: number;
  agents: number; runs_running: number; runs_total: number;
}
export interface Scope { kind: string; value: string; is_lab_env: boolean; note?: string }
export interface Project { id: string; name: string; autonomy_level: number; scopes: Scope[] }
export interface Agent { agent_id: string; name: string; phase: number }
export interface Vulnerability {
  asset: string; vulnerability_id: string; cve: string | null; cwe: string | null;
  severity: string; status: string; confidence: string; remediation: string;
}
export interface RunSummary {
  run_id: string; objective: string; state: string;
  tool_calls_used: number; cost_usd: number; started_at: string | null;
}

export const api = {
  overview: () => j<Overview>("/overview"),
  agents: () => j<Agent[]>("/agents"),
  projects: () => j<Project[]>("/projects"),
  createProject: (body: unknown) =>
    j<Project>("/projects", { method: "POST", body: JSON.stringify(body) }),
  runs: (pid: string) => j<RunSummary[]>(`/projects/${pid}/runs`),
  startRun: (pid: string, body: unknown) =>
    j<{ run_id: string }>(`/projects/${pid}/runs`, { method: "POST", body: JSON.stringify(body) }),
  vulnerabilities: (pid: string) => j<Vulnerability[]>(`/projects/${pid}/vulnerabilities`),
  report: (rid: string) => j<any>(`/runs/${rid}/report`),
  reportUrl: (rid: string, format: "md" | "html" | "pdf") =>
    `${API_BASE}/runs/${rid}/report?format=${format}`,
  audit: (pid: string) => j<any[]>(`/projects/${pid}/audit`),
  knowledge: () => j<any[]>("/knowledge"),
  wsUrl: (rid: string) => `${API_BASE.replace(/^http/, "ws")}/ws/runs/${rid}`,
};
