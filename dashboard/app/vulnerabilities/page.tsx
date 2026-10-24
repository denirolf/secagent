"use client";
import { useEffect, useState } from "react";
import { api, Project, Vulnerability } from "@/lib/api";

export default function Page() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [pid, setPid] = useState("");
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [err, setErr] = useState("");

  useEffect(() => {
    api.projects().then((ps) => { setProjects(ps); if (ps[0]) setPid(ps[0].id); })
      .catch((e) => setErr(String(e)));
  }, []);
  useEffect(() => {
    if (pid) api.vulnerabilities(pid).then(setVulns).catch((e) => setErr(String(e)));
  }, [pid]);

  return (
    <>
      <h1>Vulnerabilities</h1>
      <p className="sub">Findings with severity, validation status, and remediation.</p>
      {err && <p className="err">{err}</p>}
      <div style={{ maxWidth: 320, marginBottom: 16 }}>
        <label>Project</label>
        <select value={pid} onChange={(e) => setPid(e.target.value)}>
          {projects.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
      </div>
      <div className="card">
        <table>
          <thead><tr><th>ID</th><th>Asset</th><th>CWE</th><th>Severity</th><th>Status</th><th>Confidence</th><th>Remediation</th></tr></thead>
          <tbody>
            {vulns.map((v) => (
              <tr key={v.vulnerability_id}>
                <td className="mono">{v.vulnerability_id}</td>
                <td>{v.asset}</td>
                <td>{v.cwe || "—"}</td>
                <td><span className={`badge sev-${v.severity}`}>{v.severity}</span></td>
                <td><span className={`badge st-${v.status}`}>{v.status}</span></td>
                <td>{v.confidence}</td>
                <td style={{ maxWidth: 320 }}>{v.remediation}</td>
              </tr>
            ))}
            {vulns.length === 0 && <tr><td colSpan={7} style={{ color: "var(--muted)" }}>No vulnerabilities yet — start a run.</td></tr>}
          </tbody>
        </table>
      </div>
    </>
  );
}
