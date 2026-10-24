"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";

export default function Page() {
  const [runId, setRunId] = useState("");
  const [report, setReport] = useState<any>(null);
  const [err, setErr] = useState("");
  const [raw, setRaw] = useState(false);

  // Pre-fill from ?run= without useSearchParams (keeps the build Suspense-free).
  useEffect(() => {
    const q = new URLSearchParams(window.location.search).get("run");
    if (q) { setRunId(q); load(q); }
  }, []);

  async function load(id: string) {
    setErr(""); setReport(null);
    try { setReport(await api.report(id)); }
    catch (e) { setErr(String(e)); }
  }

  const s = report?.summary;
  const r = report?.reasoning;

  return (
    <>
      <h1>Reports</h1>
      <p className="sub">Fetch a run&apos;s vulnerability report (JSON is the canonical artifact).</p>
      <div className="row" style={{ alignItems: "flex-end", marginBottom: 18 }}>
        <div style={{ flex: 1, minWidth: 260 }}>
          <label>Run ID</label>
          <input value={runId} onChange={(e) => setRunId(e.target.value)} placeholder="run uuid" />
        </div>
        <button onClick={() => load(runId)}>Load</button>
      </div>
      {err && <p className="err">{err}</p>}

      {report && (
        <>
          <div className="grid" style={{ marginBottom: 18 }}>
            <div className="card stat"><div className="n">{s.findings_total}</div><div className="l">Findings</div></div>
            <div className="card stat"><div className="n">{s.lab_confirmed ?? 0}</div><div className="l">Lab-confirmed</div></div>
            <div className="card stat"><div className="n">{report.run?.state}</div><div className="l">Run state</div></div>
            <div className="card stat"><div className="n">{report.assets?.length ?? 0}</div><div className="l">Assets</div></div>
          </div>
          <p className="note" style={{ marginBottom: 18 }}>{s.note}</p>

          {report.narrative && (
            <div className="card" style={{ marginBottom: 18 }}>
              <b>Executive summary</b>
              <p style={{ marginTop: 6 }}>{report.narrative.headline}</p>
              <p style={{ color: "var(--muted)", fontSize: 13 }}>{report.narrative.overview}</p>
              {report.narrative.key_findings?.length > 0 && (
                <ul style={{ fontSize: 13 }}>
                  {report.narrative.key_findings.map((k: string, i: number) => <li key={i}>{k}</li>)}
                </ul>
              )}
            </div>
          )}

          <div style={{ marginBottom: 18, fontSize: 14 }}>
            Download:{" "}
            <a href={api.reportUrl(runId, "md")} target="_blank" rel="noreferrer">Markdown</a>{" · "}
            <a href={api.reportUrl(runId, "html")} target="_blank" rel="noreferrer">HTML</a>{" · "}
            <a href={api.reportUrl(runId, "pdf")} target="_blank" rel="noreferrer">PDF</a>
          </div>

          <div className="card" style={{ marginBottom: 18 }}>
            <b>Findings</b>
            <table style={{ marginTop: 10 }}>
              <thead><tr><th>ID</th><th>CWE</th><th>Severity</th><th>Status</th><th>Evidence</th></tr></thead>
              <tbody>
                {report.findings.map((f: any) => (
                  <tr key={f.vulnerability_id}>
                    <td className="mono">{f.vulnerability_id}</td>
                    <td>{f.cwe || "—"}</td>
                    <td><span className={`badge sev-${f.severity}`}>{f.severity}</span></td>
                    <td><span className={`badge st-${f.status}`}>{f.status}</span></td>
                    <td style={{ maxWidth: 360 }}>{f.evidence?.[0]?.summary}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {r && (
            <div className="card" style={{ marginBottom: 18 }}>
              <b>Security reasoning</b>
              <p style={{ color: "var(--muted)", fontSize: 12 }}>OWASP: {JSON.stringify(r.owasp_summary)}</p>
              <div style={{ fontSize: 13 }}>
                <b>Risk chains:</b>
                {r.risk_graph?.edges?.length ? (
                  <ul>{r.risk_graph.edges.map((e: any, i: number) => (
                    <li key={i}><span className="mono">{e.from} → {e.to}</span>: {e.relation}</li>
                  ))}</ul>
                ) : <span style={{ color: "var(--muted)" }}> none on this target</span>}
              </div>
              <div style={{ fontSize: 13, marginTop: 8 }}>
                <b>Proposed investigations:</b>
                <ul>{(r.proposed_investigations || []).map((x: string, i: number) => <li key={i}>{x}</li>)}</ul>
              </div>
            </div>
          )}

          <button className="secondary" onClick={() => setRaw(!raw)}>{raw ? "Hide" : "Show"} raw JSON</button>
          {raw && <pre style={{ marginTop: 12 }}>{JSON.stringify(report, null, 2)}</pre>}
        </>
      )}
    </>
  );
}
