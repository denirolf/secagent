"use client";
import { useEffect, useState } from "react";
import { api, Project } from "@/lib/api";

export default function Page() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [err, setErr] = useState("");
  useEffect(() => {
    api.projects().then(setProjects).catch((e) => setErr(String(e)));
  }, []);

  return (
    <>
      <h1>Security Lab</h1>
      <p className="sub">Authorized isolated-lab environments. Validation runs reproduce findings here only.</p>
      {err && <p className="err">{err}</p>}
      <p className="note">
        Exploit validation runs exclusively against environments flagged as a lab
        (<span className="mono">is_lab_env</span>). The validation agent hard-refuses any
        target that is not an authorized lab, runs only passive reproduction checks, and
        can reset the lab container between tests.
      </p>
      {projects.map((p) => {
        const labs = p.scopes.filter((s) => s.is_lab_env || s.kind === "lab_env");
        return (
          <div key={p.id} className="card" style={{ marginBottom: 14 }}>
            <b>{p.name}</b>
            <table style={{ marginTop: 10 }}>
              <thead><tr><th>Kind</th><th>Value</th><th>Lab</th></tr></thead>
              <tbody>
                {labs.length === 0 && <tr><td colSpan={3} style={{ color: "var(--muted)" }}>No lab environment authorized.</td></tr>}
                {labs.map((s, i) => (
                  <tr key={i}>
                    <td className="mono">{s.kind}</td>
                    <td className="mono">{s.value}</td>
                    <td><span className="badge st-lab_confirmed">lab</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        );
      })}
    </>
  );
}
