"use client";
import { useEffect, useState } from "react";
import { api, Overview } from "@/lib/api";

const STATS: [keyof Overview, string][] = [
  ["projects", "Projects"],
  ["assets", "Assets analyzed"],
  ["vulnerabilities", "Vulnerabilities"],
  ["lab_confirmed", "Lab-confirmed"],
  ["confirmed_authorized", "Confirmed (authorized)"],
  ["agents", "Agents"],
  ["runs_running", "Runs active"],
  ["runs_total", "Runs total"],
];

export default function Page() {
  const [o, setO] = useState<Overview | null>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    api.overview().then(setO).catch((e) => setErr(String(e)));
  }, []);

  return (
    <>
      <h1>Overview</h1>
      <p className="sub">Authorized, isolated-lab security testing — live platform status.</p>
      {err && <p className="err">Cannot reach the API: {err}</p>}
      <div className="grid">
        {STATS.map(([k, label]) => (
          <div key={k} className="card stat">
            <div className="n">{o ? o[k] : "—"}</div>
            <div className="l">{label}</div>
          </div>
        ))}
      </div>
      <p className="note" style={{ marginTop: 22 }}>
        Findings progress through <b>suspected → lab_confirmed → confirmed_authorized</b>.
        A scanner result is a signal, not a confirmation; confirmed_authorized is never set
        automatically.
      </p>
    </>
  );
}
