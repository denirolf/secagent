"use client";
import { useEffect, useRef, useState } from "react";
import { api, Project } from "@/lib/api";

export default function Page() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [err, setErr] = useState("");
  const [name, setName] = useState("Juice Shop Lab");
  const [autonomy, setAutonomy] = useState(3);
  const [scopeKind, setScopeKind] = useState("cidr");
  const [scopeValue, setScopeValue] = useState("172.18.0.0/16");

  const reload = () => api.projects().then(setProjects).catch((e) => setErr(String(e)));
  useEffect(() => { reload(); }, []);

  async function create() {
    try {
      await api.createProject({
        name, autonomy_level: autonomy,
        scopes: [{ kind: scopeKind, value: scopeValue, is_lab_env: true }],
      });
      reload();
    } catch (e) { setErr(String(e)); }
  }

  return (
    <>
      <h1>Projects</h1>
      <p className="sub">Define a project, its authorized scope, and start runs.</p>
      {err && <p className="err">{err}</p>}

      <div className="card" style={{ marginBottom: 20 }}>
        <b>New project</b>
        <div className="row" style={{ marginTop: 10 }}>
          <div style={{ flex: 2, minWidth: 200 }}>
            <label>Name</label>
            <input value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div style={{ flex: 1, minWidth: 140 }}>
            <label>Autonomy level</label>
            <select value={autonomy} onChange={(e) => setAutonomy(Number(e.target.value))}>
              <option value={1}>1 — Assisted</option>
              <option value={2}>2 — Semi-autonomous</option>
              <option value={3}>3 — Autonomous Lab</option>
            </select>
          </div>
        </div>
        <div className="row">
          <div style={{ flex: 1, minWidth: 140 }}>
            <label>Authorized scope kind</label>
            <select value={scopeKind} onChange={(e) => setScopeKind(e.target.value)}>
              <option value="cidr">cidr</option>
              <option value="ip">ip</option>
              <option value="domain">domain</option>
              <option value="lab_env">lab_env</option>
            </select>
          </div>
          <div style={{ flex: 2, minWidth: 200 }}>
            <label>Scope value (lab environment)</label>
            <input value={scopeValue} onChange={(e) => setScopeValue(e.target.value)} />
          </div>
        </div>
        <div style={{ marginTop: 14 }}><button onClick={create}>Create project</button></div>
        <p className="note" style={{ marginTop: 12 }}>
          Scope is the allowlist. Only targets inside it can be tested; the Scope Engine
          re-resolves DNS and blocks everything else.
        </p>
      </div>

      {projects.map((p) => <ProjectCard key={p.id} p={p} />)}
    </>
  );
}

function ProjectCard({ p }: { p: Project }) {
  const [objective, setObjective] = useState("Assess the authorized lab target");
  const [target, setTarget] = useState("http://172.18.0.4:3000");
  const [useLlm, setUseLlm] = useState(false);
  const [validate, setValidate] = useState(true);
  const [authCheck, setAuthCheck] = useState(true);
  const [reasoning, setReasoning] = useState(true);
  const [events, setEvents] = useState<string[]>([]);
  const [runId, setRunId] = useState("");
  const wsRef = useRef<WebSocket | null>(null);

  async function start() {
    setEvents([]);
    const { run_id } = await api.startRun(p.id, {
      objective, target, use_llm: useLlm,
      validate_in_lab: validate, auth_check: authCheck, reasoning,
    });
    setRunId(run_id);
    const ws = new WebSocket(api.wsUrl(run_id));
    wsRef.current = ws;
    ws.onmessage = (m) => {
      const ev = JSON.parse(m.data);
      if (ev.type === "decision") setEvents((xs) => [...xs, `▸ ${ev.step}: ${ev.rationale}`]);
      else if (ev.type === "done") setEvents((xs) => [...xs, `✓ done — ${ev.findings} finding(s)`]);
    };
  }

  return (
    <div className="card" style={{ marginBottom: 16 }}>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <b>{p.name}</b>
        <span className="mono" style={{ color: "var(--muted)" }}>
          autonomy {p.autonomy_level} · {p.scopes.map((s) => `${s.kind}:${s.value}`).join(", ")}
        </span>
      </div>
      <div className="row" style={{ marginTop: 10 }}>
        <div style={{ flex: 2, minWidth: 220 }}>
          <label>Objective</label>
          <input value={objective} onChange={(e) => setObjective(e.target.value)} />
        </div>
        <div style={{ flex: 2, minWidth: 220 }}>
          <label>Target (must be in scope)</label>
          <input value={target} onChange={(e) => setTarget(e.target.value)} />
        </div>
      </div>
      <div className="row" style={{ marginTop: 10, alignItems: "center" }}>
        <label style={{ margin: 0 }}><input type="checkbox" style={{ width: "auto" }} checked={useLlm} onChange={(e) => setUseLlm(e.target.checked)} /> LLM agents</label>
        <label style={{ margin: 0 }}><input type="checkbox" style={{ width: "auto" }} checked={validate} onChange={(e) => setValidate(e.target.checked)} /> Validate in lab</label>
        <label style={{ margin: 0 }}><input type="checkbox" style={{ width: "auto" }} checked={authCheck} onChange={(e) => setAuthCheck(e.target.checked)} /> Auth check</label>
        <label style={{ margin: 0 }}><input type="checkbox" style={{ width: "auto" }} checked={reasoning} onChange={(e) => setReasoning(e.target.checked)} /> Reasoning</label>
        <button onClick={start}>Start run</button>
      </div>
      {runId && (
        <>
          <div style={{ marginTop: 12, fontSize: 12, color: "var(--muted)" }}>
            Run <span className="mono">{runId}</span> · live:
          </div>
          <pre style={{ marginTop: 6, maxHeight: 220 }}>{events.join("\n") || "waiting for events…"}</pre>
          <a href={`/reports?run=${runId}`}>View report →</a>
        </>
      )}
    </div>
  );
}
