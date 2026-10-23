"use client";
import { useEffect, useState } from "react";
import { api, Agent } from "@/lib/api";

export default function Page() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [err, setErr] = useState("");
  useEffect(() => {
    api.agents().then(setAgents).catch((e) => setErr(String(e)));
  }, []);
  return (
    <>
      <h1>Agents</h1>
      <p className="sub">The specialized agents and the phase each is implemented in.</p>
      {err && <p className="err">{err}</p>}
      <div className="card">
        <table>
          <thead><tr><th>Agent</th><th>ID</th><th>Phase</th><th>Status</th></tr></thead>
          <tbody>
            {agents.map((a) => (
              <tr key={a.agent_id}>
                <td>{a.name}</td>
                <td className="mono">{a.agent_id}</td>
                <td>Phase {a.phase}</td>
                <td><span className="badge st-lab_confirmed">available</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
