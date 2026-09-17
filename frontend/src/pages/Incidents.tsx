import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";

interface Incident {
  id: number;
  code: string;
  title: string;
  status: string;
  severity: string;
  risk_score: number;
  tag: string | null;
  event_id: number | null;
  created_at: string;
  updated_at: string | null;
}

const SEV_COLOR: Record<string, string> = { critica: "#f43f5e", alta: "#fb923c", media: "#facc15", baixa: "#38bdf8", info: "#64748b" };
const STATUS_LABEL: Record<string, string> = { backlog: "BackLog", em_andamento: "Em Andamento", concluido: "Concluído" };
const STATUS_COLOR: Record<string, string> = { backlog: "#94a3b8", em_andamento: "#facc15", concluido: "#34d399" };

export default function Incidents() {
  const [items, setItems] = useState<Incident[]>([]);
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(true);

  function load() {
    const qs = status ? `?status_filter=${status}` : "";
    setLoading(true);
    api.get<Incident[]>(`/incidents${qs}`).then((data) => {
      setItems(data);
      setLoading(false);
    });
  }

  useEffect(() => {
    load();
    const timer = setInterval(load, 8000);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status]);

  async function updateStatus(id: number, next: string) {
    const updated = await api.patch<Incident>(`/incidents/${id}`, { status: next });
    setItems((prev) => prev.map((i) => (i.id === id ? updated : i)));
  }

  return (
    <div className="p-8 flex flex-col gap-5 max-w-[1400px]">
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight" style={{ color: "var(--text)" }}>
            Incidentes
          </h1>
          <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>
            Abertos automaticamente quando o motor de regras confirma uma skill — BackLog → Em Andamento → Concluído
          </p>
        </div>
        <select
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          className="text-sm rounded-lg px-3 py-2"
          style={{ background: "var(--surface-2)", border: "1px solid var(--border)", color: "var(--text)" }}
        >
          <option value="">Todos os status</option>
          {Object.entries(STATUS_LABEL).map(([v, l]) => (
            <option key={v} value={v}>{l}</option>
          ))}
        </select>
      </div>

      <div className="glass-card rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr style={{ borderBottom: "1px solid var(--border)" }}>
              {["Código", "Título", "Severidade", "Risco", "Tag", "Status", "Aberto em"].map((h) => (
                <th key={h} className="text-left px-4 py-2.5 text-[10px] font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {items.map((inc) => (
              <tr key={inc.id} style={{ borderTop: "1px solid var(--border)" }}>
                <td className="px-4 py-2.5 text-xs font-medium" style={{ color: "var(--text)" }}>{inc.code}</td>
                <td className="px-4 py-2.5 text-xs max-w-[360px] truncate" style={{ color: "var(--text)" }}>
                  {inc.event_id ? (
                    <Link to={`/eventos?event=${inc.event_id}`} className="hover:underline" title="Ver o evento que abriu este incidente (evidência, trilha do agente, threat intel)">
                      {inc.title}
                    </Link>
                  ) : (
                    inc.title
                  )}
                </td>
                <td className="px-4 py-2.5 text-xs font-semibold" style={{ color: SEV_COLOR[inc.severity] ?? "var(--text-muted)" }}>{inc.severity}</td>
                <td className="px-4 py-2.5 text-xs font-medium" style={{ color: "var(--text)" }}>{inc.risk_score}</td>
                <td className="px-4 py-2.5 text-xs">
                  {inc.tag ? (
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-medium" style={{ background: "rgba(34,211,238,0.12)", color: "var(--accent)" }}>
                      {inc.tag}
                    </span>
                  ) : "—"}
                </td>
                <td className="px-4 py-2.5 text-xs">
                  <select
                    value={inc.status}
                    onChange={(e) => updateStatus(inc.id, e.target.value)}
                    className="text-[10px] font-medium rounded-full px-2 py-0.5 border-0"
                    style={{ background: `${STATUS_COLOR[inc.status]}22`, color: STATUS_COLOR[inc.status] }}
                  >
                    {Object.entries(STATUS_LABEL).map(([v, l]) => (
                      <option key={v} value={v} style={{ background: "var(--surface-2)", color: "var(--text)" }}>{l}</option>
                    ))}
                  </select>
                </td>
                <td className="px-4 py-2.5 text-xs" style={{ color: "var(--text-muted)" }}>{new Date(inc.created_at).toLocaleString("pt-BR")}</td>
              </tr>
            ))}
            {!loading && items.length === 0 && (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-xs" style={{ color: "var(--text-muted)" }}>
                  Nenhum incidente {status ? `com status "${STATUS_LABEL[status]}"` : "aberto"}.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
