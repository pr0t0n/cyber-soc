import { useEffect, useState } from "react";
import { api } from "../lib/api";

interface EventRow {
  id: number;
  timestamp: string;
  source: string;
  type: string;
  severity: string;
  src_ip: string | null;
  dst_ip: string | null;
  dst_port: string | null;
  protocol: string | null;
  mitre: string[];
  risk_score: number;
  status: string;
  tag: string | null;
  country: string | null;
  city: string | null;
  rules_engine_status: string;
  matched_skills: string[];
  recommendation: string | null;
}

const SEV_COLOR: Record<string, string> = { critica: "#f43f5e", alta: "#fb923c", media: "#facc15", baixa: "#38bdf8", info: "#64748b" };
const RULES_STATUS: Record<string, { label: string; color: string }> = {
  pending: { label: "Analisando…", color: "#94a3b8" },
  matched: { label: "Skill casada", color: "#f43f5e" },
  no_match: { label: "Sem correspondência", color: "#34d399" },
};

export default function Events() {
  const [items, setItems] = useState<EventRow[]>([]);
  const [total, setTotal] = useState(0);
  const [severity, setSeverity] = useState("");

  useEffect(() => {
    const qs = severity ? `?severity=${severity}` : "";
    api.get<{ total: number; items: EventRow[] }>(`/events${qs}`).then((r) => {
      setItems(r.items);
      setTotal(r.total);
    });
  }, [severity]);

  return (
    <div className="p-8 max-w-6xl">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight" style={{ color: "var(--text)" }}>Eventos</h1>
          <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>{total} evento(s) ingerido(s)</p>
        </div>
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="text-sm rounded-lg px-3 py-2"
          style={{ background: "var(--surface-2)", border: "1px solid var(--border)", color: "var(--text)" }}
        >
          <option value="">Todas as severidades</option>
          {Object.keys(SEV_COLOR).map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
      </div>

      <div className="glass-card rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead style={{ background: "var(--surface-2)" }}>
            <tr>
              {["Severidade", "Tipo", "Origem → Destino", "Local", "Tag", "MITRE", "Risco", "Motor de Regras", "Quando"].map((h) => (
                <th key={h} className="text-left px-4 py-2.5 font-medium text-[10px] uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {items.map((e) => (
              <tr key={e.id} style={{ borderTop: "1px solid var(--border)" }}>
                <td className="px-4 py-2.5">
                  <span className="text-xs font-semibold" style={{ color: SEV_COLOR[e.severity] }}>{e.severity}</span>
                </td>
                <td className="px-4 py-2.5" style={{ color: "var(--text)" }}>{e.type}</td>
                <td className="px-4 py-2.5 text-xs" style={{ color: "var(--text-muted)" }}>
                  {e.src_ip ?? "—"} → {e.dst_ip ?? "—"}
                  {e.dst_port ? `:${e.dst_port}` : ""} {e.protocol ? `/${e.protocol}` : ""}
                </td>
                <td className="px-4 py-2.5 text-xs" style={{ color: "var(--text-muted)" }}>
                  {e.city ? `${e.city}, ` : ""}{e.country ?? "—"}
                </td>
                <td className="px-4 py-2.5 text-xs">
                  {e.tag ? (
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-medium" style={{ background: "rgba(34,211,238,0.12)", color: "var(--accent)" }}>
                      {e.tag}
                    </span>
                  ) : "—"}
                </td>
                <td className="px-4 py-2.5 text-xs" style={{ color: "var(--text-muted)" }}>{e.mitre.join(", ") || "—"}</td>
                <td className="px-4 py-2.5 text-xs font-medium" style={{ color: "var(--text)" }}>{e.risk_score}</td>
                <td className="px-4 py-2.5 text-xs max-w-[260px]">
                  <span style={{ color: RULES_STATUS[e.rules_engine_status]?.color ?? "var(--text-muted)" }}>
                    {RULES_STATUS[e.rules_engine_status]?.label ?? e.rules_engine_status}
                  </span>
                  {e.matched_skills.length > 0 && <span style={{ color: "var(--text-muted)" }}> ({e.matched_skills.join(", ")})</span>}
                  {e.recommendation && (
                    <p className="mt-0.5 truncate" style={{ color: "var(--text-muted)" }} title={e.recommendation}>
                      → {e.recommendation}
                    </p>
                  )}
                </td>
                <td className="px-4 py-2.5 text-xs" style={{ color: "var(--text-muted)" }}>{new Date(e.timestamp).toLocaleString("pt-BR")}</td>
              </tr>
            ))}
            {items.length === 0 && (
              <tr>
                <td colSpan={9} className="px-4 py-10 text-center text-sm" style={{ color: "var(--text-muted)" }}>
                  Nenhum evento ainda. Envie via <code>POST /api/ingest/wazuh</code> (ou elastic/generic).
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
