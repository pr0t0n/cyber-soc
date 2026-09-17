import { useEffect, useState } from "react";
import { api } from "../lib/api";

interface SkillListItem {
  id: number;
  source: string;
  external_id: string;
  name: string;
  category: string | null;
}
interface SkillDetail extends SkillListItem {
  yaml: string;
  hydrated: boolean;
}
interface SourceSummary {
  sources: { source: string; count: number }[];
  total: number;
  embedded: number;
  hydration_pct: number;
}

const SOURCE_LABEL: Record<string, string> = {
  attack: "MITRE ATT&CK", d3fend: "MITRE D3FEND", suricata: "Suricata", modsecurity: "ModSecurity",
  sigma: "Sigma", agent_threats: "Agent Threats", correlation: "Correlação (interna)",
};
const SOURCE_COLOR: Record<string, string> = {
  attack: "#f43f5e", d3fend: "#22d3ee", suricata: "#a78bfa", modsecurity: "#fb923c",
  sigma: "#34d399", agent_threats: "#f472b6", correlation: "#facc15",
};

export default function Rules() {
  const [summary, setSummary] = useState<SourceSummary | null>(null);
  const [source, setSource] = useState<string>("attack");
  const [q, setQ] = useState("");
  const [items, setItems] = useState<SkillListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState<SkillDetail | null>(null);

  useEffect(() => {
    api.get<SourceSummary>("/skills/sources").then(setSummary);
  }, []);

  useEffect(() => {
    const params = new URLSearchParams({ source, limit: "60" });
    if (q) params.set("q", q);
    api.get<{ total: number; items: SkillListItem[] }>(`/skills?${params}`).then((r) => {
      setItems(r.items);
      setTotal(r.total);
      setSelected(null);
    });
  }, [source, q]);

  async function open(id: number) {
    const detail = await api.get<SkillDetail>(`/skills/${id}`);
    setSelected(detail);
  }

  return (
    <div className="p-8 max-w-6xl">
      <div className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight" style={{ color: "var(--text)" }}>Regras</h1>
        <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>
          Catálogo real de skills — base do motor de regras (RAG via MCP)
        </p>
      </div>

      {summary && (
        <div className="grid grid-cols-4 md:grid-cols-8 gap-3 mb-6">
          {summary.sources.map((s) => (
            <button
              key={s.source}
              onClick={() => setSource(s.source)}
              className="glass-card rounded-xl p-4 text-left"
              style={{ outline: source === s.source ? `1.5px solid ${SOURCE_COLOR[s.source]}` : "none" }}
            >
              <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: SOURCE_COLOR[s.source] }}>
                {SOURCE_LABEL[s.source]}
              </p>
              <p className="text-2xl font-bold mt-1" style={{ color: "var(--text)" }}>{s.count}</p>
            </button>
          ))}
          <div className="glass-card rounded-xl p-4">
            <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>Hidratação RAG</p>
            <p className="text-2xl font-bold mt-1 text-gradient">{summary.hydration_pct}%</p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-[1fr_1.2fr] gap-4">
        <div>
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Buscar por nome…"
            className="w-full text-sm rounded-lg px-3.5 py-2.5 mb-3"
            style={{ background: "var(--surface-2)", border: "1px solid var(--border)", color: "var(--text)" }}
          />
          <div className="glass-card rounded-xl overflow-hidden max-h-[560px] overflow-y-auto">
            {items.map((s) => (
              <button
                key={s.id}
                onClick={() => open(s.id)}
                className="w-full text-left px-4 py-2.5 text-sm flex items-center justify-between"
                style={{
                  borderBottom: "1px solid var(--border)",
                  background: selected?.id === s.id ? "var(--surface-2)" : "transparent",
                }}
              >
                <span style={{ color: "var(--text)" }} className="truncate pr-2">
                  <span className="font-mono text-xs mr-2" style={{ color: SOURCE_COLOR[s.source] }}>{s.external_id}</span>
                  {s.name}
                </span>
              </button>
            ))}
            {items.length === 0 && <p className="p-4 text-xs" style={{ color: "var(--text-muted)" }}>Nenhuma skill encontrada.</p>}
          </div>
          <p className="text-[10px] mt-2" style={{ color: "var(--text-muted)" }}>
            {items.length} de {total} skill(s) em {SOURCE_LABEL[source]}
          </p>
        </div>

        <div className="glass-card rounded-xl p-5">
          {selected ? (
            <>
              <div className="flex items-center justify-between mb-3">
                <p className="text-sm font-semibold" style={{ color: "var(--text)" }}>{selected.name}</p>
                <span
                  className="text-[10px] px-2 py-0.5 rounded-full font-medium"
                  style={{ background: selected.hydrated ? "rgba(52,211,153,0.15)" : "rgba(148,163,184,0.15)", color: selected.hydrated ? "#34d399" : "var(--text-muted)" }}
                >
                  {selected.hydrated ? "hidratada (RAG)" : "aguardando embedding"}
                </span>
              </div>
              <pre
                className="text-xs font-mono whitespace-pre-wrap rounded-lg p-4 overflow-x-auto"
                style={{ background: "#0a0e1a", border: "1px solid var(--border)", color: "#a5f3fc" }}
              >
                {selected.yaml}
              </pre>
            </>
          ) : (
            <p className="text-sm" style={{ color: "var(--text-muted)" }}>Selecione uma skill à esquerda para ver o YAML.</p>
          )}
        </div>
      </div>
    </div>
  );
}
