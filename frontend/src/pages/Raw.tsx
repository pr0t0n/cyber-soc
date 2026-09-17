import { Fragment, useEffect, useState } from "react";
import { api } from "../lib/api";

interface RawItem {
  id: number;
  timestamp: string;
  received_at: string;
  source: string;
  tag: string | null;
  rule_id: string | null;
  rule_level: number | null;
  rule_groups: string[] | null;
  full_log: string | null;
  rules_engine_status: string;
}

interface EventDetail {
  raw: unknown;
}

export default function Raw() {
  const [q, setQ] = useState("");
  const [source, setSource] = useState("");
  const [items, setItems] = useState<RawItem[]>([]);
  const [total, setTotal] = useState(0);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [rawJson, setRawJson] = useState<Record<number, unknown>>({});

  useEffect(() => {
    const qs = new URLSearchParams();
    if (q) qs.set("q", q);
    if (source) qs.set("source", source);
    const timer = setTimeout(() => {
      api.get<{ total: number; items: RawItem[] }>(`/events/raw?${qs.toString()}`).then((r) => {
        setItems(r.items);
        setTotal(r.total);
      });
    }, 300);
    return () => clearTimeout(timer);
  }, [q, source]);

  async function toggle(id: number) {
    if (expanded === id) {
      setExpanded(null);
      return;
    }
    setExpanded(id);
    if (!rawJson[id]) {
      const detail = await api.get<EventDetail>(`/events/${id}`);
      setRawJson((prev) => ({ ...prev, [id]: detail.raw }));
    }
  }

  return (
    <div className="p-8 max-w-6xl">
      <div className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight" style={{ color: "var(--text)" }}>Raw (Wazuh/SIEM)</h1>
        <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>
          {total} evento(s) — dado bruto direto da fonte, sem interpretação da IA
        </p>
      </div>

      <div className="flex items-center gap-2 mb-4">
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Buscar no JSON bruto (IP, regra, mensagem...)"
          className="flex-1 text-sm rounded-lg px-3.5 py-2.5"
          style={{ background: "var(--surface-2)", border: "1px solid var(--border)", color: "var(--text)" }}
        />
        <select
          value={source}
          onChange={(e) => setSource(e.target.value)}
          className="text-sm rounded-lg px-3 py-2.5"
          style={{ background: "var(--surface-2)", border: "1px solid var(--border)", color: "var(--text)" }}
        >
          <option value="">Todas as fontes</option>
          <option value="wazuh">wazuh</option>
          <option value="elastic">elastic</option>
          <option value="generic">generic</option>
        </select>
      </div>

      <div className="glass-card rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead style={{ background: "var(--surface-2)" }}>
            <tr>
              {["", "Quando", "Fonte", "Tag", "Regra", "Nível", "Grupos", "Full log"].map((h) => (
                <th key={h} className="text-left px-4 py-2.5 font-medium text-[10px] uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {items.map((e) => (
              <Fragment key={e.id}>
                <tr style={{ borderTop: "1px solid var(--border)", cursor: "pointer" }} onClick={() => toggle(e.id)}>
                  <td className="px-3 py-2.5 text-xs" style={{ color: "var(--text-muted)" }}>{expanded === e.id ? "▾" : "▸"}</td>
                  <td className="px-4 py-2.5 text-xs" style={{ color: "var(--text-muted)" }}>{new Date(e.timestamp).toLocaleString("pt-BR")}</td>
                  <td className="px-4 py-2.5 text-xs" style={{ color: "var(--text)" }}>{e.source}</td>
                  <td className="px-4 py-2.5 text-xs" style={{ color: "var(--text-muted)" }}>{e.tag ?? "—"}</td>
                  <td className="px-4 py-2.5 text-xs font-mono" style={{ color: "var(--text-muted)" }}>{e.rule_id ?? "—"}</td>
                  <td className="px-4 py-2.5 text-xs" style={{ color: "var(--text)" }}>{e.rule_level ?? "—"}</td>
                  <td className="px-4 py-2.5 text-xs" style={{ color: "var(--text-muted)" }}>{e.rule_groups?.join(", ") ?? "—"}</td>
                  <td className="px-4 py-2.5 text-xs max-w-[280px] truncate" style={{ color: "var(--text-muted)" }} title={e.full_log ?? ""}>
                    {e.full_log ?? "—"}
                  </td>
                </tr>
                {expanded === e.id && (
                  <tr style={{ borderTop: "1px solid var(--border)" }}>
                    <td colSpan={8} className="px-6 py-4" style={{ background: "var(--surface-2)" }}>
                      <pre
                        className="text-[10px] rounded-lg p-3 overflow-x-auto max-h-96"
                        style={{ background: "var(--surface)", border: "1px solid var(--border)", color: "var(--text-muted)" }}
                      >
                        {rawJson[e.id] ? JSON.stringify(rawJson[e.id], null, 1) : "Carregando…"}
                      </pre>
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
            {items.length === 0 && (
              <tr>
                <td colSpan={8} className="px-4 py-10 text-center text-sm" style={{ color: "var(--text-muted)" }}>
                  Nenhum evento encontrado.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
