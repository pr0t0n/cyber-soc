import { useEffect, useState, type ReactNode } from "react";
import { api } from "../lib/api";
import WorldMap, { type WorldMapPoint } from "../components/WorldMap";

const SEV_LABEL: Record<string, string> = { critica: "Crítica", alta: "Alta", media: "Média", baixa: "Baixa", info: "Info" };
const SEV_COLOR: Record<string, string> = { critica: "#f43f5e", alta: "#fb923c", media: "#facc15", baixa: "#38bdf8", info: "#64748b" };
const INCIDENT_STATUS_LABEL: Record<string, string> = { backlog: "BackLog", em_andamento: "Em Andamento", concluido: "Concluído" };
const INCIDENT_STATUS_COLOR: Record<string, string> = { backlog: "#94a3b8", em_andamento: "#facc15", concluido: "#34d399" };

interface Summary {
  severity_counts: Record<string, number>;
  events_today: number;
  critical_active: number;
  avg_risk_score: number;
  mitre_coverage_pct: number;
}
interface EpsData {
  eps: { current: number; avg_5m: number };
  total_events: number;
  pending_analysis: number;
  funnel: { stage: string; label: string; count: number; pct_of_total: number }[];
}
interface HeatmapData {
  tactics: { name: string; techniques: { id: string; count: number }[] }[];
  max_count: number;
}
interface RiskHeatmap {
  days: string[];
  grid: number[][];
}
interface ConnectorsStatus {
  total: number;
  items: { id: number; name: string; kind: string; type: string; status: string; last_test: { status: string } | null }[];
}
interface IncidentsStatus {
  summary: { backlog: number; em_andamento: number; concluido: number; total: number };
  recent: { id: number; code: string; title: string; status: string; severity: string }[];
}

function useDashboardData(tag: string) {
  const qs = tag ? `?tag=${encodeURIComponent(tag)}` : "";
  const [summary, setSummary] = useState<Summary | null>(null);
  const [eps, setEps] = useState<EpsData | null>(null);
  const [heatmap, setHeatmap] = useState<HeatmapData | null>(null);
  const [riskHeatmap, setRiskHeatmap] = useState<RiskHeatmap | null>(null);
  const [connectors, setConnectors] = useState<ConnectorsStatus | null>(null);
  const [incidents, setIncidents] = useState<IncidentsStatus | null>(null);
  const [worldMap, setWorldMap] = useState<WorldMapPoint[] | null>(null);
  const [tags, setTags] = useState<string[]>([]);

  useEffect(() => {
    api.get<Summary>(`/dashboard/summary${qs}`).then(setSummary);
    api.get<EpsData>(`/dashboard/eps${qs}`).then(setEps);
    api.get<HeatmapData>(`/dashboard/mitre-heatmap${qs}`).then(setHeatmap);
    api.get<RiskHeatmap>(`/dashboard/risk-heatmap${qs}`).then(setRiskHeatmap);
    api.get<ConnectorsStatus>("/dashboard/connectors-status").then(setConnectors);
    api.get<IncidentsStatus>(`/dashboard/incidents-status${qs}`).then(setIncidents);
    api.get<{ points: WorldMapPoint[] }>(`/dashboard/world-map${qs}`).then((r) => setWorldMap(r.points));
    api.get<{ tags: string[] }>("/dashboard/tags").then((r) => setTags(r.tags));
  }, [qs]);

  return { summary, eps, heatmap, riskHeatmap, connectors, incidents, setIncidents, worldMap, tags };
}

function riskColor(v: number) {
  if (!v) return "#131a2c";
  if (v >= 70) return "#f43f5e";
  if (v >= 40) return "#fb923c";
  if (v >= 15) return "#facc15";
  return "#22d3ee";
}

function mitreColor(count: number, max: number) {
  if (!count) return "#131a2c";
  const r = max > 0 ? count / max : 0;
  return `rgba(244,63,94,${(0.2 + r * 0.7).toFixed(2)})`;
}

export default function Dashboard() {
  const [tag, setTag] = useState("");
  const { summary, eps, heatmap, riskHeatmap, connectors, incidents, setIncidents, worldMap, tags } = useDashboardData(tag);

  async function updateIncidentStatus(id: number, status: string) {
    const updated = await api.patch<{ id: number; status: string }>(`/incidents/${id}`, { status });
    setIncidents((prev) => {
      if (!prev) return prev;
      const previousStatus = prev.recent.find((i) => i.id === id)?.status;
      const counts = { ...prev.summary };
      if (previousStatus) counts[previousStatus as keyof typeof counts] = Math.max(0, counts[previousStatus as keyof typeof counts] - 1);
      counts[updated.status as keyof typeof counts] += 1;
      return {
        summary: counts,
        recent: prev.recent.map((i) => (i.id === id ? { ...i, status: updated.status } : i)),
      };
    });
  }

  return (
    <div className="p-8 flex flex-col gap-5 max-w-[1400px]">
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight" style={{ color: "var(--text)" }}>
            Dashboard <span className="text-gradient">Executivo</span>
          </h1>
          <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>
            Postura de segurança em tempo real
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs" style={{ color: "var(--text-muted)" }}>Cliente</span>
          <select
            value={tag}
            onChange={(e) => setTag(e.target.value)}
            className="text-sm rounded-lg px-3 py-2"
            style={{ background: "var(--surface-2)", border: "1px solid var(--border)", color: "var(--text)" }}
          >
            <option value="">Todos os eventos</option>
            {tags.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </div>
      </div>

      {summary && (
        <div className="grid grid-cols-5 gap-3">
          {Object.keys(SEV_LABEL).map((k) => (
            <div key={k} className="glass-card rounded-xl p-4">
              <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: SEV_COLOR[k] }}>
                {SEV_LABEL[k]}
              </p>
              <p className="text-3xl font-bold mt-1.5" style={{ color: SEV_COLOR[k] }}>
                {summary.severity_counts[k] ?? 0}
              </p>
            </div>
          ))}
        </div>
      )}

      {summary && (
        <div className="grid grid-cols-4 gap-3">
          <Stat label="Eventos hoje" value={summary.events_today} />
          <Stat label="Risco médio" value={summary.avg_risk_score} accent />
          <Stat label="Cobertura MITRE" value={`${summary.mitre_coverage_pct}%`} />
          <Stat label="EPS agora" value={eps ? eps.eps.current : "…"} />
        </div>
      )}

      <div className="grid grid-cols-2 gap-4">
        <Card title="Funil de Triagem" subtitle="Total de EPS → Motor de Regras (IA) → Incidentes">
          {eps && (
            <>
              <div className="flex flex-col gap-3">
                {eps.funnel.map((f, i) => (
                  <div key={f.stage} className="grid grid-cols-[130px_1fr_90px] items-center gap-3">
                    <span className="text-xs" style={{ color: "var(--text-muted)" }}>{f.label}</span>
                    <div className="h-3.5 rounded-full overflow-hidden" style={{ background: "var(--surface-2)" }}>
                      <div
                        className="h-full rounded-full"
                        style={{
                          width: `${f.pct_of_total}%`,
                          background: i === 0 ? "linear-gradient(90deg, var(--accent), var(--accent-2))" : i === 1 ? "#fb923c" : "#f43f5e",
                        }}
                      />
                    </div>
                    <span className="text-xs text-right" style={{ color: "var(--text-muted)" }}>
                      {f.count} <span className="opacity-60">({f.pct_of_total}%)</span>
                    </span>
                  </div>
                ))}
              </div>
              {eps.pending_analysis > 0 && (
                <p className="text-[10px] mt-3" style={{ color: "var(--text-muted)" }}>
                  {eps.pending_analysis} evento(s) ainda em análise pelo motor de regras (Supervisor + RAG em background).
                </p>
              )}
            </>
          )}
        </Card>

        <Card title="Incidentes" subtitle="Tratativa interna (BackLog / Em Andamento / Concluído)">
          {incidents && (
            <>
              <div className="grid grid-cols-3 gap-3 mb-4">
                {(["backlog", "em_andamento", "concluido"] as const).map((s) => (
                  <div key={s} className="text-center rounded-lg py-3" style={{ background: "var(--surface-2)" }}>
                    <p className="text-[10px] font-semibold uppercase tracking-wide" style={{ color: "var(--text-muted)" }}>
                      {INCIDENT_STATUS_LABEL[s]}
                    </p>
                    <p className="text-2xl font-bold mt-1" style={{ color: INCIDENT_STATUS_COLOR[s] }}>
                      {incidents.summary[s]}
                    </p>
                  </div>
                ))}
              </div>
              <div className="flex flex-col gap-1.5">
                {incidents.recent.map((inc) => (
                  <div key={inc.id} className="flex items-center justify-between text-xs py-1.5" style={{ borderBottom: "1px solid var(--border)" }}>
                    <span style={{ color: "var(--text)" }} className="truncate pr-2">{inc.code} · {inc.title}</span>
                    <select
                      value={inc.status}
                      onChange={(e) => updateIncidentStatus(inc.id, e.target.value)}
                      className="text-[10px] font-medium rounded-full px-2 py-0.5 border-0"
                      style={{ background: `${INCIDENT_STATUS_COLOR[inc.status]}22`, color: INCIDENT_STATUS_COLOR[inc.status] }}
                    >
                      {Object.entries(INCIDENT_STATUS_LABEL).map(([v, l]) => (
                        <option key={v} value={v} style={{ background: "var(--surface-2)", color: "var(--text)" }}>{l}</option>
                      ))}
                    </select>
                  </div>
                ))}
                {incidents.recent.length === 0 && <p className="text-xs" style={{ color: "var(--text-muted)" }}>Nenhum incidente aberto.</p>}
              </div>
            </>
          )}
        </Card>
      </div>

      <Card title="World Map" subtitle="Origem geográfica dos eventos, por volume e severidade">
        {worldMap && <WorldMap points={worldMap} />}
        <p className="text-[10px] mt-2" style={{ color: "var(--text-muted)" }}>
          Mapa: “Simple World Map” de Al MacDonald / Fritz Lekschas (CC BY-SA 3.0).
        </p>
      </Card>

      <div className="grid grid-cols-2 gap-4">
        <Card title="Heat Map MITRE ATT&CK" subtitle="Densidade por tática × técnica">
          {heatmap && (
            <div className="flex flex-col gap-2 overflow-x-auto">
              {heatmap.tactics.map((t) => (
                <div key={t.name} className="flex items-center gap-3">
                  <span className="w-36 shrink-0 text-xs font-medium" style={{ color: "var(--text-muted)" }}>{t.name}</span>
                  <div className="flex gap-1.5">
                    {t.techniques.map((c) => (
                      <div
                        key={c.id}
                        title={`${c.id}: ${c.count} evento(s)`}
                        className="w-14 h-10 rounded-md flex flex-col items-center justify-center"
                        style={{ background: mitreColor(c.count, heatmap.max_count), border: "1px solid var(--border)" }}
                      >
                        <span className="text-[9px] font-semibold" style={{ color: "var(--text)" }}>{c.id}</span>
                        <span className="text-[9px]" style={{ color: "var(--text-muted)" }}>{c.count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card title="Heat Map de Risco" subtitle="Risco médio do ambiente por dia × hora (7 dias)">
          {riskHeatmap && (
            <div className="overflow-x-auto">
              <div className="flex flex-col gap-1 min-w-[520px]">
                {riskHeatmap.grid.map((row, i) => (
                  <div key={i} className="flex items-center gap-1.5">
                    <span className="w-8 text-[10px] text-right pr-1" style={{ color: "var(--text-muted)" }}>{riskHeatmap.days[i]}</span>
                    {row.map((v, j) => (
                      <div key={j} title={`${riskHeatmap.days[i]} ${j}h: risco ${v}`} className="flex-1 h-3.5 rounded-sm" style={{ background: riskColor(v) }} />
                    ))}
                  </div>
                ))}
              </div>
            </div>
          )}
        </Card>
      </div>

      <Card title="Integrações" subtitle="Status das plataformas de acesso configuradas">
        {connectors && connectors.items.length === 0 && (
          <p className="text-xs" style={{ color: "var(--text-muted)" }}>Nenhuma integração configurada ainda — veja a página Integrações.</p>
        )}
        {connectors && connectors.items.length > 0 && (
          <div className="flex flex-col gap-1.5">
            {connectors.items.map((c) => (
              <div key={c.id} className="flex items-center justify-between text-xs py-1.5" style={{ borderBottom: "1px solid var(--border)" }}>
                <span style={{ color: "var(--text)" }}>
                  {c.name} <span style={{ color: "var(--text-muted)" }}>· {c.type}</span>
                </span>
                <span style={{ color: c.last_test?.status === "ok" ? "#34d399" : "var(--text-muted)" }}>
                  {c.last_test?.status ?? "não testado"}
                </span>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

function Stat({ label, value, accent }: { label: string; value: string | number; accent?: boolean }) {
  return (
    <div className="glass-card rounded-xl p-4">
      <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>{label}</p>
      <p className={`text-2xl font-bold mt-1.5 ${accent ? "text-gradient" : ""}`} style={{ color: accent ? undefined : "var(--text)" }}>
        {value}
      </p>
    </div>
  );
}

function Card({ title, subtitle, children }: { title: string; subtitle?: string; children: ReactNode }) {
  return (
    <div className="glass-card rounded-xl p-5">
      <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>{title}</p>
      {subtitle && <p className="text-sm font-medium mb-4 mt-0.5" style={{ color: "var(--text)" }}>{subtitle}</p>}
      {children}
    </div>
  );
}
