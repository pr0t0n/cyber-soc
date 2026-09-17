import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
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
  recent: { id: number; code: string; title: string; status: string; severity: string; event_id: number | null }[];
}
interface AgentActivityItem {
  event_id: number;
  type: string;
  severity: string;
  src_ip: string | null;
  tag: string | null;
  rules_engine_status: string;
  matched_skills: string[];
  recommendation: string | null;
  stages_done: number;
  stages_total: number;
  current_stage: string | null;
  received_at: string | null;
}

const RULES_STATUS_LABEL: Record<string, string> = {
  pending: "Na fila", analyzing: "Analisando…", matched: "Skill casada", no_match: "Sem correspondência",
  informational: "Informativo (via rápida)",
};
const RULES_STATUS_COLOR: Record<string, string> = {
  pending: "#94a3b8", analyzing: "#22d3ee", matched: "#f43f5e", no_match: "#34d399", informational: "#64748b",
};

interface DurationStats {
  avg_seconds: number | null;
  median_seconds: number | null;
  p95_seconds: number | null;
  sample_size: number;
}
interface AnalysisMetrics {
  efficiency_pct: number | null;
  degraded_count: number;
  analyzed_by_ai_count: number;
  fast_lane_count: number;
  analysis_speed: DurationStats;
  sla_event_to_incident: DurationStats;
  backlog: { count: number; oldest_seconds: number | null };
}

function fmtDuration(seconds: number | null): string {
  if (seconds == null) return "—";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}min`;
  return `${(seconds / 3600).toFixed(1)}h`;
}
const STAGE_LABEL: Record<string, string> = {
  attack_defend: "ATT&CK/D3FEND", network_signature: "Assinaturas de Rede", web_application: "Aplicação Web/WAF",
};

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
  const [activity, setActivity] = useState<AgentActivityItem[] | null>(null);
  const [metrics, setMetrics] = useState<AnalysisMetrics | null>(null);

  useEffect(() => {
    const loadSlow = () => {
      api.get<Summary>(`/dashboard/summary${qs}`).then(setSummary);
      api.get<HeatmapData>(`/dashboard/mitre-heatmap${qs}`).then(setHeatmap);
      api.get<RiskHeatmap>(`/dashboard/risk-heatmap${qs}`).then(setRiskHeatmap);
      api.get<ConnectorsStatus>("/dashboard/connectors-status").then(setConnectors);
      api.get<IncidentsStatus>(`/dashboard/incidents-status${qs}`).then(setIncidents);
      api.get<{ points: WorldMapPoint[] }>(`/dashboard/world-map${qs}`).then((r) => setWorldMap(r.points));
      api.get<{ tags: string[] }>("/dashboard/tags").then((r) => setTags(r.tags));
    };
    const loadFast = () => {
      api.get<EpsData>(`/dashboard/eps${qs}`).then(setEps);
      api.get<{ items: AgentActivityItem[] }>(`/dashboard/agent-activity${qs}`).then((r) => setActivity(r.items));
      api.get<AnalysisMetrics>(`/dashboard/analysis-metrics${qs}`).then(setMetrics);
    };
    loadSlow();
    loadFast();
    const slowTimer = setInterval(loadSlow, 20000);
    const fastTimer = setInterval(loadFast, 5000);
    return () => {
      clearInterval(slowTimer);
      clearInterval(fastTimer);
    };
  }, [qs]);

  return { summary, eps, heatmap, riskHeatmap, connectors, incidents, setIncidents, worldMap, tags, activity, metrics };
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
  const { summary, eps, heatmap, riskHeatmap, connectors, incidents, setIncidents, worldMap, tags, activity, metrics } = useDashboardData(tag);

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

        <Card title="Incidentes" subtitle="Pipeline completo: Sendo Analisados → BackLog → Em Andamento → Concluído">
          {incidents && (
            <>
              <div className="grid grid-cols-4 gap-3 mb-4">
                <div className="text-center rounded-lg py-3" style={{ background: "var(--surface-2)" }}>
                  <p className="text-[10px] font-semibold uppercase tracking-wide" style={{ color: "var(--text-muted)" }}>
                    Sendo Analisados
                  </p>
                  <p className="text-2xl font-bold mt-1" style={{ color: "#22d3ee" }}>
                    {metrics?.backlog.count ?? "…"}
                  </p>
                </div>
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
                    {inc.event_id ? (
                      <Link
                        to={`/eventos?event=${inc.event_id}`}
                        className="truncate pr-2 hover:underline"
                        style={{ color: "var(--text)" }}
                        title="Ver evento de origem, trilha do agente e threat intel"
                      >
                        {inc.code} · {inc.title}
                      </Link>
                    ) : (
                      <span style={{ color: "var(--text)" }} className="truncate pr-2">{inc.code} · {inc.title}</span>
                    )}
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

      <Card title="Eficiência do Motor de Regras" subtitle="% sem degradação, velocidade de análise e SLA evento → incidente — calculados dos timestamps reais">
        {metrics && (
          <div className="grid grid-cols-5 gap-3">
            <div className="rounded-lg p-3" style={{ background: "var(--surface-2)" }}>
              <p className="text-[10px] uppercase tracking-wide" style={{ color: "var(--text-muted)" }}>Eficiência</p>
              <p className="text-xl font-bold mt-1" style={{ color: (metrics.efficiency_pct ?? 100) >= 80 ? "#34d399" : "#facc15" }}>
                {metrics.efficiency_pct != null ? `${metrics.efficiency_pct}%` : "—"}
              </p>
              <p className="text-[10px] mt-0.5" style={{ color: "var(--text-muted)" }}>
                {metrics.analyzed_by_ai_count} análise(s) de IA{metrics.degraded_count > 0 ? `, ${metrics.degraded_count} degradada(s)` : ""}
              </p>
            </div>
            <div className="rounded-lg p-3" style={{ background: "var(--surface-2)" }}>
              <p className="text-[10px] uppercase tracking-wide" style={{ color: "var(--text-muted)" }}>Velocidade (mediana)</p>
              <p className="text-xl font-bold mt-1" style={{ color: "var(--text)" }}>{fmtDuration(metrics.analysis_speed.median_seconds)}</p>
              <p className="text-[10px] mt-0.5" style={{ color: "var(--text-muted)" }}>
                p95 {fmtDuration(metrics.analysis_speed.p95_seconds)} · {metrics.analysis_speed.sample_size} evento(s)
              </p>
            </div>
            <div className="rounded-lg p-3" style={{ background: "var(--surface-2)" }}>
              <p className="text-[10px] uppercase tracking-wide" style={{ color: "var(--text-muted)" }}>SLA evento → incidente</p>
              <p className="text-xl font-bold mt-1" style={{ color: "var(--text)" }}>{fmtDuration(metrics.sla_event_to_incident.median_seconds)}</p>
              <p className="text-[10px] mt-0.5" style={{ color: "var(--text-muted)" }}>
                p95 {fmtDuration(metrics.sla_event_to_incident.p95_seconds)} · {metrics.sla_event_to_incident.sample_size} incidente(s)
              </p>
            </div>
            <div className="rounded-lg p-3" style={{ background: "var(--surface-2)" }}>
              <p className="text-[10px] uppercase tracking-wide" style={{ color: "var(--text-muted)" }}>Fila (backlog)</p>
              <p className="text-xl font-bold mt-1" style={{ color: metrics.backlog.count > 20 ? "#f43f5e" : "var(--text)" }}>{metrics.backlog.count}</p>
              <p className="text-[10px] mt-0.5" style={{ color: "var(--text-muted)" }}>
                mais antigo há {fmtDuration(metrics.backlog.oldest_seconds)}
              </p>
            </div>
            <div className="rounded-lg p-3" style={{ background: "var(--surface-2)" }}>
              <p className="text-[10px] uppercase tracking-wide" style={{ color: "var(--text-muted)" }}>Via rápida (compliance)</p>
              <p className="text-xl font-bold mt-1" style={{ color: "var(--text)" }}>{metrics.fast_lane_count}</p>
              <p className="text-[10px] mt-0.5" style={{ color: "var(--text-muted)" }}>SCA/rootcheck, sem IA</p>
            </div>
          </div>
        )}
      </Card>

      <Card title="Atividade do Agente" subtitle="O que o Supervisor (LangGraph + RAG) está analisando agora, evento a evento">
        {activity && activity.length === 0 && (
          <p className="text-xs" style={{ color: "var(--text-muted)" }}>Nenhum evento processado pelo motor de regras ainda.</p>
        )}
        {activity && activity.length > 0 && (
          <div className="flex flex-col gap-1.5">
            {activity.map((a) => {
              const inFlight = a.rules_engine_status === "pending" || a.rules_engine_status === "analyzing";
              return (
                <Link
                  to={`/eventos?event=${a.event_id}`}
                  key={a.event_id}
                  className="flex items-center justify-between text-xs py-1.5 gap-3 hover:opacity-80"
                  style={{ borderBottom: "1px solid var(--border)" }}
                >
                  <div className="flex items-center gap-2 min-w-0">
                    {inFlight && (
                      <span className="inline-block w-1.5 h-1.5 rounded-full animate-pulse shrink-0" style={{ background: RULES_STATUS_COLOR[a.rules_engine_status] }} />
                    )}
                    <span style={{ color: "var(--text)" }} className="truncate">
                      {a.type} <span style={{ color: "var(--text-muted)" }}>· {a.src_ip ?? "origem desconhecida"}</span>
                    </span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {a.recommendation && !inFlight && (
                      <span className="truncate max-w-[220px]" style={{ color: "var(--text-muted)" }} title={a.recommendation}>
                        → {a.recommendation}
                      </span>
                    )}
                    {inFlight && a.current_stage && (
                      <span style={{ color: "var(--text-muted)" }}>{STAGE_LABEL[a.current_stage] ?? a.current_stage} ({a.stages_done}/{a.stages_total})</span>
                    )}
                    <span className="font-medium" style={{ color: RULES_STATUS_COLOR[a.rules_engine_status] ?? "var(--text-muted)" }}>
                      {RULES_STATUS_LABEL[a.rules_engine_status] ?? a.rules_engine_status}
                    </span>
                  </div>
                </Link>
              );
            })}
          </div>
        )}
      </Card>

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
