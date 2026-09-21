import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";

interface IncidentNarrative {
  incident_id: number;
  code: string;
  severity: string;
  status: string;
  risk_score: number;
  tag: string | null;
  src_ips: string[];
  event_count: number;
  techniques: string[];
  techniques_named: string[];
  matched_skills: string[];
  age_label: string;
  glpi_ticket_id: number | null;
  glpi_status_label: string | null;
  narrative: string;
}
interface TimelineItem {
  kind: "incident_created" | "pattern_learned" | "suspicious_flagged";
  timestamp: string;
  label: string;
  severity: string;
  ref_id: number;
}
interface LearnedPatternItem {
  pattern_key: string;
  mitre: string[];
  confirmations: number;
  first_confirmed_at: string;
  last_confirmed_at: string;
  recommendation: string | null;
}
interface TrafficBaselineItem {
  src_ip: string;
  events_24h: number;
  first_seen_this_window: boolean;
  avg_per_day_7d: number | null;
  distinct_types_7d: string[];
  is_above_baseline: boolean;
}
interface DurationStats {
  avg_seconds: number | null;
  median_seconds: number | null;
  p95_seconds: number | null;
  sample_size: number;
}
interface MttMetrics {
  mttd: DurationStats;
  mttr_respond: DurationStats;
  mttc_contain: DurationStats;
  mttr_repair: DurationStats;
}
interface KpiData {
  sla: { target_hours: Record<string, number>; compliant: number; total: number; compliance_pct: number | null };
  workload_reduction_pct: number | null;
  data_sources: { source: string; total: number; relevant: number; relevant_pct: number | null }[];
}
interface AnalysisMetrics {
  stability_pct: number | null;
  degraded_count: number;
  grounding_rejected_count: number;
  deterministic_pct: number | null;
  deterministic_count: number;
  analyzed_by_ai_count: number;
  fast_lane_count: number;
  hydration_pct: number | null;
  hydrated_count: number;
  matched_count: number;
  suspicious_count: number;
  learned_patterns_count: number;
  analysis_speed: DurationStats;
  sla_event_to_incident: DurationStats;
  backlog: { count: number; oldest_seconds: number | null };
}
interface WatchlistItem {
  id: number;
  type: string;
  src_ip: string | null;
  dst_ip: string | null;
  severity: string;
  reason: string | null;
  received_at: string;
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

// Mesma paleta de severidade do resto do app (Dashboard/Eventos/Incidentes)
// — reaproveitada por consistência, sempre pareada com rótulo direto.
const SEV_COLOR: Record<string, string> = { critica: "#f43f5e", alta: "#fb923c", media: "#facc15", baixa: "#38bdf8", info: "#64748b" };
const KIND_ICON: Record<string, string> = { incident_created: "🚨", pattern_learned: "🧠", suspicious_flagged: "🔎" };
const RULES_STATUS_LABEL: Record<string, string> = {
  pending: "Na fila", analyzing: "Analisando…", matched: "Skill casada", no_match: "Sem correspondência",
  informational: "Informativo (via rápida)",
};
const RULES_STATUS_COLOR: Record<string, string> = {
  pending: "#94a3b8", analyzing: "#22d3ee", matched: "#f43f5e", no_match: "#34d399", informational: "#64748b",
};
const STAGE_LABEL: Record<string, string> = {
  attack_defend: "ATT&CK/D3FEND", network_signature: "Assinaturas de Rede", web_application: "Aplicação Web/WAF",
};

function fmtDuration(seconds: number | null): string {
  if (seconds == null) return "—";
  // Achado real: a via rápida determinística decide em milissegundos —
  // arredondar pra segundo inteiro sempre virava "0s", que parece "quebrado"
  // em vez de "rápido de verdade" (mesmo problema que `formatDelay` já
  // resolvia pro delay de análise no Dashboard, mas não aqui).
  if (seconds < 1) return `${Math.round(seconds * 1000)}ms`;
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}min`;
  return `${(seconds / 3600).toFixed(1)}h`;
}

function timeAgo(iso: string): string {
  const diffMs = Date.now() - new Date(iso).getTime();
  const min = Math.floor(diffMs / 60000);
  if (min < 1) return "agora";
  if (min < 60) return `há ${min}min`;
  const h = Math.floor(min / 60);
  if (h < 24) return `há ${h}h`;
  return `há ${Math.floor(h / 24)}d`;
}

export default function VisaoOperacional() {
  const [narratives, setNarratives] = useState<IncidentNarrative[] | null>(null);
  const [timeline, setTimeline] = useState<TimelineItem[] | null>(null);
  const [patterns, setPatterns] = useState<LearnedPatternItem[] | null>(null);
  const [baseline, setBaseline] = useState<TrafficBaselineItem[] | null>(null);
  const [mtt, setMtt] = useState<MttMetrics | null>(null);
  const [kpis, setKpis] = useState<KpiData | null>(null);
  const [metrics, setMetrics] = useState<AnalysisMetrics | null>(null);
  const [watchlist, setWatchlist] = useState<WatchlistItem[] | null>(null);
  const [activity, setActivity] = useState<AgentActivityItem[] | null>(null);

  useEffect(() => {
    const load = () => {
      api.get<{ items: IncidentNarrative[] }>("/dashboard/incident-narratives").then((r) => setNarratives(r.items));
      api.get<{ items: TimelineItem[] }>("/dashboard/activity-timeline").then((r) => setTimeline(r.items));
      api.get<{ items: LearnedPatternItem[] }>("/dashboard/learned-patterns").then((r) => setPatterns(r.items));
      api.get<{ items: TrafficBaselineItem[] }>("/dashboard/traffic-baseline").then((r) => setBaseline(r.items));
      api.get<MttMetrics>("/dashboard/mtt-metrics").then(setMtt);
      api.get<KpiData>("/dashboard/kpis").then(setKpis);
      api.get<AnalysisMetrics>("/dashboard/analysis-metrics").then(setMetrics);
      api.get<{ items: WatchlistItem[] }>("/dashboard/watchlist").then((r) => setWatchlist(r.items));
      api.get<{ items: AgentActivityItem[] }>("/dashboard/agent-activity").then((r) => setActivity(r.items));
    };
    load();
    const timer = setInterval(load, 15000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="p-8 flex flex-col gap-5 max-w-[1400px]">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight" style={{ color: "var(--text)" }}>
          Visão <span className="text-gradient">Operacional</span>
        </h1>
        <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>
          Síntese para N3/operador de plantão — o que está acontecendo no ambiente agora, não só contadores
        </p>
      </div>

      <div className="grid grid-cols-4 gap-3">
        <MttTile
          label="MTTD"
          hint="Detectar — alerta gerado → incidente identificado"
          stats={mtt?.mttd}
        />
        <MttTile
          label="MTTR (responder)"
          hint="Responder — incidente identificado → tratativa iniciada no GLPI"
          stats={mtt?.mttr_respond}
        />
        <MttTile
          label="MTTC (conter)"
          hint='Conter — tratativa iniciada → ticket em "Planejado" (bloqueio da ameaça)'
          stats={mtt?.mttc_contain}
        />
        <MttTile
          label="MTTR (reparo)"
          hint="Reparar — bloqueio iniciado → ambiente restaurado a um estado seguro"
          stats={mtt?.mttr_repair}
        />
      </div>

      <div className="grid grid-cols-3 gap-3">
        <div className="glass-card rounded-xl p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>SLA</p>
          <p className="text-2xl font-bold mt-1.5" style={{ color: kpis?.sla.compliance_pct == null ? "var(--text-muted)" : kpis.sla.compliance_pct >= 80 ? "#34d399" : kpis.sla.compliance_pct >= 50 ? "#facc15" : "#f43f5e" }}>
            {kpis?.sla.compliance_pct != null ? `${kpis.sla.compliance_pct}%` : "…"}
          </p>
          <p className="text-[10px] mt-1" style={{ color: "var(--text-muted)" }}>
            {kpis && kpis.sla.total > 0
              ? `${kpis.sla.compliant}/${kpis.sla.total} incidente(s) resolvido(s) dentro do prazo-alvo da severidade`
              : "sem incidente resolvido ainda pra medir"}
          </p>
        </div>
        <div className="glass-card rounded-xl p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>Redução de carga de trabalho</p>
          <p className="text-2xl font-bold mt-1.5" style={{ color: "var(--text)" }}>
            {kpis?.workload_reduction_pct != null ? `${kpis.workload_reduction_pct}%` : "…"}
          </p>
          <p className="text-[10px] mt-1" style={{ color: "var(--text-muted)" }}>
            dos eventos recebidos que nunca precisaram virar incidente (trabalho real pra um analista)
          </p>
        </div>
        <div className="glass-card rounded-xl p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>Relevância por fonte</p>
          {kpis && kpis.data_sources.length === 0 && (
            <p className="text-xs mt-1.5" style={{ color: "var(--text-muted)" }}>Sem eventos ainda.</p>
          )}
          <div className="flex flex-col gap-1 mt-1.5">
            {kpis?.data_sources.map((d) => (
              <div key={d.source} className="flex items-center justify-between text-xs">
                <span style={{ color: "var(--text)" }}>{d.source}</span>
                <span style={{ color: "var(--text-muted)" }}>
                  {d.relevant}/{d.total} relevante(s){d.relevant_pct != null ? ` (${d.relevant_pct}%)` : ""}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="glass-card rounded-xl p-5">
          <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>Incidentes ativos</p>
          <p className="text-sm font-medium mb-4 mt-0.5" style={{ color: "var(--text)" }}>
            Cada incidente como história — origem, há quanto tempo, o que já foi confirmado, status real do ticket
          </p>
          {narratives && narratives.length === 0 && (
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>Nenhum incidente ativo no momento.</p>
          )}
          <div className="flex flex-col gap-3 max-h-[800px] overflow-y-auto pr-1">
            {narratives?.map((n) => (
              <div key={n.incident_id} className="rounded-lg p-3" style={{ background: "var(--surface-2)", borderLeft: `3px solid ${SEV_COLOR[n.severity]}` }}>
                <div className="flex items-center justify-between gap-2 mb-1">
                  <Link to="/resposta?tab=incidentes" className="text-xs font-semibold hover:underline" style={{ color: "var(--text)" }}>
                    {n.code}
                  </Link>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <span className="text-[10px] font-medium uppercase" style={{ color: SEV_COLOR[n.severity] }}>{n.severity}</span>
                    {n.glpi_ticket_id != null && (
                      <span className="text-[10px] font-medium rounded-full px-1.5 py-0.5" style={{ background: "rgba(148,163,184,0.15)", color: "var(--text-muted)" }}>
                        GLPI #{n.glpi_ticket_id} · {n.glpi_status_label}
                      </span>
                    )}
                  </div>
                </div>
                <p className="text-xs" style={{ color: "var(--text)" }}>{n.narrative}</p>
                {n.techniques_named.length > 0 && (
                  <p className="text-[10px] mt-1" style={{ color: "var(--text-muted)" }}>{n.techniques_named.join(" · ")}</p>
                )}
              </div>
            ))}
          </div>
        </div>

        <div className="glass-card rounded-xl p-5">
          <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>Linha do tempo</p>
          <p className="text-sm font-medium mb-4 mt-0.5" style={{ color: "var(--text)" }}>
            O que aconteceu no ambiente, em ordem — incidente aberto, padrão aprendido, evento sinalizado
          </p>
          {timeline && timeline.length === 0 && (
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>Sem atividade registrada ainda.</p>
          )}
          <div className="flex flex-col gap-2 max-h-[420px] overflow-y-auto">
            {timeline?.map((t, i) => (
              <div key={`${t.kind}-${t.ref_id}-${i}`} className="flex items-start gap-2 text-xs py-1" style={{ borderBottom: "1px solid var(--border)" }}>
                <span className="shrink-0">{KIND_ICON[t.kind] ?? "•"}</span>
                <span className="min-w-0 flex-1" style={{ color: "var(--text)" }}>{t.label}</span>
                <span className="shrink-0" style={{ color: "var(--text-muted)" }}>{timeAgo(t.timestamp)}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="glass-card rounded-xl p-5">
          <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>Padrões aprendidos</p>
          <p className="text-sm font-medium mb-4 mt-0.5" style={{ color: "var(--text)" }}>
            Tipos de alerta que a IA já confirmou o bastante pra virar via rápida, sem gastar LLM de novo
          </p>
          {patterns && patterns.length === 0 && (
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>Nenhum padrão promovido ainda — precisa de confirmações repetidas da IA.</p>
          )}
          <div className="flex flex-col gap-1.5">
            {patterns?.map((p) => (
              <div key={p.pattern_key} className="flex items-center justify-between text-xs py-1.5" style={{ borderBottom: "1px solid var(--border)" }}>
                <span className="truncate pr-2" style={{ color: "var(--text)" }} title={p.recommendation ?? undefined}>
                  {p.pattern_key}{p.mitre.length > 0 ? ` · ${p.mitre.join(", ")}` : ""}
                </span>
                <span className="shrink-0 rounded-full px-2 py-0.5 text-[10px] font-medium" style={{ background: "rgba(167,139,250,0.15)", color: "#a78bfa" }}>
                  {p.confirmations}x confirmado
                </span>
              </div>
            ))}
          </div>
        </div>

        <div className="glass-card rounded-xl p-5">
          <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>Tráfego do ambiente</p>
          <p className="text-sm font-medium mb-4 mt-0.5" style={{ color: "var(--text)" }}>
            Origens mais ativas nas últimas 24h comparadas ao próprio histórico de 7 dias
          </p>
          {baseline && baseline.length === 0 && (
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>Sem tráfego com IP de origem nas últimas 24h.</p>
          )}
          <div className="flex flex-col gap-1.5">
            {baseline?.map((b) => (
              <div key={b.src_ip} className="flex items-center justify-between text-xs py-1.5" style={{ borderBottom: "1px solid var(--border)" }}>
                <span className="truncate pr-2" style={{ color: "var(--text)" }}>{b.src_ip}</span>
                <div className="flex items-center gap-2 shrink-0">
                  <span style={{ color: "var(--text-muted)" }}>
                    {b.events_24h} evt/24h {b.avg_per_day_7d != null ? `(média 7d: ${b.avg_per_day_7d}/dia)` : "(sem histórico)"}
                  </span>
                  {b.is_above_baseline && (
                    <span className="rounded-full px-2 py-0.5 text-[10px] font-medium" style={{ background: "rgba(250,204,21,0.15)", color: "#facc15" }}>
                      {b.first_seen_this_window ? "origem nova" : "acima do padrão"}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <Card title="Estabilidade e Qualidade do Motor de Regras" subtitle="% sem degradação de infra, % de vereditos corrigidos por aterramento, % com dado real, velocidade e SLA — calculados dos timestamps e dos eventos reais, nunca estimados">
        {metrics && (
          <div className="grid grid-cols-3 gap-3">
            <div className="rounded-lg p-3" style={{ background: "var(--surface-2)" }}>
              <p className="text-[10px] uppercase tracking-wide" style={{ color: "var(--text-muted)" }}>Estabilidade da IA</p>
              <p className="text-xl font-bold mt-1" style={{ color: metrics.stability_pct == null ? "var(--text-muted)" : metrics.stability_pct >= 80 ? "#34d399" : "#facc15" }}>
                {metrics.stability_pct != null ? `${metrics.stability_pct}%` : "—"}
              </p>
              <p className="text-[10px] mt-0.5" style={{ color: "var(--text-muted)" }}>
                {metrics.analyzed_by_ai_count} análise(s) de IA{metrics.degraded_count > 0 ? `, ${metrics.degraded_count} degradada(s)` : ""} — só mede infra, não acerto
              </p>
            </div>
            <div className="rounded-lg p-3" style={{ background: "var(--surface-2)" }}>
              <p className="text-[10px] uppercase tracking-wide" style={{ color: "var(--text-muted)" }}>Alucinações corrigidas</p>
              <p className="text-xl font-bold mt-1" style={{ color: metrics.grounding_rejected_count > 0 ? "#fb923c" : "#34d399" }}>
                {metrics.grounding_rejected_count}
              </p>
              <p className="text-[10px] mt-0.5" style={{ color: "var(--text-muted)" }}>
                vezes que o Supervisor quis confirmar um match sem nenhuma skill real por trás
              </p>
            </div>
            <div className="rounded-lg p-3" style={{ background: "var(--surface-2)" }}>
              <p className="text-[10px] uppercase tracking-wide" style={{ color: "var(--text-muted)" }}>Via determinística</p>
              <p className="text-xl font-bold mt-1" style={{ color: metrics.deterministic_pct == null ? "var(--text-muted)" : "#34d399" }}>
                {metrics.deterministic_pct != null ? `${metrics.deterministic_pct}%` : "—"}
              </p>
              <p className="text-[10px] mt-0.5" style={{ color: "var(--text-muted)" }}>
                {metrics.deterministic_count}/{metrics.analyzed_by_ai_count} resolvidos por técnica MITRE exata, sem julgamento de IA
              </p>
            </div>
            <div className="rounded-lg p-3" style={{ background: "var(--surface-2)" }}>
              <p className="text-[10px] uppercase tracking-wide" style={{ color: "var(--text-muted)" }}>Hidratação de dado</p>
              <p className="text-xl font-bold mt-1" style={{ color: metrics.hydration_pct == null ? "var(--text-muted)" : metrics.hydration_pct >= 80 ? "#34d399" : metrics.hydration_pct >= 40 ? "#facc15" : "#f43f5e" }}>
                {metrics.hydration_pct != null ? `${metrics.hydration_pct}%` : "—"}
              </p>
              <p className="text-[10px] mt-0.5" style={{ color: "var(--text-muted)" }}>
                {metrics.hydrated_count}/{metrics.matched_count} com MITRE ou threat intel — "estabilidade" não mede isto
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
            <div className="rounded-lg p-3" style={{ background: "var(--surface-2)" }}>
              <p className="text-[10px] uppercase tracking-wide" style={{ color: "var(--text-muted)" }}>Padrões aprendidos</p>
              <p className="text-xl font-bold mt-1" style={{ color: "#a78bfa" }}>{metrics.learned_patterns_count}</p>
              <p className="text-[10px] mt-0.5" style={{ color: "var(--text-muted)" }}>
                tipo(s) de alerta que a IA já confirmou o bastante pra virar via rápida
              </p>
            </div>
            <div className="rounded-lg p-3" style={{ background: "var(--surface-2)" }}>
              <p className="text-[10px] uppercase tracking-wide" style={{ color: "var(--text-muted)" }}>Suspeitos (watchlist)</p>
              <p className="text-xl font-bold mt-1" style={{ color: metrics.suspicious_count > 0 ? "#facc15" : "var(--text)" }}>
                {metrics.suspicious_count}
              </p>
              <p className="text-[10px] mt-0.5" style={{ color: "var(--text-muted)" }}>
                sem skill confirmada, mas origem foge do padrão de 7 dias
              </p>
            </div>
          </div>
        )}
      </Card>

      <Card title="Watchlist — Averiguação Posterior" subtitle="Sem skill confirmada, mas a origem foge do próprio histórico de 7 dias — curiosidade para revisão manual, não incidente confirmado">
        {watchlist && watchlist.length === 0 && (
          <p className="text-xs" style={{ color: "var(--text-muted)" }}>Nada fora do padrão no momento.</p>
        )}
        {watchlist && watchlist.length > 0 && (
          <div className="flex flex-col gap-1.5">
            {watchlist.map((w) => (
              <div key={w.id} className="flex items-center justify-between text-xs py-1.5 gap-3" style={{ borderBottom: "1px solid var(--border)" }}>
                <div className="flex items-center gap-2 min-w-0">
                  <span className="inline-block w-1.5 h-1.5 rounded-full shrink-0" style={{ background: "#facc15" }} />
                  <Link to={`/resposta?tab=analises&event=${w.id}`} className="truncate hover:underline" style={{ color: "var(--text)" }}>
                    {w.type} <span style={{ color: "var(--text-muted)" }}>· {w.src_ip ?? "origem desconhecida"}</span>
                  </Link>
                </div>
                <span className="truncate max-w-[380px] shrink-0" style={{ color: "var(--text-muted)" }} title={w.reason ?? undefined}>
                  {w.reason}
                </span>
              </div>
            ))}
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
                  to={`/resposta?tab=analises&event=${a.event_id}`}
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

function MttTile({ label, hint, stats }: { label: string; hint: string; stats?: DurationStats }) {
  return (
    <div className="glass-card rounded-xl p-4" title={hint}>
      <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>{label}</p>
      <p className="text-2xl font-bold mt-1.5" style={{ color: stats && stats.sample_size > 0 ? "var(--text)" : "var(--text-muted)" }}>
        {stats ? fmtDuration(stats.median_seconds) : "…"}
      </p>
      <p className="text-[10px] mt-1" style={{ color: "var(--text-muted)" }}>
        {stats && stats.sample_size > 0
          ? `p95 ${fmtDuration(stats.p95_seconds)} · ${stats.sample_size} incidente(s)`
          : "sem amostra — nenhum incidente chegou nesta fase ainda"}
      </p>
    </div>
  );
}
