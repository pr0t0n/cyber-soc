import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import WorldMap, { type WorldMapPoint } from "../components/WorldMap";
import TriageFunnel from "../components/TriageFunnel";
import Gauge from "../components/Gauge";

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
  analysis_delay_seconds: number | null;
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
interface IncidentsStatus {
  summary: { backlog: number; em_andamento: number; concluido: number; total: number };
  recent: { id: number; code: string; title: string; status: string; severity: string; event_id: number | null; glpi_ticket_id: number | null }[];
}
interface DurationStats {
  avg_seconds: number | null;
  median_seconds: number | null;
  p95_seconds: number | null;
  sample_size: number;
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
interface AttackVectorCell {
  source: string;
  category: string;
  total: number;
  matched: number;
  no_match: number;
  suspicious: number;
  other: number;
}
interface AttackVectorData {
  sources: string[];
  categories: string[];
  cells: AttackVectorCell[];
}
interface ConfusionMatrixData {
  true_positive: number;
  false_positive: number;
  true_negative: number;
  false_negative: number;
  reviewed_count: number;
  total_events: number;
  accuracy_pct: number | null;
  precision_pct: number | null;
  recall_pct: number | null;
  f1_pct: number | null;
  false_positive_rate_pct: number | null;
  false_negative_rate_pct: number | null;
}

function useDashboardData(tag: string) {
  const qs = tag ? `?tag=${encodeURIComponent(tag)}` : "";
  const [summary, setSummary] = useState<Summary | null>(null);
  const [eps, setEps] = useState<EpsData | null>(null);
  const [heatmap, setHeatmap] = useState<HeatmapData | null>(null);
  const [riskHeatmap, setRiskHeatmap] = useState<RiskHeatmap | null>(null);
  const [incidents, setIncidents] = useState<IncidentsStatus | null>(null);
  const [worldMap, setWorldMap] = useState<WorldMapPoint[] | null>(null);
  const [tags, setTags] = useState<string[]>([]);
  const [metrics, setMetrics] = useState<AnalysisMetrics | null>(null);
  const [attackVector, setAttackVector] = useState<AttackVectorData | null>(null);
  const [confusionMatrix, setConfusionMatrix] = useState<ConfusionMatrixData | null>(null);
  const [newIncidentAlert, setNewIncidentAlert] = useState<{ id: number; code: string; title: string; severity: string } | null>(null);
  const seenIncidentIds = useRef<Set<number> | null>(null);

  useEffect(() => {
    const loadSlow = () => {
      api.get<Summary>(`/dashboard/summary${qs}`).then(setSummary);
      api.get<HeatmapData>(`/dashboard/mitre-heatmap${qs}`).then(setHeatmap);
      api.get<RiskHeatmap>(`/dashboard/risk-heatmap${qs}`).then(setRiskHeatmap);
      // Pedido real: status de incidente com ticket GLPI vem de lá, não de
      // uma lista suspensa local — sincroniza antes de buscar o estado
      // atual pra já vir com o status mais recente do ticket nesta mesma
      // rodada de polling (falha do GLPI aqui nunca trava o dashboard).
      api.post<{ synced: number; failed: number }>("/incidents/sync-glpi").catch(() => null).finally(() => {
        api.get<IncidentsStatus>(`/dashboard/incidents-status${qs}`).then((data) => {
          setIncidents(data);
          const ids = new Set(data.recent.map((i) => i.id));
          // Primeira carga só estabelece a base — sem isso, TODO incidente já
          // existente apareceria como "novo" assim que a página abre.
          if (seenIncidentIds.current !== null) {
            const fresh = data.recent.find((i) => !seenIncidentIds.current!.has(i.id));
            if (fresh) setNewIncidentAlert(fresh);
          }
          seenIncidentIds.current = ids;
        });
      });
      api.get<{ points: WorldMapPoint[] }>(`/dashboard/world-map${qs}`).then((r) => setWorldMap(r.points));
      api.get<{ tags: string[] }>("/dashboard/tags").then((r) => setTags(r.tags));
      api.get<AttackVectorData>(`/dashboard/attack-vector${qs}`).then(setAttackVector);
      api.get<ConfusionMatrixData>(`/dashboard/confusion-matrix${qs}`).then(setConfusionMatrix);
    };
    const loadFast = () => {
      api.get<EpsData>(`/dashboard/eps${qs}`).then(setEps);
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

  return {
    summary, eps, heatmap, riskHeatmap, incidents, setIncidents, worldMap, tags, metrics,
    attackVector, confusionMatrix, newIncidentAlert, dismissIncidentAlert: () => setNewIncidentAlert(null),
  };
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

// Attack Vector: cor segue a IDENTIDADE do resultado predominante da célula
// (confirmado/sem ameaça/suspeito/outro), intensidade segue o VOLUME —
// nunca as duas coisas misturadas na mesma escala (ver dataviz: "color
// follows the entity, never its rank").
const ATTACK_VECTOR_RESULT_RGB: Record<string, string> = {
  matched: "244,63,94", suspicious: "250,204,21", no_match: "52,211,153", other: "100,116,139",
};
const ATTACK_VECTOR_RESULT_LABEL: Record<string, string> = {
  matched: "Confirmado", suspicious: "Suspeito", no_match: "Sem ameaça", other: "Informativo/em análise",
};
function dominantResult(cell: AttackVectorCell): keyof typeof ATTACK_VECTOR_RESULT_RGB {
  const ranked: [keyof typeof ATTACK_VECTOR_RESULT_RGB, number][] = [
    ["matched", cell.matched], ["suspicious", cell.suspicious], ["no_match", cell.no_match], ["other", cell.other],
  ];
  ranked.sort((a, b) => b[1] - a[1]);
  return ranked[0][1] > 0 ? ranked[0][0] : "other";
}
function attackVectorCellColor(cell: AttackVectorCell | undefined, maxTotal: number): string {
  if (!cell || !cell.total) return "#131a2c";
  const r = maxTotal > 0 ? cell.total / maxTotal : 0;
  return `rgba(${ATTACK_VECTOR_RESULT_RGB[dominantResult(cell)]},${(0.2 + r * 0.7).toFixed(2)})`;
}

export default function Dashboard() {
  const [tag, setTag] = useState("");
  const {
    summary, eps, heatmap, riskHeatmap, incidents, setIncidents, worldMap, tags, metrics,
    attackVector, confusionMatrix, newIncidentAlert, dismissIncidentAlert,
  } = useDashboardData(tag);

  useEffect(() => {
    if (!newIncidentAlert) return;
    const timer = setTimeout(dismissIncidentAlert, 15000);
    return () => clearTimeout(timer);
  }, [newIncidentAlert, dismissIncidentAlert]);

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
      {newIncidentAlert && (
        <div
          className="toast-in fixed top-5 right-5 z-50 w-80 rounded-xl p-4 shadow-2xl"
          style={{
            background: "var(--surface)",
            borderTop: "1px solid var(--border)",
            borderRight: "1px solid var(--border)",
            borderBottom: "1px solid var(--border)",
            borderLeft: `4px solid ${SEV_COLOR[newIncidentAlert.severity] ?? "var(--accent)"}`,
          }}
        >
          <div className="flex items-start justify-between gap-2">
            <div className="min-w-0">
              <p
                className="text-[10px] font-semibold uppercase tracking-wider flex items-center gap-1.5"
                style={{ color: SEV_COLOR[newIncidentAlert.severity] ?? "var(--text-muted)" }}
              >
                <span className="inline-block w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: "currentColor" }} />
                Novo incidente · {SEV_LABEL[newIncidentAlert.severity] ?? newIncidentAlert.severity}
              </p>
              <Link
                to="/resposta?tab=incidentes"
                onClick={dismissIncidentAlert}
                className="text-sm font-medium mt-1 block truncate hover:underline"
                style={{ color: "var(--text)" }}
                title={newIncidentAlert.title}
              >
                {newIncidentAlert.code} · {newIncidentAlert.title}
              </Link>
            </div>
            <button
              onClick={dismissIncidentAlert}
              className="shrink-0 text-xs leading-none rounded-full w-5 h-5 flex items-center justify-center hover:bg-white/10"
              style={{ color: "var(--text-muted)" }}
              aria-label="Dispensar"
            >
              ×
            </button>
          </div>
        </div>
      )}

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
        <div className="grid grid-cols-3 gap-3">
          <Stat label="Eventos hoje" value={summary.events_today} />
          <Stat label="EPS agora" value={eps ? eps.eps.current : "…"} />
          <Stat
            label="Delay de análise"
            value={eps ? formatDelay(eps.analysis_delay_seconds) : "…"}
            valueColor={eps ? delayColor(eps.analysis_delay_seconds) : undefined}
          />
        </div>
      )}

      {summary && (
        <div className="glass-card rounded-xl p-4 flex items-center justify-around flex-wrap gap-4">
          <Gauge value={summary.avg_risk_score} label="Risco médio" />
          <Gauge value={summary.mitre_coverage_pct} label="Cobertura MITRE" suffix="%" invert />
          <Gauge value={metrics ? metrics.stability_pct : null} label="Estabilidade da IA" suffix="%" invert />
          <Gauge value={metrics ? metrics.hydration_pct : null} label="Hidratação de dado" suffix="%" invert />
        </div>
      )}

      <div className="grid grid-cols-2 gap-4">
        <Card title="Funil de Triagem" subtitle="Total de EPS → Motor de Regras (IA) → Incidentes" className="self-start">
          {eps && (
            <>
              <TriageFunnel stages={eps.funnel} />
              {eps.pending_analysis > 0 && (
                <p className="text-[10px] mt-1" style={{ color: "var(--text-muted)" }}>
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
                        to={`/resposta?tab=analises&event=${inc.event_id}`}
                        className="truncate pr-2 hover:underline"
                        style={{ color: "var(--text)" }}
                        title="Ver evento de origem, trilha do agente e threat intel"
                      >
                        {inc.code} · {inc.title}
                      </Link>
                    ) : (
                      <span style={{ color: "var(--text)" }} className="truncate pr-2">{inc.code} · {inc.title}</span>
                    )}
                    {inc.glpi_ticket_id != null ? (
                      <span
                        className="text-[10px] font-medium rounded-full px-2 py-0.5 shrink-0"
                        style={{ background: `${INCIDENT_STATUS_COLOR[inc.status]}22`, color: INCIDENT_STATUS_COLOR[inc.status] }}
                        title={`Sincronizado do ticket GLPI #${inc.glpi_ticket_id} — não editável aqui`}
                      >
                        {INCIDENT_STATUS_LABEL[inc.status]} · GLPI #{inc.glpi_ticket_id}
                      </span>
                    ) : (
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
                    )}
                  </div>
                ))}
                {incidents.recent.length === 0 && <p className="text-xs" style={{ color: "var(--text-muted)" }}>Nenhum incidente aberto.</p>}
              </div>
            </>
          )}
        </Card>
      </div>

      <Card title="Attack Vector" subtitle="Tratamento de eventos por fonte de dado × vetor de ataque (tática MITRE) — resultado predominante em cada célula, não uma matriz de confusão de ML (sem rótulo de verdade fundamental)">
        {attackVector && attackVector.sources.length === 0 && (
          <p className="text-xs" style={{ color: "var(--text-muted)" }}>Nenhum evento analisado ainda.</p>
        )}
        {attackVector && attackVector.sources.length > 0 && (() => {
          const cellsByKey = new Map(attackVector.cells.map((c) => [`${c.source}|${c.category}`, c]));
          const maxTotal = Math.max(...attackVector.cells.map((c) => c.total), 1);
          return (
            <div className="overflow-x-auto">
              <div className="flex flex-col gap-2 min-w-[640px] w-fit">
                <div className="flex items-center gap-1.5 pl-24">
                  {attackVector.categories.map((c) => (
                    <span
                      key={c}
                      className="w-20 shrink-0 text-[9px] font-medium text-center truncate"
                      style={{ color: "var(--text-muted)" }}
                      title={c}
                    >
                      {c}
                    </span>
                  ))}
                </div>
                {attackVector.sources.map((s) => (
                  <div key={s} className="flex items-center gap-1.5">
                    <span className="w-24 shrink-0 text-xs font-medium truncate" style={{ color: "var(--text-muted)" }}>{s}</span>
                    <div className="flex gap-1.5">
                      {attackVector.categories.map((c) => {
                        const cell = cellsByKey.get(`${s}|${c}`);
                        const tooltip = cell
                          ? `${s} × ${c}: ${cell.total} evento(s) — ${cell.matched} confirmado(s), ${cell.no_match} sem ameaça, ${cell.suspicious} suspeito(s), ${cell.other} informativo/em análise`
                          : `${s} × ${c}: sem eventos`;
                        return (
                          <div
                            key={c}
                            title={tooltip}
                            className="w-20 h-10 rounded-md flex items-center justify-center"
                            style={{ background: attackVectorCellColor(cell, maxTotal), border: "1px solid var(--border)" }}
                          >
                            <span className="text-[10px] font-semibold" style={{ color: "var(--text)" }}>{cell?.total ?? 0}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
              <div className="flex items-center gap-3 mt-3 flex-wrap">
                {Object.entries(ATTACK_VECTOR_RESULT_LABEL).map(([k, label]) => (
                  <span key={k} className="flex items-center gap-1.5 text-[10px]" style={{ color: "var(--text-muted)" }}>
                    <span className="inline-block w-2.5 h-2.5 rounded-sm" style={{ background: `rgb(${ATTACK_VECTOR_RESULT_RGB[k]})` }} />
                    {label}
                  </span>
                ))}
              </div>
            </div>
          );
        })()}
      </Card>

      <Card title="Matriz de Confusão" subtitle="Precisão real do motor de regras contra a reclassificação humana (Eventos → revisar) — não confundir com Estabilidade da IA, que só mede infraestrutura">
        {confusionMatrix && confusionMatrix.reviewed_count === 0 && (
          <p className="text-xs" style={{ color: "var(--text-muted)" }}>
            Nenhum evento revisado por um analista ainda ({confusionMatrix.total_events} evento(s) no total) — abra um evento em Eventos e use "Revisão do analista" para começar a medir.
          </p>
        )}
        {confusionMatrix && confusionMatrix.reviewed_count > 0 && (
          <>
            <div className="grid grid-cols-4 gap-3 mb-4">
              <div className="rounded-lg p-3 text-center" style={{ background: "rgba(52,211,153,0.1)" }}>
                <p className="text-[10px] uppercase tracking-wide" style={{ color: "var(--text-muted)" }}>Verdadeiro Positivo</p>
                <p className="text-xl font-bold mt-1" style={{ color: "#34d399" }}>{confusionMatrix.true_positive}</p>
              </div>
              <div className="rounded-lg p-3 text-center" style={{ background: "rgba(244,63,94,0.1)" }}>
                <p className="text-[10px] uppercase tracking-wide" style={{ color: "var(--text-muted)" }}>Falso Positivo</p>
                <p className="text-xl font-bold mt-1" style={{ color: "#f43f5e" }}>{confusionMatrix.false_positive}</p>
              </div>
              <div className="rounded-lg p-3 text-center" style={{ background: "rgba(52,211,153,0.1)" }}>
                <p className="text-[10px] uppercase tracking-wide" style={{ color: "var(--text-muted)" }}>Verdadeiro Negativo</p>
                <p className="text-xl font-bold mt-1" style={{ color: "#34d399" }}>{confusionMatrix.true_negative}</p>
              </div>
              <div className="rounded-lg p-3 text-center" style={{ background: "rgba(244,63,94,0.1)" }}>
                <p className="text-[10px] uppercase tracking-wide" style={{ color: "var(--text-muted)" }}>Falso Negativo</p>
                <p className="text-xl font-bold mt-1" style={{ color: "#f43f5e" }}>{confusionMatrix.false_negative}</p>
              </div>
            </div>
            <div className="grid grid-cols-3 gap-3">
              {([
                ["Acurácia", confusionMatrix.accuracy_pct],
                ["Precisão", confusionMatrix.precision_pct],
                ["Recall", confusionMatrix.recall_pct],
                ["F1-Score", confusionMatrix.f1_pct],
                ["Taxa de Falso Positivo", confusionMatrix.false_positive_rate_pct],
                ["Taxa de Falso Negativo", confusionMatrix.false_negative_rate_pct],
              ] as [string, number | null][]).map(([label, value]) => (
                <div key={label} className="rounded-lg p-3" style={{ background: "var(--surface-2)" }}>
                  <p className="text-[10px] uppercase tracking-wide" style={{ color: "var(--text-muted)" }}>{label}</p>
                  <p className="text-xl font-bold mt-1" style={{ color: "var(--text)" }}>{value != null ? `${value}%` : "—"}</p>
                </div>
              ))}
            </div>
            <p className="text-[10px] mt-3" style={{ color: "var(--text-muted)" }}>
              {confusionMatrix.reviewed_count} de {confusionMatrix.total_events} evento(s) revisado(s) por um analista — amostra pequena pesa menos.
            </p>
          </>
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

    </div>
  );
}

function Stat({ label, value, accent, valueColor }: { label: string; value: string | number; accent?: boolean; valueColor?: string }) {
  return (
    <div className="glass-card rounded-xl p-4">
      <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>{label}</p>
      <p
        className={`text-2xl font-bold mt-1.5 ${accent && !valueColor ? "text-gradient" : ""}`}
        style={{ color: valueColor ?? (accent ? undefined : "var(--text)") }}
      >
        {value}
      </p>
    </div>
  );
}

// `analysis_delay_seconds` (app/api/dashboard.py /eps) é recebido->analisado
// real dos últimos 5 minutos, não uma estimativa — `null` significa "nada
// analisado ainda nessa janela", distinto de "delay zero".
function formatDelay(seconds: number | null): string {
  if (seconds === null) return "sem dado";
  if (seconds < 1) return `${Math.round(seconds * 1000)}ms`;
  return `${seconds.toFixed(1)}s`;
}

function delayColor(seconds: number | null): string | undefined {
  if (seconds === null) return "var(--text-muted)";
  if (seconds <= 5) return "#34d399";
  if (seconds <= 30) return "#facc15";
  return "#f43f5e";
}

function Card({ title, subtitle, children, className = "" }: { title: string; subtitle?: string; children: ReactNode; className?: string }) {
  return (
    <div className={`glass-card rounded-xl p-5 ${className}`}>
      <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>{title}</p>
      {subtitle && <p className="text-sm font-medium mb-4 mt-0.5" style={{ color: "var(--text)" }}>{subtitle}</p>}
      {children}
    </div>
  );
}
