import { Fragment, useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../lib/api";
import Pagination from "../components/Pagination";

// Página única reunindo Incidentes + Análises + Raw — as telas do fluxo
// "detectar -> confirmar -> revisar" viviam separadas antes; juntas aqui como
// abas de uma mesma investigação, com paginação nas 3 (a antiga aba
// "Resposta", configuração de notificação por criticidade, foi removida por
// não trazer informação relevante pro analista — configuração de conector
// continua em Integrações).
type Tab = "incidentes" | "analises" | "raw";
const TABS: { key: Tab; label: string }[] = [
  { key: "incidentes", label: "Incidentes" },
  { key: "analises", label: "Análises" },
  { key: "raw", label: "Raw (Wazuh)" },
];

export default function Resposta() {
  const [searchParams, setSearchParams] = useSearchParams();
  const tabParam = searchParams.get("tab");
  const tab: Tab = TABS.some((t) => t.key === tabParam) ? (tabParam as Tab) : "incidentes";

  function setTab(next: Tab) {
    const params = new URLSearchParams(searchParams);
    params.set("tab", next);
    if (next !== "analises") params.delete("event"); // deep-link de evento só faz sentido em Análises
    setSearchParams(params);
  }

  return (
    <div className="p-8 flex flex-col gap-5 max-w-[1400px]">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight" style={{ color: "var(--text)" }}>
          Resposta <span className="text-gradient">e Investigação</span>
        </h1>
        <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>
          Do incidente confirmado à evidência bruta — esta plataforma não executa ação nenhuma (não isola host, não
          bloqueia IP), ela <strong>informa</strong>.
        </p>
      </div>

      <div className="flex items-center gap-1.5 border-b" style={{ borderColor: "var(--border)" }}>
        {TABS.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className="text-sm font-medium px-4 py-2.5 -mb-px"
            style={
              tab === t.key
                ? { color: "var(--accent)", borderBottom: "2px solid var(--accent)" }
                : { color: "var(--text-muted)", borderBottom: "2px solid transparent" }
            }
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "incidentes" && <IncidentesTab />}
      {tab === "analises" && <AnalisesTab />}
      {tab === "raw" && <RawTab />}
    </div>
  );
}

const PAGE_SIZE = 20;

// ---------------------------------------------------------------------------
// Incidentes
// ---------------------------------------------------------------------------

interface Incident {
  id: number;
  code: string;
  title: string;
  status: string;
  severity: string;
  risk_score: number;
  tag: string | null;
  event_id: number | null;
  glpi_ticket_id: number | null;
  created_at: string;
  updated_at: string | null;
}

const SEV_COLOR: Record<string, string> = { critica: "#f43f5e", alta: "#fb923c", media: "#facc15", baixa: "#38bdf8", info: "#64748b" };
const INCIDENT_STATUS_LABEL: Record<string, string> = { backlog: "BackLog", em_andamento: "Em Andamento", concluido: "Concluído" };
const INCIDENT_STATUS_COLOR: Record<string, string> = { backlog: "#94a3b8", em_andamento: "#facc15", concluido: "#34d399" };

function IncidentesTab() {
  const [items, setItems] = useState<Incident[]>([]);
  const [total, setTotal] = useState(0);
  const [status, setStatus] = useState("");
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);

  function load() {
    const qs = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(offset) });
    if (status) qs.set("status_filter", status);
    setLoading(true);
    // Pedido real: status de incidente com ticket GLPI vem de lá, não de
    // uma lista suspensa local — sincroniza antes de buscar (GLPI fora do
    // ar nunca trava a lista).
    api.post("/incidents/sync-glpi").catch(() => null).finally(() => {
      api.get<{ total: number; items: Incident[] }>(`/incidents?${qs.toString()}`).then((data) => {
        setItems(data.items);
        setTotal(data.total);
        setLoading(false);
      });
    });
  }

  useEffect(() => {
    load();
    const timer = setInterval(load, 8000);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status, offset]);

  useEffect(() => setOffset(0), [status]);

  async function updateStatus(id: number, next: string) {
    const updated = await api.patch<Incident>(`/incidents/${id}`, { status: next });
    setItems((prev) => prev.map((i) => (i.id === id ? updated : i)));
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <p className="text-sm" style={{ color: "var(--text-muted)" }}>
          Abertos automaticamente quando o motor de regras confirma uma skill — BackLog → Em Andamento → Concluído
        </p>
        <select
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          className="text-sm rounded-lg px-3 py-2"
          style={{ background: "var(--surface-2)", border: "1px solid var(--border)", color: "var(--text)" }}
        >
          <option value="">Todos os status</option>
          {Object.entries(INCIDENT_STATUS_LABEL).map(([v, l]) => (
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
                    <Link to={`/resposta?tab=analises&event=${inc.event_id}`} className="hover:underline" title="Ver o evento que abriu este incidente (evidência, trilha do agente, threat intel)">
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
                  {inc.glpi_ticket_id != null ? (
                    <span
                      className="text-[10px] font-medium rounded-full px-2 py-0.5"
                      style={{ background: `${INCIDENT_STATUS_COLOR[inc.status]}22`, color: INCIDENT_STATUS_COLOR[inc.status] }}
                      title={`Sincronizado do ticket GLPI #${inc.glpi_ticket_id} — não editável aqui`}
                    >
                      {INCIDENT_STATUS_LABEL[inc.status]} · GLPI #{inc.glpi_ticket_id}
                    </span>
                  ) : (
                    <select
                      value={inc.status}
                      onChange={(e) => updateStatus(inc.id, e.target.value)}
                      className="text-[10px] font-medium rounded-full px-2 py-0.5 border-0"
                      style={{ background: `${INCIDENT_STATUS_COLOR[inc.status]}22`, color: INCIDENT_STATUS_COLOR[inc.status] }}
                    >
                      {Object.entries(INCIDENT_STATUS_LABEL).map(([v, l]) => (
                        <option key={v} value={v} style={{ background: "var(--surface-2)", color: "var(--text)" }}>{l}</option>
                      ))}
                    </select>
                  )}
                </td>
                <td className="px-4 py-2.5 text-xs" style={{ color: "var(--text-muted)" }}>{new Date(inc.created_at).toLocaleString("pt-BR")}</td>
              </tr>
            ))}
            {!loading && items.length === 0 && (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-xs" style={{ color: "var(--text-muted)" }}>
                  Nenhum incidente {status ? `com status "${INCIDENT_STATUS_LABEL[status]}"` : "aberto"}.
                </td>
              </tr>
            )}
          </tbody>
        </table>
        <Pagination total={total} limit={PAGE_SIZE} offset={offset} onOffsetChange={setOffset} />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Análises (eventos)
// ---------------------------------------------------------------------------

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
  stages_done: number;
  stages_total: number;
  current_stage: string | null;
  hit_count: number | null;
  rule_ref: string | null;
  correlated_count: number | null;
  analyst_verdict: string | null;
}

interface GroupVerdict {
  matched: boolean;
  skills: string[];
  reasoning: string;
  candidates_considered: number;
  degraded: boolean;
}

interface EventDetail extends EventRow {
  src_port: string | null;
  behavior: string | null;
  enrichment: {
    abuseipdb?: { status: string; abuse_confidence_score?: number; total_reports?: number; is_tor?: boolean; isp?: string; detail?: string } | null;
    shodan?: { status: string; found?: boolean; ports?: number[]; org?: string; tags?: string[]; vulns?: string[]; detail?: string } | null;
    assessment?: { risk_score: number; level: string; is_malicious: boolean; reasons: string[] };
  };
  raw: unknown;
  rules_engine_verdict: {
    groups?: Record<string, GroupVerdict>;
    stage?: string;
    stages_done?: number;
    stages_total?: number;
    summary?: string;
  };
}

const RULES_STATUS: Record<string, { label: string; color: string }> = {
  pending: { label: "Na fila…", color: "#94a3b8" },
  analyzing: { label: "Analisando…", color: "#22d3ee" },
  matched: { label: "Skill casada", color: "#f43f5e" },
  no_match: { label: "Sem correspondência", color: "#34d399" },
  informational: { label: "Informativo (via rápida)", color: "#64748b" },
};
const STAGES: { key: string; label: string }[] = [
  { key: "attack_defend", label: "ATT&CK / D3FEND" },
  { key: "network_signature", label: "Assinaturas de Rede" },
  { key: "web_application", label: "Aplicação Web / WAF" },
  { key: "supervisor", label: "Supervisor (consolidação)" },
];
const IN_FLIGHT = new Set(["pending", "analyzing"]);
const DECISION_BY_STATUS: Record<string, { label: string; color: string }> = {
  matched: { label: "INCIDENTE CONFIRMADO", color: "#f43f5e" },
  no_match: { label: "SEM CORRESPONDÊNCIA", color: "#34d399" },
  informational: { label: "INFORMATIVO — SEM ANÁLISE DE IA", color: "var(--text-muted)" },
  pending: { label: "NA FILA…", color: "#94a3b8" },
  analyzing: { label: "ANALISANDO…", color: "#22d3ee" },
};
const ANALYST_VERDICT_LABEL: Record<string, string> = {
  true_positive: "Confirmado — ameaça real (VP)",
  false_positive: "Reclassificado — falso positivo (FP)",
  true_negative: "Confirmado — não é ameaça (VN)",
  false_negative: "Reclassificado — passou uma ameaça real (FN)",
};
const ANALYST_VERDICT_COLOR: Record<string, string> = {
  true_positive: "#34d399", false_positive: "#f43f5e", true_negative: "#34d399", false_negative: "#f43f5e",
};

function AnalisesTab() {
  const [items, setItems] = useState<EventRow[]>([]);
  const [total, setTotal] = useState(0);
  const [severity, setSeverity] = useState("");
  const [offset, setOffset] = useState(0);
  const [searchParams] = useSearchParams();
  const linkedEventId = searchParams.get("event");
  const [expanded, setExpanded] = useState<number | null>(linkedEventId ? Number(linkedEventId) : null);
  const rowRefs = useRef<Record<number, HTMLTableRowElement | null>>({});

  useEffect(() => {
    if (!linkedEventId || items.length === 0) return;
    rowRefs.current[Number(linkedEventId)]?.scrollIntoView({ behavior: "smooth", block: "center" });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [items.length, linkedEventId]);

  useEffect(() => {
    const qs = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(offset) });
    if (severity) qs.set("severity", severity);
    let cancelled = false;
    const load = () =>
      api.get<{ total: number; items: EventRow[] }>(`/events?${qs.toString()}`).then((r) => {
        if (cancelled) return;
        setItems(r.items);
        setTotal(r.total);
      });
    load();
    const timer = setInterval(load, 4000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [severity, offset]);

  useEffect(() => setOffset(0), [severity]);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <p className="text-sm" style={{ color: "var(--text-muted)" }}>{total} evento(s) ingerido(s)</p>
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
              {["", "Severidade", "Tipo", "Origem → Destino", "Local", "Tag", "MITRE", "Risco", "Motor de Regras", "Quando"].map((h) => (
                <th key={h} className="text-left px-4 py-2.5 font-medium text-[10px] uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {items.map((e) => (
              <EventRowView
                key={e.id}
                event={e}
                expanded={expanded === e.id}
                onToggle={() => setExpanded(expanded === e.id ? null : e.id)}
                rowRef={(el) => { rowRefs.current[e.id] = el; }}
              />
            ))}
            {items.length === 0 && (
              <tr>
                <td colSpan={10} className="px-4 py-10 text-center text-sm" style={{ color: "var(--text-muted)" }}>
                  Nenhum evento ainda. Envie via <code>POST /api/ingest/wazuh</code> (ou elastic/generic).
                </td>
              </tr>
            )}
          </tbody>
        </table>
        <Pagination total={total} limit={PAGE_SIZE} offset={offset} onOffsetChange={setOffset} />
      </div>
    </div>
  );
}

function EventRowView({
  event: e, expanded, onToggle, rowRef,
}: {
  event: EventRow; expanded: boolean; onToggle: () => void; rowRef: (el: HTMLTableRowElement | null) => void;
}) {
  const st = RULES_STATUS[e.rules_engine_status] ?? { label: e.rules_engine_status, color: "var(--text-muted)" };
  return (
    <>
      <tr
        ref={rowRef}
        style={{ borderTop: "1px solid var(--border)", cursor: "pointer" }}
        onClick={onToggle}
      >
        <td className="px-3 py-2.5 text-xs" style={{ color: "var(--text-muted)" }}>{expanded ? "▾" : "▸"}</td>
        <td className="px-4 py-2.5">
          <span className="text-xs font-semibold" style={{ color: SEV_COLOR[e.severity] }}>{e.severity}</span>
        </td>
        <td className="px-4 py-2.5" style={{ color: "var(--text)" }}>
          {e.type}
          {e.rules_engine_status === "no_match" && (
            <span
              className="ml-1.5 text-[10px] align-middle"
              style={{ color: "var(--sev-media, #facc15)" }}
              title="Rótulo relatado pela fonte (SIEM) — nenhuma skill/assinatura real confirmou este padrão"
            >
              ⚠️ não confirmado
            </span>
          )}
          <p className="text-[10px] mt-0.5" style={{ color: "var(--text-muted)" }}>
            {e.hit_count != null ? `${e.hit_count} tentativa(s) relatada(s)` : "sem contagem de tentativas"}
          </p>
        </td>
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
          <div className="flex items-center gap-1.5">
            {IN_FLIGHT.has(e.rules_engine_status) && (
              <span className="inline-block w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: st.color }} />
            )}
            <span style={{ color: st.color }}>{st.label}</span>
            {IN_FLIGHT.has(e.rules_engine_status) && (
              <span style={{ color: "var(--text-muted)" }}>({e.stages_done}/{e.stages_total} grupos)</span>
            )}
          </div>
          {e.matched_skills.length > 0 && <span style={{ color: "var(--text-muted)" }}>{e.matched_skills.join(", ")}</span>}
          {e.recommendation && (
            <p className="mt-0.5 truncate" style={{ color: "var(--text-muted)" }} title={e.recommendation}>
              → {e.recommendation}
            </p>
          )}
        </td>
        <td className="px-4 py-2.5 text-xs" style={{ color: "var(--text-muted)" }}>{new Date(e.timestamp).toLocaleString("pt-BR")}</td>
      </tr>
      {expanded && (
        <tr style={{ borderTop: "1px solid var(--border)" }}>
          <td colSpan={10} className="px-6 py-4" style={{ background: "var(--surface-2)" }}>
            <EventDetailPanel eventId={e.id} />
          </td>
        </tr>
      )}
    </>
  );
}

function EventDetailPanel({ eventId }: { eventId: number }) {
  const [detail, setDetail] = useState<EventDetail | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = () =>
      api.get<EventDetail>(`/events/${eventId}`).then((d) => {
        if (!cancelled) setDetail(d);
      });
    load();
    const timer = setInterval(() => {
      if (detail && !IN_FLIGHT.has(detail.rules_engine_status)) return;
      load();
    }, 3000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [eventId, detail?.rules_engine_status]);

  if (!detail) return <p className="text-xs" style={{ color: "var(--text-muted)" }}>Carregando…</p>;

  const groups = detail.rules_engine_verdict?.groups ?? {};
  const finished = !IN_FLIGHT.has(detail.rules_engine_status);
  const abuse = detail.enrichment?.abuseipdb;
  const shodan = detail.enrichment?.shodan;
  const assessment = detail.enrichment?.assessment;
  const decision = DECISION_BY_STATUS[detail.rules_engine_status] ?? { label: detail.rules_engine_status.toUpperCase(), color: "var(--text-muted)" };

  const setVerdict = (verdict: string | null) => {
    api.patch<{ id: number; analyst_verdict: string | null }>(`/events/${eventId}/verdict`, { verdict }).then((r) => {
      setDetail((d) => (d ? { ...d, analyst_verdict: r.analyst_verdict } : d));
    });
  };
  // Só faz sentido revisar um veredito que de fato terminou — e as opções
  // mudam com o que o motor decidiu: quem disse "casou" só pode ser
  // confirmado (VP) ou contestado como falso positivo (FP); quem disse "sem
  // correspondência"/"suspeito" só pode ser confirmado como não-ameaça (VN)
  // ou contestado como uma ameaça que passou (FN) — nunca os quatro botões
  // ao mesmo tempo, que não fariam sentido pro mesmo evento.
  const reviewOptions: { verdict: string; label: string }[] =
    detail.rules_engine_status === "matched"
      ? [{ verdict: "true_positive", label: "Confirmar ameaça real" }, { verdict: "false_positive", label: "Marcar como falso positivo" }]
      : detail.rules_engine_status === "no_match" || detail.rules_engine_status === "suspicious"
        ? [{ verdict: "true_negative", label: "Confirmar que não é ameaça" }, { verdict: "false_negative", label: "Na verdade era uma ameaça real" }]
        : [];

  return (
    <div className="flex flex-col gap-4">
      <div>
        <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>Decisão</p>
        <p className="text-xl font-bold mt-0.5" style={{ color: decision.color }}>{decision.label}</p>
        <p className="text-xs mt-1 max-w-2xl" style={{ color: "var(--text-muted)" }}>
          {detail.rules_engine_verdict?.summary || (finished ? "Sem resumo do Supervisor para este veredito." : "Análise em andamento…")}
        </p>
        {finished && reviewOptions.length > 0 && (
          <div className="mt-3 flex items-center gap-2 flex-wrap">
            <span className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
              Revisão do analista:
            </span>
            {detail.analyst_verdict ? (
              <>
                <span className="text-xs font-medium rounded-full px-2 py-0.5" style={{ background: `${ANALYST_VERDICT_COLOR[detail.analyst_verdict]}22`, color: ANALYST_VERDICT_COLOR[detail.analyst_verdict] }}>
                  {ANALYST_VERDICT_LABEL[detail.analyst_verdict] ?? detail.analyst_verdict}
                </span>
                <button
                  onClick={() => setVerdict(null)}
                  className="text-[10px] underline"
                  style={{ color: "var(--text-muted)" }}
                >
                  remover revisão
                </button>
              </>
            ) : (
              reviewOptions.map((o) => (
                <button
                  key={o.verdict}
                  onClick={() => setVerdict(o.verdict)}
                  className="text-xs font-medium rounded-full px-2.5 py-1"
                  style={{ background: "var(--surface)", border: "1px solid var(--border)", color: "var(--text)" }}
                >
                  {o.label}
                </button>
              ))
            )}
          </div>
        )}
      </div>
      <div className="grid grid-cols-2 gap-6">
      <div>
        <div className="rounded-lg px-3 py-2 mb-3" style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
          <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
            Evidência quantitativa e justificativa da severidade
          </p>
          <p className="text-xs mt-1" style={{ color: "var(--text)" }}>
            {detail.hit_count != null
              ? `${detail.hit_count} tentativa(s)/ocorrência(s) relatada(s) pela fonte.`
              : "A fonte não informou uma contagem de tentativas/ocorrências para este evento — o rótulo por si só não comprova volume."}
          </p>
          {detail.correlated_count != null && detail.correlated_count > 1 && (
            <p className="text-xs mt-1" style={{ color: "var(--text)" }}>
              Correlação: esta origem gerou <strong>{detail.correlated_count} evento(s)</strong> nos últimos 10 minutos — não é um evento isolado.
            </p>
          )}
          <p className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>
            Severidade "{detail.severity}": {detail.rule_ref ?? "sem referência da regra de origem — classificação recebida sem justificativa detalhada."}
          </p>
        </div>
        <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: "var(--text-muted)" }}>
          Trilha do Agente (LangGraph Supervisor)
        </p>
        <div className="flex flex-col gap-2">
          {STAGES.map((s) => {
            const g = groups[s.key];
            const isSupervisor = s.key === "supervisor";
            const done = isSupervisor ? finished : Boolean(g);
            const running = !done && detail.rules_engine_verdict?.stage === s.key;
            return (
              <div key={s.key} className="rounded-lg px-3 py-2" style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium flex items-center gap-1.5" style={{ color: "var(--text)" }}>
                    <span>{done ? "✅" : running ? "⏳" : "⚪"}</span> {s.label}
                  </span>
                  {g && (
                    <span className="text-[10px]" style={{ color: g.matched ? "#f43f5e" : g.degraded ? "#facc15" : "#34d399" }}>
                      {g.matched ? "casou" : g.degraded ? "degradado (inconclusivo)" : "sem correspondência"} · {g.candidates_considered} candidata(s)
                    </span>
                  )}
                  {isSupervisor && finished && (
                    <span className="text-[10px]" style={{ color: detail.rules_engine_status === "matched" ? "#f43f5e" : "#34d399" }}>
                      {detail.rules_engine_status === "matched" ? "incidente aberto" : "concluído"}
                    </span>
                  )}
                </div>
                {g?.reasoning && (
                  <p className="text-[11px] mt-1" style={{ color: "var(--text-muted)" }}>{g.reasoning}</p>
                )}
                {isSupervisor && finished && detail.rules_engine_verdict?.summary && (
                  <p className="text-[11px] mt-1" style={{ color: "var(--text-muted)" }}>{detail.rules_engine_verdict.summary}</p>
                )}
              </div>
            );
          })}
        </div>
        {detail.recommendation && (
          <div className="mt-3 rounded-lg px-3 py-2" style={{ background: "rgba(34,211,238,0.08)", border: "1px solid var(--border)" }}>
            <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: "var(--accent)" }}>Recomendação</p>
            <p className="text-xs mt-1" style={{ color: "var(--text)" }}>{detail.recommendation}</p>
          </div>
        )}
      </div>

      <div className="flex flex-col gap-4">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: "var(--text-muted)" }}>
            Threat Intel (IP de origem: {detail.src_ip ?? "—"})
          </p>
          {!abuse && !shodan && (
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>Sem provedor configurado ou IP não público.</p>
          )}
          {abuse && (
            <div className="text-xs mb-1.5" style={{ color: "var(--text-muted)" }}>
              <span className="font-medium" style={{ color: "var(--text)" }}>AbuseIPDB: </span>
              {abuse.status === "ok"
                ? `score ${abuse.abuse_confidence_score}/100, ${abuse.total_reports} relato(s)${abuse.is_tor ? ", nó Tor" : ""} — ${abuse.isp ?? "ISP desconhecido"}`
                : (abuse.detail ?? abuse.status)}
            </div>
          )}
          {shodan && (
            <div className="text-xs" style={{ color: "var(--text-muted)" }}>
              <span className="font-medium" style={{ color: "var(--text)" }}>Shodan: </span>
              {shodan.status === "ok"
                ? shodan.found
                  ? `portas ${shodan.ports?.join(", ") || "—"} · ${shodan.org ?? "org. desconhecida"}${shodan.vulns?.length ? ` · ${shodan.vulns.length} CVE(s)` : ""}`
                  : "sem informação no Shodan"
                : (shodan.detail ?? shodan.status)}
            </div>
          )}
          {assessment && (
            <p className="text-[11px] mt-1.5" style={{ color: "var(--text-muted)" }}>{assessment.reasons.join(" ")}</p>
          )}
        </div>

        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: "var(--text-muted)" }}>
            Evento bruto (artefato original)
          </p>
          <pre
            className="text-[10px] rounded-lg p-3 overflow-x-auto max-h-40"
            style={{ background: "var(--surface)", border: "1px solid var(--border)", color: "var(--text-muted)" }}
          >
            {JSON.stringify(detail.raw, null, 1)}
          </pre>
        </div>
      </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Raw
// ---------------------------------------------------------------------------

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

function RawTab() {
  const [q, setQ] = useState("");
  const [source, setSource] = useState("");
  const [items, setItems] = useState<RawItem[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [rawJson, setRawJson] = useState<Record<number, unknown>>({});

  useEffect(() => {
    const qs = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(offset) });
    if (q) qs.set("q", q);
    if (source) qs.set("source", source);
    const timer = setTimeout(() => {
      api.get<{ total: number; items: RawItem[] }>(`/events/raw?${qs.toString()}`).then((r) => {
        setItems(r.items);
        setTotal(r.total);
      });
    }, 300);
    return () => clearTimeout(timer);
  }, [q, source, offset]);

  useEffect(() => setOffset(0), [q, source]);

  async function toggle(id: number) {
    if (expanded === id) {
      setExpanded(null);
      return;
    }
    setExpanded(id);
    if (!rawJson[id]) {
      const detail = await api.get<{ raw: unknown }>(`/events/${id}`);
      setRawJson((prev) => ({ ...prev, [id]: detail.raw }));
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm" style={{ color: "var(--text-muted)" }}>
        {total} evento(s) — dado bruto direto da fonte, sem interpretação da IA
      </p>

      <div className="flex items-center gap-2">
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
        <Pagination total={total} limit={PAGE_SIZE} offset={offset} onOffsetChange={setOffset} />
      </div>
    </div>
  );
}
