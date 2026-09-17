import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
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
  stages_done: number;
  stages_total: number;
  current_stage: string | null;
  hit_count: number | null;
  rule_ref: string | null;
  correlated_count: number | null;
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

const SEV_COLOR: Record<string, string> = { critica: "#f43f5e", alta: "#fb923c", media: "#facc15", baixa: "#38bdf8", info: "#64748b" };
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

export default function Events() {
  const [items, setItems] = useState<EventRow[]>([]);
  const [total, setTotal] = useState(0);
  const [severity, setSeverity] = useState("");
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
    const qs = severity ? `?severity=${severity}` : "";
    let cancelled = false;
    const load = () =>
      api.get<{ total: number; items: EventRow[] }>(`/events${qs}`).then((r) => {
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

  return (
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
  );
}
