import { useEffect, useMemo, useState } from "react";
import { Sankey, ResponsiveContainer, Layer, Rectangle } from "recharts";
import { api } from "../lib/api";

interface Connector {
  id: number;
  name: string;
  kind: string;
  type: string;
  status: string;
  config: Record<string, unknown>;
}

const SEVERITIES = ["critica", "alta", "media", "baixa", "info"] as const;
const SEV_LABEL: Record<string, string> = { critica: "Crítica", alta: "Alta", media: "Média", baixa: "Baixa", info: "Info" };
// Mesma paleta de severidade usada em todo o app (Dashboard/Eventos/Incidentes)
// — reaproveitada aqui por consistência; sempre pareada com rótulo direto no
// nó (nunca só a cor) para quem não distingue bem a diferença entre
// media/alta a olho.
const SEV_COLOR: Record<string, string> = { critica: "#f43f5e", alta: "#fb923c", media: "#facc15", baixa: "#38bdf8", info: "#64748b" };
const TYPE_ICON: Record<string, string> = { slack: "💬", teams: "👥", jira: "🎫", glpi: "🎟️", webhook: "🔗", email: "✉️" };

export default function Resposta() {
  const [items, setItems] = useState<Connector[]>([]);
  const [loading, setLoading] = useState(true);

  function load() {
    api.get<Connector[]>("/admin/connectors").then((all) => {
      setItems(all.filter((c) => c.kind === "notification"));
      setLoading(false);
    });
  }

  useEffect(load, []);

  const severitiesOf = (c: Connector): string[] => (c.config.severities as string[] | undefined) ?? [];

  async function toggle(c: Connector, severity: string) {
    const current = severitiesOf(c);
    const next = current.includes(severity) ? current.filter((s) => s !== severity) : [...current, severity];
    await api.patch(`/admin/connectors/${c.id}`, { config: { ...c.config, severities: next } });
    load();
  }

  const sankey = useMemo(() => {
    const nodes: { name: string; color: string }[] = SEVERITIES.map((s) => ({ name: SEV_LABEL[s], color: SEV_COLOR[s] }));
    const connectorOffset = nodes.length;
    for (const c of items) nodes.push({ name: `${TYPE_ICON[c.type] ?? ""} ${c.name}`, color: "var(--surface-2)" });

    const links: { source: number; target: number; value: number; color: string }[] = [];
    items.forEach((c, ci) => {
      for (const sev of severitiesOf(c)) {
        const sevIndex = SEVERITIES.indexOf(sev as (typeof SEVERITIES)[number]);
        if (sevIndex === -1) continue;
        links.push({ source: sevIndex, target: connectorOffset + ci, value: 1, color: SEV_COLOR[sev] });
      }
    });
    return { nodes, links, hasAnyLink: links.length > 0 };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [items]);

  return (
    <div className="p-8 flex flex-col gap-5 max-w-[1400px]">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight" style={{ color: "var(--text)" }}>
          Resposta <span className="text-gradient">e Ações</span>
        </h1>
        <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>
          Esta plataforma não executa ação nenhuma (não isola host, não bloqueia IP) — ela <strong>informa</strong>: por
          criticidade, quais integrações recebem mensagem (Slack/Teams) ou chamado (Jira/GLPI) quando um incidente é
          confirmado ou escala.
        </p>
      </div>

      <div className="glass-card rounded-xl p-5">
        <p className="text-[10px] font-semibold uppercase tracking-wider mb-3" style={{ color: "var(--text-muted)" }}>
          Fluxo: Criticidade → Notificação
        </p>
        {loading ? (
          <p className="text-xs" style={{ color: "var(--text-muted)" }}>Carregando…</p>
        ) : items.length === 0 ? (
          <p className="text-xs" style={{ color: "var(--text-muted)" }}>
            Nenhuma integração de notificação cadastrada — crie uma em Sistema → Integrações (categoria "ITSM /
            Comunicação") antes de configurar o fluxo aqui.
          </p>
        ) : (
          <div style={{ width: "100%", height: 70 + items.length * 46 }}>
            <ResponsiveContainer>
              <Sankey
                data={sankey}
                nodeWidth={14}
                nodePadding={28}
                linkCurvature={0.5}
                iterations={0}
                node={<FlowNode />}
                link={<FlowLink hasAnyLink={sankey.hasAnyLink} />}
                margin={{ top: 8, bottom: 8, left: 8, right: 140 }}
              />
            </ResponsiveContainer>
          </div>
        )}
      </div>

      <div className="flex flex-col gap-2">
        {items.map((c) => (
          <div key={c.id} className="glass-card rounded-xl p-4 flex items-center justify-between flex-wrap gap-3">
            <p className="text-sm font-medium" style={{ color: "var(--text)" }}>
              {TYPE_ICON[c.type] ?? ""} {c.name} <span className="text-xs font-normal" style={{ color: "var(--text-muted)" }}>({c.type}{c.status !== "enabled" ? " · desabilitado" : ""})</span>
            </p>
            <div className="flex gap-1.5">
              {SEVERITIES.map((sev) => {
                const active = severitiesOf(c).includes(sev);
                return (
                  <button
                    key={sev}
                    onClick={() => toggle(c, sev)}
                    className="text-[10px] font-medium rounded-full px-2.5 py-1 transition-colors"
                    style={{
                      background: active ? `${SEV_COLOR[sev]}33` : "var(--surface-2)",
                      border: `1px solid ${active ? SEV_COLOR[sev] : "var(--border)"}`,
                      color: active ? SEV_COLOR[sev] : "var(--text-muted)",
                    }}
                  >
                    {SEV_LABEL[sev]}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function FlowNode(props: any) {
  const { x, y, width, height, payload } = props;
  const isSeverity = SEVERITIES.map((s) => SEV_LABEL[s]).includes(payload.name);
  return (
    <Layer>
      <Rectangle x={x} y={y} width={width} height={height} fill={payload.color} fillOpacity={isSeverity ? 0.9 : 0.6} />
      <text
        x={isSeverity ? x - 8 : x + width + 8}
        y={y + height / 2}
        textAnchor={isSeverity ? "end" : "start"}
        dominantBaseline="middle"
        fontSize={12}
        fill="var(--text)"
      >
        {payload.name}
      </text>
    </Layer>
  );
}

function FlowLink({ hasAnyLink, ...props }: any) {
  if (!hasAnyLink) return null;
  const { sourceX, sourceY, sourceControlX, targetControlX, targetX, targetY, linkWidth, payload } = props;
  const d = `M${sourceX},${sourceY}C${sourceControlX},${sourceY} ${targetControlX},${targetY} ${targetX},${targetY}`;
  return <path d={d} fill="none" stroke={payload.color} strokeOpacity={0.45} strokeWidth={Math.max(linkWidth, 3)} />;
}
