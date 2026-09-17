interface FunnelStage {
  stage: string;
  label: string;
  count: number;
  pct_of_total: number;
}

// 3 tons distintos (não um único hue sequencial) porque cada estágio é uma
// ETAPA de pipeline com identidade própria (ingestão / triagem de IA /
// incidente confirmado), não uma progressão de magnitude — validado contra
// o fundo escuro do app (CVD ΔE 10.3+, piso de visão normal 15.9, contraste
// >=3:1; ver dataviz skill) e sempre pareado com rótulo direto, nunca só cor.
const STAGE_COLOR = ["#22d3ee", "#a78bfa", "#f472b6"];

const VB_W = 1000;
const VB_H = 210;
const MARGIN_X = 80;
const CENTER_Y = 135;
const MAX_HALF = 50;
const MIN_BAND_H = 12;

// Sankey do recharts não dá conta de um funil com só 2-3 estágios e valores
// muito díspares (303 -> 13 -> 13 virava dois retângulos colados, sem afunilar
// de verdade) — por isso a faixa é desenhada à mão: cada trecho é um caminho
// bezier fechado ligando a altura do estágio i à altura do estágio i+1, o que
// garante o efeito de "rio estreitando" mesmo com poucos pontos.
export default function TriageFunnel({ stages }: { stages: FunnelStage[] }) {
  if (stages.length === 0 || stages.every((s) => s.count === 0)) {
    return <p className="text-xs" style={{ color: "var(--text-muted)" }}>Sem eventos ainda.</p>;
  }

  const maxCount = Math.max(...stages.map((s) => s.count), 1);
  const n = stages.length;
  const xs = stages.map((_, i) => (n === 1 ? VB_W / 2 : MARGIN_X + (i * (VB_W - 2 * MARGIN_X)) / (n - 1)));
  const halves = stages.map((s) => Math.max((s.count / maxCount) * MAX_HALF, MIN_BAND_H / 2));

  return (
    <div style={{ width: "100%", height: VB_H }}>
      <svg viewBox={`0 0 ${VB_W} ${VB_H}`} width="100%" height="100%" preserveAspectRatio="none">
        {stages.slice(1).map((s, i) => {
          const x0 = xs[i];
          const x1 = xs[i + 1];
          const midX = (x0 + x1) / 2;
          const top0 = CENTER_Y - halves[i];
          const bot0 = CENTER_Y + halves[i];
          const top1 = CENTER_Y - halves[i + 1];
          const bot1 = CENTER_Y + halves[i + 1];
          const color = STAGE_COLOR[i + 1] ?? STAGE_COLOR[STAGE_COLOR.length - 1];
          const d = `M${x0},${top0} C${midX},${top0} ${midX},${top1} ${x1},${top1} L${x1},${bot1} C${midX},${bot1} ${midX},${bot0} ${x0},${bot0} Z`;
          return <path key={s.stage} d={d} fill={color} fillOpacity={0.88} />;
        })}
        {stages.map((s, i) => {
          const half = halves[i];
          return (
            <line
              key={`guide-${s.stage}`}
              x1={xs[i]} x2={xs[i]}
              y1={52} y2={CENTER_Y - half}
              stroke="var(--text-muted)" strokeOpacity={0.25} strokeDasharray="2,3"
            />
          );
        })}
        {stages.map((s, i) => (
          <g key={`label-${s.stage}`}>
            <text
              x={xs[i]} y={20} textAnchor="middle" fontSize={11} fill="var(--text-muted)"
              style={{ textTransform: "uppercase", letterSpacing: 0.4 }}
            >
              {s.label}
            </text>
            <text x={xs[i]} y={42} textAnchor="middle" fontSize={19} fontWeight={700} fill={i === 0 ? STAGE_COLOR[0] : "var(--text)"}>
              {s.count}
              {i > 0 && <tspan fontSize={11} fontWeight={400} fill="var(--text-muted)"> ({s.pct_of_total}%)</tspan>}
            </text>
          </g>
        ))}
      </svg>
    </div>
  );
}
