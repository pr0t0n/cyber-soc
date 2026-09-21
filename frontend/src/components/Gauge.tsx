// Termômetro/gauge radial simples (0-100) — usado para métricas de
// magnitude com um limiar de risco implícito (nota de risco, eficiência),
// não para identidade categórica. Cor = 1 hue sequencial por faixa de risco
// (verde/amarelo/laranja/vermelho), sempre pareado com o número por extenso
// no centro — nunca só a cor comunica o valor.
const SIZE = 120;
const STROKE = 12;
const RADIUS = (SIZE - STROKE) / 2;
const CIRCUMFERENCE = Math.PI * RADIUS; // meia-volta (arco de 180°)

function colorFor(value: number, invert: boolean): string {
  const v = invert ? 100 - value : value;
  if (v >= 80) return "#f43f5e";
  if (v >= 50) return "#fb923c";
  if (v >= 25) return "#facc15";
  return "#34d399";
}

export default function Gauge({
  value, label, suffix = "", invert = false,
}: { value: number | null; label: string; suffix?: string; invert?: boolean }) {
  // `null` é "sem amostra ainda" — nunca vira 0% nem 100% forçado no
  // chamador. Achado real: mostrar 0% (vermelho, alarmante) ou 100% (verde,
  // falso positivo de "tudo ótimo") quando não há dado nenhum ainda é pior
  // que não mostrar nada — os dois já geraram confusão real neste dashboard.
  const hasData = value != null;
  const clamped = hasData ? Math.max(0, Math.min(100, value)) : 0;
  const offset = CIRCUMFERENCE - (clamped / 100) * CIRCUMFERENCE;
  const color = hasData ? colorFor(clamped, invert) : "var(--border)";

  return (
    <div className="flex flex-col items-center">
      <svg width={SIZE} height={SIZE / 2 + 12} viewBox={`0 0 ${SIZE} ${SIZE / 2 + 12}`}>
        <path
          d={`M ${STROKE / 2} ${SIZE / 2} A ${RADIUS} ${RADIUS} 0 0 1 ${SIZE - STROKE / 2} ${SIZE / 2}`}
          fill="none"
          stroke="var(--surface-2)"
          strokeWidth={STROKE}
          strokeLinecap="round"
        />
        {hasData && (
          <path
            d={`M ${STROKE / 2} ${SIZE / 2} A ${RADIUS} ${RADIUS} 0 0 1 ${SIZE - STROKE / 2} ${SIZE / 2}`}
            fill="none"
            stroke={color}
            strokeWidth={STROKE}
            strokeLinecap="round"
            strokeDasharray={CIRCUMFERENCE}
            strokeDashoffset={offset}
            style={{ transition: "stroke-dashoffset 0.6s ease, stroke 0.6s ease" }}
          />
        )}
        <text x={SIZE / 2} y={SIZE / 2 - 4} textAnchor="middle" fontSize={22} fontWeight={700} fill={hasData ? "var(--text)" : "var(--text-muted)"}>
          {hasData ? `${Math.round(clamped)}${suffix}` : "—"}
        </text>
      </svg>
      <p className="text-[10px] font-semibold uppercase tracking-wider -mt-1" style={{ color: "var(--text-muted)" }}>{label}</p>
    </div>
  );
}
