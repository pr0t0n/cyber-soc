import { useEffect, useRef, useState } from "react";

export interface WorldMapPoint {
  country: string | null;
  city: string | null;
  lat: number;
  lon: number;
  count: number;
  max_severity: string;
  max_risk: number;
}

const SEV_COLOR: Record<string, string> = {
  critica: "#f43f5e", alta: "#fb923c", media: "#facc15", baixa: "#38bdf8", info: "#64748b",
};

// Projeção equirretangular simples: assume que o SVG embutido cobre o globo
// inteiro (lon -180..180, lat 90..-90) — suficiente para posicionar pinos numa
// visualização executiva (não é uma ferramenta de medição geográfica).
function project(lat: number, lon: number) {
  const left = ((lon + 180) / 360) * 100;
  const top = ((90 - lat) / 180) * 100;
  return { left: `${left}%`, top: `${top}%` };
}

export default function WorldMap({ points }: { points: WorldMapPoint[] }) {
  const [svg, setSvg] = useState<string | null>(null);
  const [hover, setHover] = useState<WorldMapPoint | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetch("/world-map.svg")
      .then((r) => r.text())
      .then(setSvg)
      .catch(() => setSvg(null));
  }, []);

  const maxCount = Math.max(...points.map((p) => p.count), 1);

  return (
    <div ref={containerRef} className="relative w-full rounded-lg overflow-hidden" style={{ aspectRatio: "784 / 459", background: "#0d1326" }}>
      {svg && (
        <div
          className="absolute inset-0 w-full h-full [&>svg]:w-full [&>svg]:h-full"
          dangerouslySetInnerHTML={{ __html: svg }}
          aria-hidden
        />
      )}
      {points.map((p, i) => {
        const pos = project(p.lat, p.lon);
        const size = 6 + Math.min(p.count / maxCount, 1) * 14;
        const color = SEV_COLOR[p.max_severity] ?? SEV_COLOR.info;
        return (
          <div
            key={i}
            className="absolute rounded-full cursor-pointer"
            style={{
              left: pos.left,
              top: pos.top,
              width: size,
              height: size,
              transform: "translate(-50%, -50%)",
              background: color,
              boxShadow: `0 0 0 4px ${color}22, 0 0 12px 2px ${color}55`,
            }}
            onMouseEnter={() => setHover(p)}
            onMouseLeave={() => setHover(null)}
          />
        );
      })}
      {hover && (
        <div
          className="absolute z-10 text-xs rounded-md px-3 py-2 pointer-events-none"
          style={{
            left: project(hover.lat, hover.lon).left,
            top: project(hover.lat, hover.lon).top,
            transform: "translate(-50%, calc(-100% - 12px))",
            background: "#161d35",
            border: "1px solid var(--border)",
            color: "var(--text)",
            whiteSpace: "nowrap",
          }}
        >
          <p className="font-semibold">{hover.city ? `${hover.city}, ` : ""}{hover.country ?? "Desconhecido"}</p>
          <p style={{ color: "var(--text-muted)" }}>
            {hover.count} evento(s) · risco máx {hover.max_risk}
          </p>
        </div>
      )}
      {points.length === 0 && (
        <div className="absolute inset-0 flex items-center justify-center text-xs" style={{ color: "var(--text-muted)" }}>
          Nenhum evento com IP público geolocalizado ainda.
        </div>
      )}
    </div>
  );
}
