// Paginação compartilhada (Incidentes/Análises/Raw, dentro de Resposta) — só
// avança/volta uma página por vez de propósito (nunca "pular pra página 50"):
// as listas aqui são investigativas, o analista lê em ordem, não busca um
// número de página específico.
export default function Pagination({
  total, limit, offset, onOffsetChange,
}: {
  total: number; limit: number; offset: number; onOffsetChange: (next: number) => void;
}) {
  if (total <= limit) return null;
  const page = Math.floor(offset / limit) + 1;
  const totalPages = Math.max(1, Math.ceil(total / limit));
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(offset + limit, total);

  return (
    <div className="flex items-center justify-between px-4 py-3 text-xs" style={{ borderTop: "1px solid var(--border)", color: "var(--text-muted)" }}>
      <span>
        {from}–{to} de {total} · página {page}/{totalPages}
      </span>
      <div className="flex items-center gap-2">
        <button
          onClick={() => onOffsetChange(Math.max(0, offset - limit))}
          disabled={offset === 0}
          className="rounded-lg px-3 py-1.5 font-medium disabled:opacity-40"
          style={{ background: "var(--surface-2)", border: "1px solid var(--border)", color: "var(--text)" }}
        >
          ← Anterior
        </button>
        <button
          onClick={() => onOffsetChange(offset + limit)}
          disabled={offset + limit >= total}
          className="rounded-lg px-3 py-1.5 font-medium disabled:opacity-40"
          style={{ background: "var(--surface-2)", border: "1px solid var(--border)", color: "var(--text)" }}
        >
          Próxima →
        </button>
      </div>
    </div>
  );
}
