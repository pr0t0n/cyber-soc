import { useEffect, useState, type FormEvent } from "react";
import { api, ApiError } from "../lib/api";

interface Connector {
  id: number;
  name: string;
  kind: string;
  type: string;
  status: string;
  config: Record<string, unknown>;
  last_test: { status: string; detail?: string } | null;
  ingest_token?: string;
  ingest_endpoint?: string;
}

const KIND_TYPES: Record<string, string[]> = {
  siem: ["wazuh", "elastic", "generic"],
  threatintel: ["abuseipdb", "shodan", "virustotal", "socradar"],
  notification: ["jira", "glpi", "slack", "teams", "webhook", "email"],
};

const inputStyle = { background: "var(--surface-2)", border: "1px solid var(--border)", color: "var(--text)" };

export default function Connectors() {
  const [items, setItems] = useState<Connector[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [kind, setKind] = useState("threatintel");
  const [type, setType] = useState("abuseipdb");
  const [clientTag, setClientTag] = useState("");
  const [configText, setConfigText] = useState('{\n  "api_key": ""\n}');
  const [error, setError] = useState<string | null>(null);
  const [lastToken, setLastToken] = useState<{ token: string; endpoint: string } | null>(null);

  function load() {
    api.get<Connector[]>("/admin/connectors").then(setItems);
  }

  useEffect(load, []);

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    setError(null);
    let config: Record<string, unknown>;
    try {
      config = JSON.parse(configText);
    } catch {
      setError("Configuração inválida (JSON).");
      return;
    }
    if (kind === "siem" && clientTag.trim()) config.client_tag = clientTag.trim();
    try {
      const created = await api.post<Connector>("/admin/connectors", { name, kind, type, config });
      if (created.ingest_token) setLastToken({ token: created.ingest_token, endpoint: created.ingest_endpoint! });
      setShowForm(false);
      setName("");
      setClientTag("");
      load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Falha ao criar integração.");
    }
  }

  async function onTest(id: number) {
    await api.post(`/admin/connectors/${id}/test`);
    load();
  }

  async function onDelete(id: number) {
    await api.delete(`/admin/connectors/${id}`);
    load();
  }

  return (
    <div className="p-8 max-w-4xl">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight" style={{ color: "var(--text)" }}>Integrações</h1>
          <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>SIEM, threat intel e ITSM/comunicação</p>
        </div>
        <button
          onClick={() => setShowForm((v) => !v)}
          className="text-sm rounded-lg px-4 py-2 font-semibold text-slate-950"
          style={{ background: "linear-gradient(90deg, var(--accent), var(--accent-2))" }}
        >
          {showForm ? "Cancelar" : "Nova integração"}
        </button>
      </div>

      {lastToken && (
        <div className="glass-card rounded-xl p-4 mb-6 text-xs" style={{ border: "1px solid var(--accent)" }}>
          <p className="font-semibold mb-1" style={{ color: "var(--accent)" }}>Token de ingestão (mostrado uma única vez)</p>
          <p style={{ color: "var(--text)" }}>
            Envie com <code>Authorization: Bearer {lastToken.token}</code> para{" "}
            <code>{lastToken.endpoint}</code>
          </p>
          <button onClick={() => setLastToken(null)} className="mt-2 text-[11px]" style={{ color: "var(--text-muted)" }}>Dispensar</button>
        </div>
      )}

      {showForm && (
        <form onSubmit={onCreate} className="glass-card rounded-xl p-5 mb-6 flex flex-col gap-3">
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: "var(--text-muted)" }}>Nome</label>
            <input required value={name} onChange={(e) => setName(e.target.value)} className="w-full text-sm rounded-lg px-3 py-2" style={inputStyle} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium mb-1" style={{ color: "var(--text-muted)" }}>Categoria</label>
              <select
                value={kind}
                onChange={(e) => { setKind(e.target.value); setType(KIND_TYPES[e.target.value][0]); }}
                className="w-full text-sm rounded-lg px-3 py-2"
                style={inputStyle}
              >
                {Object.keys(KIND_TYPES).map((k) => <option key={k} value={k}>{k}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium mb-1" style={{ color: "var(--text-muted)" }}>Tipo</label>
              <select value={type} onChange={(e) => setType(e.target.value)} className="w-full text-sm rounded-lg px-3 py-2" style={inputStyle}>
                {KIND_TYPES[kind].map((t) => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
          </div>
          {kind === "siem" && (
            <div>
              <label className="block text-xs font-medium mb-1" style={{ color: "var(--text-muted)" }}>
                Tag do cliente (opcional — ex: VALID)
              </label>
              <input
                value={clientTag}
                onChange={(e) => setClientTag(e.target.value)}
                placeholder="VALID"
                className="w-full text-sm rounded-lg px-3 py-2"
                style={inputStyle}
              />
              <p className="text-[10px] mt-1" style={{ color: "var(--text-muted)" }}>
                Eventos ingeridos com o token desta integração ficam marcados com essa tag e podem ser filtrados no dashboard.
              </p>
            </div>
          )}
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: "var(--text-muted)" }}>Configuração (JSON)</label>
            <textarea
              value={configText}
              onChange={(e) => setConfigText(e.target.value)}
              rows={4}
              className="w-full text-xs font-mono rounded-lg px-3 py-2"
              style={inputStyle}
            />
          </div>
          {error && <p className="text-xs" style={{ color: "var(--sev-critica)" }}>{error}</p>}
          <button type="submit" className="self-start text-sm rounded-lg px-4 py-2 font-semibold text-slate-950" style={{ background: "linear-gradient(90deg, var(--accent), var(--accent-2))" }}>
            Salvar
          </button>
        </form>
      )}

      <div className="flex flex-col gap-2">
        {items.map((c) => (
          <div key={c.id} className="glass-card rounded-xl p-4 flex items-center justify-between">
            <div>
              <p className="text-sm font-medium" style={{ color: "var(--text)" }}>
                {c.name} {c.config.client_tag ? (
                  <span className="ml-2 px-2 py-0.5 rounded-full text-[10px] font-medium" style={{ background: "rgba(34,211,238,0.12)", color: "var(--accent)" }}>
                    {String(c.config.client_tag)}
                  </span>
                ) : null}
              </p>
              <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
                {c.kind} · {c.type} · {c.status}
                {c.last_test && ` · último teste: ${c.last_test.status}`}
              </p>
            </div>
            <div className="flex gap-2">
              <button onClick={() => onTest(c.id)} className="text-xs rounded-lg px-3 py-1.5" style={{ border: "1px solid var(--border)", color: "var(--text)" }}>
                Testar
              </button>
              <button onClick={() => onDelete(c.id)} className="text-xs rounded-lg px-3 py-1.5" style={{ border: "1px solid rgba(244,63,94,0.4)", color: "var(--sev-critica)" }}>
                Excluir
              </button>
            </div>
          </div>
        ))}
        {items.length === 0 && <p className="text-sm" style={{ color: "var(--text-muted)" }}>Nenhuma integração cadastrada ainda.</p>}
      </div>
    </div>
  );
}
