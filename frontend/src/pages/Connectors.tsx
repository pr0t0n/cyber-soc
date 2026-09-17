import { useEffect, useState, type FormEvent } from "react";
import { api, ApiError } from "../lib/api";

interface SchemaField {
  key: string;
  label: string;
  type: "text" | "password";
  required: boolean;
  secret: boolean;
  help?: string;
}

interface ConnectorSchema {
  fields: SchemaField[];
  docs_url: string | null;
  mode: string | null;
  test_supported: boolean;
  integration_format: string | null;
}

interface Connector {
  id: number;
  name: string;
  kind: string;
  type: string;
  status: string;
  config: Record<string, unknown>;
  last_test: { status: string; detail?: string } | null;
  schema_fields: SchemaField[];
  docs_url: string | null;
  mode: string | null;
  test_supported: boolean;
  integration_format: string | null;
  ingest_token?: string;
  ingest_endpoint?: string;
}

const KIND_TYPES: Record<string, string[]> = {
  siem: ["wazuh", "elastic", "generic"],
  threatintel: ["abuseipdb", "shodan", "virustotal", "socradar"],
  notification: ["jira", "glpi", "slack", "teams", "webhook", "email"],
};
const KIND_LABEL: Record<string, string> = { siem: "SIEM / Correlacionador de eventos", threatintel: "Threat Intel", notification: "ITSM / Comunicação" };
const MODE_LABEL: Record<string, string> = { push: "A plataforma de origem envia para nós (push)", pull: "Nós consultamos a plataforma de origem (pull)" };

const inputStyle = { background: "var(--surface-2)", border: "1px solid var(--border)", color: "var(--text)" };

export default function Connectors() {
  const [items, setItems] = useState<Connector[]>([]);
  const [schemas, setSchemas] = useState<Record<string, ConnectorSchema>>({});
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [kind, setKind] = useState("siem");
  const [type, setType] = useState("wazuh");
  const [fieldValues, setFieldValues] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [lastToken, setLastToken] = useState<{ token: string; endpoint: string; format: string } | null>(null);
  const [testing, setTesting] = useState<number | null>(null);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [editName, setEditName] = useState("");
  const [editStatus, setEditStatus] = useState("enabled");
  const [editFieldValues, setEditFieldValues] = useState<Record<string, string>>({});
  const [editError, setEditError] = useState<string | null>(null);

  function load() {
    api.get<Connector[]>("/admin/connectors").then(setItems);
  }

  useEffect(() => {
    load();
    api.get<Record<string, ConnectorSchema>>("/admin/connectors/schemas").then(setSchemas);
  }, []);

  const schemaKey = `${kind}:${type}`;
  const activeSchema = schemas[schemaKey];

  function selectKind(newKind: string) {
    setKind(newKind);
    const firstType = KIND_TYPES[newKind][0];
    setType(firstType);
    setFieldValues({});
  }

  function selectType(newType: string) {
    setType(newType);
    setFieldValues({});
  }

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    setError(null);
    const missing = (activeSchema?.fields ?? []).find((f) => f.required && !fieldValues[f.key]?.trim());
    if (missing) {
      setError(`Preencha "${missing.label}".`);
      return;
    }
    const config: Record<string, string> = {};
    for (const f of activeSchema?.fields ?? []) {
      if (fieldValues[f.key]?.trim()) config[f.key] = fieldValues[f.key].trim();
    }
    try {
      const created = await api.post<Connector>("/admin/connectors", { name, kind, type, config });
      if (created.ingest_token) {
        setLastToken({ token: created.ingest_token, endpoint: created.ingest_endpoint!, format: created.integration_format ?? "" });
      }
      setShowForm(false);
      setName("");
      setFieldValues({});
      load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Falha ao criar integração.");
    }
  }

  async function onTest(id: number) {
    setTesting(id);
    await api.post(`/admin/connectors/${id}/test`);
    await load();
    setTesting(null);
  }

  async function onDelete(id: number) {
    await api.delete(`/admin/connectors/${id}`);
    load();
  }

  function onStartEdit(c: Connector) {
    setEditingId(c.id);
    setEditName(c.name);
    setEditStatus(c.status);
    // Pré-preenche com os valores atuais — campos secretos vêm mascarados
    // ("••••••") do GET; deixar como está no submit faz o backend preservar
    // o segredo real (só sobrescreve o que o usuário de fato digitar de novo).
    const values: Record<string, string> = {};
    for (const f of c.schema_fields) {
      const current = c.config[f.key];
      if (current != null) values[f.key] = String(current);
    }
    setEditFieldValues(values);
    setEditError(null);
  }

  function onCancelEdit() {
    setEditingId(null);
    setEditError(null);
  }

  async function onSaveEdit(c: Connector) {
    setEditError(null);
    const missing = c.schema_fields.find((f) => f.required && !editFieldValues[f.key]?.trim());
    if (missing) {
      setEditError(`Preencha "${missing.label}".`);
      return;
    }
    const config: Record<string, string> = {};
    for (const f of c.schema_fields) {
      if (editFieldValues[f.key]?.trim()) config[f.key] = editFieldValues[f.key].trim();
    }
    try {
      await api.patch(`/admin/connectors/${c.id}`, { name: editName, status: editStatus, config });
      setEditingId(null);
      load();
    } catch (err) {
      setEditError(err instanceof ApiError ? err.message : "Falha ao salvar alterações.");
    }
  }

  return (
    <div className="p-8 max-w-4xl">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight" style={{ color: "var(--text)" }}>Integrações</h1>
          <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>
            A plataforma só coleta logs de fontes com integração cadastrada e habilitada aqui.
          </p>
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
          {lastToken.format && (
            <pre className="mt-2 text-[11px] rounded-lg p-3 overflow-x-auto whitespace-pre-wrap" style={{ background: "var(--surface)", color: "var(--text-muted)" }}>
              {lastToken.format}
            </pre>
          )}
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
              <select value={kind} onChange={(e) => selectKind(e.target.value)} className="w-full text-sm rounded-lg px-3 py-2" style={inputStyle}>
                {Object.keys(KIND_TYPES).map((k) => <option key={k} value={k}>{KIND_LABEL[k]}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium mb-1" style={{ color: "var(--text-muted)" }}>Plataforma</label>
              <select value={type} onChange={(e) => selectType(e.target.value)} className="w-full text-sm rounded-lg px-3 py-2" style={inputStyle}>
                {KIND_TYPES[kind].map((t) => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
          </div>

          {activeSchema && (
            <div className="rounded-lg px-3 py-2 text-[11px]" style={{ background: "var(--surface)", border: "1px solid var(--border)", color: "var(--text-muted)" }}>
              {activeSchema.mode && <p className="mb-1">{MODE_LABEL[activeSchema.mode] ?? activeSchema.mode}</p>}
              {activeSchema.docs_url && (
                <a href={activeSchema.docs_url} target="_blank" rel="noreferrer" style={{ color: "var(--accent)" }}>
                  Documentação oficial ↗
                </a>
              )}
            </div>
          )}

          {(activeSchema?.fields ?? []).map((f) => (
            <div key={f.key}>
              <label className="block text-xs font-medium mb-1" style={{ color: "var(--text-muted)" }}>
                {f.label}{f.required && " *"}
              </label>
              <input
                type={f.type === "password" ? "password" : "text"}
                value={fieldValues[f.key] ?? ""}
                onChange={(e) => setFieldValues((v) => ({ ...v, [f.key]: e.target.value }))}
                className="w-full text-sm rounded-lg px-3 py-2"
                style={inputStyle}
              />
              {f.help && <p className="text-[10px] mt-1" style={{ color: "var(--text-muted)" }}>{f.help}</p>}
            </div>
          ))}

          {activeSchema?.integration_format && (
            <div>
              <label className="block text-xs font-medium mb-1" style={{ color: "var(--text-muted)" }}>Formato de integração (o que configurar na plataforma de origem)</label>
              <pre className="text-[11px] rounded-lg p-3 overflow-x-auto whitespace-pre-wrap" style={{ background: "var(--surface)", border: "1px solid var(--border)", color: "var(--text-muted)" }}>
                {activeSchema.integration_format}
              </pre>
            </div>
          )}

          {error && <p className="text-xs" style={{ color: "var(--sev-critica)" }}>{error}</p>}
          <button type="submit" className="self-start text-sm rounded-lg px-4 py-2 font-semibold text-slate-950" style={{ background: "linear-gradient(90deg, var(--accent), var(--accent-2))" }}>
            Salvar
          </button>
        </form>
      )}

      <div className="flex flex-col gap-2">
        {items.map((c) => (
          <div key={c.id} className="glass-card rounded-xl p-4">
            {editingId === c.id ? (
              <div className="flex flex-col gap-3">
                <div>
                  <label className="block text-xs font-medium mb-1" style={{ color: "var(--text-muted)" }}>Nome</label>
                  <input value={editName} onChange={(e) => setEditName(e.target.value)} className="w-full text-sm rounded-lg px-3 py-2" style={inputStyle} />
                </div>
                <div className="grid grid-cols-2 gap-3 text-xs" style={{ color: "var(--text-muted)" }}>
                  <p>Categoria: <span style={{ color: "var(--text)" }}>{KIND_LABEL[c.kind] ?? c.kind}</span></p>
                  <p>Plataforma: <span style={{ color: "var(--text)" }}>{c.type}</span> (não editável — exclua e crie outra para trocar)</p>
                </div>
                <div>
                  <label className="block text-xs font-medium mb-1" style={{ color: "var(--text-muted)" }}>Status</label>
                  <select value={editStatus} onChange={(e) => setEditStatus(e.target.value)} className="w-full text-sm rounded-lg px-3 py-2" style={inputStyle}>
                    <option value="enabled">Habilitada</option>
                    <option value="disabled">Desabilitada</option>
                  </select>
                </div>
                {c.schema_fields.map((f) => (
                  <div key={f.key}>
                    <label className="block text-xs font-medium mb-1" style={{ color: "var(--text-muted)" }}>
                      {f.label}{f.required && " *"}
                    </label>
                    <input
                      type={f.type === "password" ? "password" : "text"}
                      value={editFieldValues[f.key] ?? ""}
                      onChange={(e) => setEditFieldValues((v) => ({ ...v, [f.key]: e.target.value }))}
                      className="w-full text-sm rounded-lg px-3 py-2"
                      style={inputStyle}
                    />
                    {f.secret && editFieldValues[f.key] === "••••••" && (
                      <p className="text-[10px] mt-1" style={{ color: "var(--text-muted)" }}>Mantido sem alteração — apague e digite um novo valor para trocar.</p>
                    )}
                    {f.help && !(f.secret && editFieldValues[f.key] === "••••••") && (
                      <p className="text-[10px] mt-1" style={{ color: "var(--text-muted)" }}>{f.help}</p>
                    )}
                  </div>
                ))}
                {editError && <p className="text-xs" style={{ color: "var(--sev-critica)" }}>{editError}</p>}
                <div className="flex gap-2">
                  <button
                    onClick={() => onSaveEdit(c)}
                    className="text-sm rounded-lg px-4 py-2 font-semibold text-slate-950"
                    style={{ background: "linear-gradient(90deg, var(--accent), var(--accent-2))" }}
                  >
                    Salvar
                  </button>
                  <button onClick={onCancelEdit} className="text-sm rounded-lg px-4 py-2" style={{ border: "1px solid var(--border)", color: "var(--text)" }}>
                    Cancelar
                  </button>
                </div>
              </div>
            ) : (
              <>
                <div className="flex items-center justify-between">
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
                      {c.docs_url && (
                        <> · <a href={c.docs_url} target="_blank" rel="noreferrer" style={{ color: "var(--accent)" }}>docs ↗</a></>
                      )}
                      {c.last_test && ` · último teste: ${c.last_test.status}${c.last_test.detail ? ` (${c.last_test.detail})` : ""}`}
                    </p>
                  </div>
                  <div className="flex gap-2 shrink-0">
                    <button onClick={() => onStartEdit(c)} className="text-xs rounded-lg px-3 py-1.5" style={{ border: "1px solid var(--border)", color: "var(--text)" }}>
                      Editar
                    </button>
                    <button
                      onClick={() => onTest(c.id)}
                      disabled={testing === c.id}
                      className="text-xs rounded-lg px-3 py-1.5 disabled:opacity-50"
                      style={{ border: "1px solid var(--border)", color: "var(--text)" }}
                      title={c.test_supported ? undefined : "Sem teste ao vivo implementado para esta plataforma ainda"}
                    >
                      {testing === c.id ? "Testando…" : "Testar"}
                    </button>
                    <button onClick={() => onDelete(c.id)} className="text-xs rounded-lg px-3 py-1.5" style={{ border: "1px solid rgba(244,63,94,0.4)", color: "var(--sev-critica)" }}>
                      Excluir
                    </button>
                  </div>
                </div>
                {c.integration_format && (
                  <details className="mt-2">
                    <summary className="text-[11px] cursor-pointer" style={{ color: "var(--text-muted)" }}>Formato de integração</summary>
                    <pre className="mt-1 text-[11px] rounded-lg p-3 overflow-x-auto whitespace-pre-wrap" style={{ background: "var(--surface)", color: "var(--text-muted)" }}>
                      {c.integration_format}
                    </pre>
                  </details>
                )}
              </>
            )}
          </div>
        ))}
        {items.length === 0 && <p className="text-sm" style={{ color: "var(--text-muted)" }}>Nenhuma integração cadastrada ainda — sem integração, a plataforma não coleta nada dessa fonte.</p>}
      </div>
    </div>
  );
}
