import { useEffect, useState, type FormEvent } from "react";
import { api, ApiError } from "../lib/api";
import { useAuth } from "../lib/auth";
import type { User } from "../lib/auth";

export default function Users() {
  const { user: me } = useAuth();
  const [items, setItems] = useState<User[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("analista");
  const [error, setError] = useState<string | null>(null);

  function load() {
    api.get<User[]>("/auth/users").then(setItems).catch(() => setItems([]));
  }

  useEffect(load, []);

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.post("/auth/users", { name, email, password, role });
      setShowForm(false);
      setName("");
      setEmail("");
      setPassword("");
      load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Falha ao criar usuário.");
    }
  }

  async function onDelete(id: number) {
    await api.delete(`/auth/users/${id}`);
    load();
  }

  const inputStyle = { background: "var(--surface-2)", border: "1px solid var(--border)", color: "var(--text)" };

  if (me?.role !== "admin" && me?.role !== "gestor") {
    return <div className="p-8 text-sm" style={{ color: "var(--text-muted)" }}>Apenas administradores/gestores acessam esta página.</div>;
  }

  return (
    <div className="p-8 max-w-3xl">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight" style={{ color: "var(--text)" }}>Usuários</h1>
          <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>Contas concedidas pelo administrador — sem autocadastro</p>
        </div>
        {me?.role === "admin" && (
          <button
            onClick={() => setShowForm((v) => !v)}
            className="text-sm rounded-lg px-4 py-2 font-semibold text-slate-950"
            style={{ background: "linear-gradient(90deg, var(--accent), var(--accent-2))" }}
          >
            {showForm ? "Cancelar" : "Novo usuário"}
          </button>
        )}
      </div>

      {showForm && (
        <form onSubmit={onCreate} className="glass-card rounded-xl p-5 mb-6 grid grid-cols-2 gap-3">
          <input required placeholder="Nome" value={name} onChange={(e) => setName(e.target.value)} className="text-sm rounded-lg px-3 py-2" style={inputStyle} />
          <input required type="email" placeholder="E-mail" value={email} onChange={(e) => setEmail(e.target.value)} className="text-sm rounded-lg px-3 py-2" style={inputStyle} />
          <input required type="password" placeholder="Senha inicial" value={password} onChange={(e) => setPassword(e.target.value)} className="text-sm rounded-lg px-3 py-2" style={inputStyle} />
          <select value={role} onChange={(e) => setRole(e.target.value)} className="text-sm rounded-lg px-3 py-2" style={inputStyle}>
            <option value="analista">analista</option>
            <option value="gestor">gestor</option>
            <option value="admin">admin</option>
          </select>
          {error && <p className="col-span-2 text-xs" style={{ color: "var(--sev-critica)" }}>{error}</p>}
          <button type="submit" className="col-span-2 self-start text-sm rounded-lg px-4 py-2 font-semibold text-slate-950" style={{ background: "linear-gradient(90deg, var(--accent), var(--accent-2))" }}>
            Criar
          </button>
        </form>
      )}

      <div className="glass-card rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead style={{ background: "var(--surface-2)" }}>
            <tr>
              {["Nome", "E-mail", "Papel", "Status", ""].map((h) => (
                <th key={h} className="text-left px-4 py-2.5 font-medium text-[10px] uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {items.map((u) => (
              <tr key={u.id} style={{ borderTop: "1px solid var(--border)" }}>
                <td className="px-4 py-2.5" style={{ color: "var(--text)" }}>{u.name}</td>
                <td className="px-4 py-2.5" style={{ color: "var(--text-muted)" }}>{u.email}</td>
                <td className="px-4 py-2.5" style={{ color: "var(--text-muted)" }}>{u.role}</td>
                <td className="px-4 py-2.5" style={{ color: "var(--text-muted)" }}>{u.status}</td>
                <td className="px-4 py-2.5 text-right">
                  {me?.role === "admin" && u.id !== me.id && (
                    <button onClick={() => onDelete(u.id)} className="text-xs" style={{ color: "var(--sev-critica)" }}>
                      Remover
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
