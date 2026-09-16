import { useState, type FormEvent } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../lib/auth";
import { ApiError } from "../lib/api";
import { IconShield } from "../components/icons";

export default function Login() {
  const { user, login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (user) return <Navigate to="/" replace />;

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await login(email, password);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Falha ao entrar.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      className="min-h-screen flex items-center justify-center relative overflow-hidden"
      style={{ background: "var(--bg)" }}
    >
      <div
        className="absolute inset-0 opacity-40"
        style={{ background: "radial-gradient(600px circle at 30% 20%, rgba(34,211,238,0.12), transparent 60%), radial-gradient(600px circle at 80% 80%, rgba(99,102,241,0.12), transparent 60%)" }}
      />
      <form onSubmit={onSubmit} className="relative w-full max-w-sm glass-card rounded-2xl p-9 shadow-2xl">
        <div className="flex items-center gap-3 mb-8">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center" style={{ background: "linear-gradient(135deg, var(--accent), var(--accent-2))" }}>
            <IconShield className="w-5 h-5 text-slate-950" />
          </div>
          <div>
            <p className="text-base font-semibold" style={{ color: "var(--text)" }}>Cyber SOC Copilot</p>
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>Acesso restrito · N1/N2</p>
          </div>
        </div>

        <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-muted)" }}>E-mail</label>
        <input
          type="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="w-full rounded-lg px-3.5 py-2.5 text-sm mb-4 focus:outline-none focus:ring-2"
          style={{ background: "var(--surface-2)", border: "1px solid var(--border)", color: "var(--text)" }}
        />

        <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-muted)" }}>Senha</label>
        <input
          type="password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="w-full rounded-lg px-3.5 py-2.5 text-sm mb-5 focus:outline-none focus:ring-2"
          style={{ background: "var(--surface-2)", border: "1px solid var(--border)", color: "var(--text)" }}
        />

        {error && <p className="text-xs mb-4" style={{ color: "var(--sev-critica)" }}>{error}</p>}

        <button
          type="submit"
          disabled={busy}
          className="w-full rounded-lg text-sm font-semibold py-2.5 disabled:opacity-50 text-slate-950"
          style={{ background: "linear-gradient(90deg, var(--accent), var(--accent-2))" }}
        >
          {busy ? "Entrando…" : "Entrar"}
        </button>
        <p className="text-[11px] text-center mt-5" style={{ color: "var(--text-muted)" }}>
          Contas concedidas apenas pelo administrador — sem autocadastro.
        </p>
      </form>
    </div>
  );
}
