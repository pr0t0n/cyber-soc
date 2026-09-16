import { useState, type FormEvent } from "react";
import { api } from "../lib/api";

interface Message {
  role: "user" | "assistant";
  content: string;
  degraded?: boolean;
}

export default function Chat() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (!input.trim()) return;
    const question = input;
    setInput("");
    setMessages((m) => [...m, { role: "user", content: question }]);
    setBusy(true);
    try {
      const res = await api.post<{ answer: string; degraded: boolean }>("/chat", { message: question });
      setMessages((m) => [...m, { role: "assistant", content: res.answer, degraded: res.degraded }]);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="p-8 max-w-3xl flex flex-col h-screen">
      <div className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight" style={{ color: "var(--text)" }}>Copilot</h1>
        <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>Pergunte sobre eventos, risco, IP ou incidente</p>
      </div>

      <div className="flex-1 overflow-y-auto flex flex-col gap-3 mb-4">
        {messages.length === 0 && (
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>
            Ex.: "algum evento crítico hoje?", "o que é o IP 185.220.101.8?"
          </p>
        )}
        {messages.map((m, i) => (
          <div
            key={i}
            className="max-w-[85%] rounded-xl px-4 py-2.5 text-sm whitespace-pre-wrap"
            style={
              m.role === "user"
                ? { alignSelf: "flex-end", background: "linear-gradient(90deg, var(--accent), var(--accent-2))", color: "#04101c" }
                : { alignSelf: "flex-start", background: "var(--surface-2)", border: "1px solid var(--border)", color: "var(--text)" }
            }
          >
            {m.content}
            {m.degraded && <p className="text-[10px] mt-1" style={{ color: "var(--sev-media)" }}>IA indisponível — resposta em modo degradado</p>}
          </div>
        ))}
      </div>

      <form onSubmit={onSubmit} className="flex gap-2">
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Digite sua pergunta…"
          className="flex-1 text-sm rounded-lg px-3.5 py-2.5"
          style={{ background: "var(--surface-2)", border: "1px solid var(--border)", color: "var(--text)" }}
        />
        <button
          disabled={busy}
          className="text-sm rounded-lg px-5 py-2.5 font-semibold disabled:opacity-50 text-slate-950"
          style={{ background: "linear-gradient(90deg, var(--accent), var(--accent-2))" }}
        >
          Enviar
        </button>
      </form>
    </div>
  );
}
