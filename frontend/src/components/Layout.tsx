import type { ReactNode } from "react";
import { NavLink } from "react-router-dom";
import { useAuth } from "../lib/auth";
import {
  IconBook, IconChat, IconGrid, IconLogout,
  IconPlug, IconRadar, IconSend, IconSettings, IconShield, IconUsers,
} from "./icons";

const NAV = [
  { to: "/", label: "Dashboard", end: true, icon: IconGrid },
  { to: "/operacional", label: "Visão Operacional", icon: IconRadar },
  { to: "/resposta", label: "Resposta e Investigação", icon: IconSend },
  { to: "/chat", label: "Copilot", icon: IconChat },
  { to: "/usuarios", label: "Usuários", icon: IconUsers },
];

// "Sistema": integração (fontes de dados) e regras (Detection Studio) não são
// operação do dia a dia do analista N1/N2 — são configuração/engenharia da
// plataforma, então ficam agrupadas à parte da lista de navegação principal.
const SYSTEM_NAV = [
  { to: "/integracoes", label: "Integrações", icon: IconPlug },
  { to: "/regras", label: "Regras", icon: IconBook },
];

export default function Layout({ children }: { children: ReactNode }) {
  const { user, logout } = useAuth();

  return (
    <div className="flex min-h-screen" style={{ background: "var(--bg)" }}>
      <aside
        className="w-60 shrink-0 flex flex-col"
        style={{ background: "var(--surface)", borderRight: "1px solid var(--border)" }}
      >
        <div className="px-6 py-6 flex items-center gap-2.5" style={{ borderBottom: "1px solid var(--border)" }}>
          <div
            className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
            style={{ background: "linear-gradient(135deg, var(--accent), var(--accent-2))" }}
          >
            <IconShield className="w-[18px] h-[18px] text-slate-950" />
          </div>
          <div>
            <p className="text-sm font-semibold tracking-tight" style={{ color: "var(--text)" }}>
              Cyber SOC
            </p>
            <p className="text-[10px] uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
              Copilot N1/N2
            </p>
          </div>
        </div>

        <nav className="flex-1 py-4 px-3 flex flex-col gap-1 overflow-y-auto">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  isActive ? "text-white" : "hover:bg-white/[0.03]"
                }`
              }
              style={({ isActive }) => ({
                background: isActive ? "linear-gradient(90deg, rgba(34,211,238,0.14), rgba(99,102,241,0.08))" : "transparent",
                color: isActive ? "var(--text)" : "var(--text-muted)",
                borderLeft: isActive ? "2px solid var(--accent)" : "2px solid transparent",
              })}
            >
              <item.icon />
              {item.label}
            </NavLink>
          ))}

          <div className="flex items-center gap-2 px-3.5 pt-4 pb-1.5">
            <IconSettings className="w-3.5 h-3.5" />
            <span className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
              Sistema
            </span>
          </div>
          {SYSTEM_NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  isActive ? "text-white" : "hover:bg-white/[0.03]"
                }`
              }
              style={({ isActive }) => ({
                background: isActive ? "linear-gradient(90deg, rgba(34,211,238,0.14), rgba(99,102,241,0.08))" : "transparent",
                color: isActive ? "var(--text)" : "var(--text-muted)",
                borderLeft: isActive ? "2px solid var(--accent)" : "2px solid transparent",
              })}
            >
              <item.icon />
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="px-5 py-4" style={{ borderTop: "1px solid var(--border)" }}>
          <div className="flex items-center gap-2.5">
            <div
              className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-semibold shrink-0"
              style={{ background: "var(--surface-2)", color: "var(--accent)", border: "1px solid var(--border)" }}
            >
              {user?.name?.[0]?.toUpperCase() ?? "?"}
            </div>
            <div className="min-w-0">
              <p className="text-xs font-medium truncate" style={{ color: "var(--text)" }}>{user?.name}</p>
              <p className="text-[10px] uppercase tracking-wide" style={{ color: "var(--text-muted)" }}>{user?.role}</p>
            </div>
            <button onClick={logout} className="ml-auto p-1.5 rounded-md hover:bg-white/5" style={{ color: "var(--text-muted)" }} title="Sair">
              <IconLogout className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>
      <main className="flex-1 overflow-y-auto">{children}</main>
    </div>
  );
}
