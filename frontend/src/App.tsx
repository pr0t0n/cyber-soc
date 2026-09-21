import type { ReactNode } from "react";
import { Navigate, Route, Routes, useSearchParams } from "react-router-dom";
import { AuthProvider, useAuth } from "./lib/auth";
import Layout from "./components/Layout";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Connectors from "./pages/Connectors";
import Chat from "./pages/Chat";
import Rules from "./pages/Rules";
import Users from "./pages/Users";
import Resposta from "./pages/Resposta";
import VisaoOperacional from "./pages/VisaoOperacional";

function Protected({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="p-8 text-slate-400">Carregando…</div>;
  if (!user) return <Navigate to="/login" replace />;
  return <Layout>{children}</Layout>;
}

// Incidentes/Análises(Eventos)/Raw viraram abas de /resposta — estas rotas
// existem só pra links/favoritos antigos continuarem funcionando, preservando
// outros parâmetros da URL (ex.: `?event=123` de um deep-link pra Análises).
function RedirectToResposta({ tab }: { tab: string }) {
  const [searchParams] = useSearchParams();
  const params = new URLSearchParams(searchParams);
  params.set("tab", tab);
  return <Navigate to={`/resposta?${params.toString()}`} replace />;
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/" element={<Protected><Dashboard /></Protected>} />
      <Route path="/operacional" element={<Protected><VisaoOperacional /></Protected>} />
      <Route path="/resposta" element={<Protected><Resposta /></Protected>} />
      <Route path="/incidentes" element={<Protected><RedirectToResposta tab="incidentes" /></Protected>} />
      <Route path="/eventos" element={<Protected><RedirectToResposta tab="analises" /></Protected>} />
      <Route path="/raw" element={<Protected><RedirectToResposta tab="raw" /></Protected>} />
      <Route path="/integracoes" element={<Protected><Connectors /></Protected>} />
      <Route path="/usuarios" element={<Protected><Users /></Protected>} />
      <Route path="/chat" element={<Protected><Chat /></Protected>} />
      <Route path="/regras" element={<Protected><Rules /></Protected>} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppRoutes />
    </AuthProvider>
  );
}
