import type { ReactNode } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./lib/auth";
import Layout from "./components/Layout";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Events from "./pages/Events";
import Raw from "./pages/Raw";
import Connectors from "./pages/Connectors";
import Chat from "./pages/Chat";
import Rules from "./pages/Rules";
import Users from "./pages/Users";

function Protected({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="p-8 text-slate-400">Carregando…</div>;
  if (!user) return <Navigate to="/login" replace />;
  return <Layout>{children}</Layout>;
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/" element={<Protected><Dashboard /></Protected>} />
      <Route path="/eventos" element={<Protected><Events /></Protected>} />
      <Route path="/raw" element={<Protected><Raw /></Protected>} />
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
