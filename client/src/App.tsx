import { Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './hooks/useAuth';
import Layout from './components/Layout';
import Login from './pages/Login';
import Overview from './pages/Overview';
import Alerts from './pages/Alerts';
import Incidents from './pages/Incidents';
import Assets from './pages/Assets';
import Identities from './pages/Identities';
import Credentials from './pages/Credentials';
import Policies from './pages/Policies';
import ThreatIntel from './pages/ThreatIntel';
import Events from './pages/Events';
import Audit from './pages/Audit';
import GrokAnalyst from './pages/GrokAnalyst';

function PrivateRoute({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center text-slate-500">
        Loading Aegis SOC…
      </div>
    );
  }
  if (!user) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/" element={<PrivateRoute><Layout /></PrivateRoute>}>
        <Route index element={<Overview />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="incidents" element={<Incidents />} />
        <Route path="assets" element={<Assets />} />
        <Route path="identities" element={<Identities />} />
        <Route path="credentials" element={<Credentials />} />
        <Route path="policies" element={<Policies />} />
        <Route path="threat-intel" element={<ThreatIntel />} />
        <Route path="events" element={<Events />} />
        <Route path="audit" element={<Audit />} />
        <Route path="grok" element={<GrokAnalyst />} />
      </Route>
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
