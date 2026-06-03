/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { Component, Suspense, lazy, type ReactNode } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/Layout";
import { AuthProvider, RequireAuth, RequirePathAccess } from "./context/AuthContext";
import { LanguageProvider } from "./context/LanguageContext";
import { ThemeProvider } from "./context/ThemeContext";

class ErrorBoundary extends Component<
  { children: ReactNode },
  { hasError: boolean }
> {
  state = { hasError: false };

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="page-frame">
          <div className="card p-6 text-sm text-on-surface-variant">
            Something went wrong loading this page.{" "}
            <button
              className="underline"
              onClick={() => {
                this.setState({ hasError: false });
                window.location.reload();
              }}
            >
              Reload
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

const SettingsLayout = lazy(() => import("./components/SettingsLayout"));
const Home = lazy(() => import("./pages/Home"));
const Feed = lazy(() => import("./pages/Feed"));
const Recon = lazy(() => import("./pages/Recon"));
const Watchlist = lazy(() => import("./pages/Watchlist"));
const Dashboard = lazy(() => import("./pages/Dashboard"));
const ExtensionsCatalog = lazy(() => import("./pages/ExtensionsCatalog"));
const ThreatIngestion = lazy(() => import("./pages/ThreatIngestion"));
const SystemHealth = lazy(() => import("./pages/SystemHealth"));
const UsersRoles = lazy(() => import("./pages/UsersRoles"));
const SecurityPolicies = lazy(() => import("./pages/SecurityPolicies"));
const ApiCredentials = lazy(() => import("./pages/ApiCredentials"));
const Profile = lazy(() => import("./pages/Profile"));
const Notifications = lazy(() => import("./pages/Notifications"));
const AnalysisResult = lazy(() => import("./pages/AnalysisResult"));
const BatchAnalysis = lazy(() => import("./pages/BatchAnalysis"));
const SoccChat = lazy(() => import("./pages/socc/SoccChat"));
const ShiftHandoff = lazy(() => import("./pages/ShiftHandoff"));
const ShiftHandoffHistoryPage = lazy(async () => {
  const module = await import("./pages/ShiftHandoff");
  return { default: module.ShiftHandoffHistoryPage };
});
const ShiftHandoffIncidentsPage = lazy(async () => {
  const module = await import("./pages/ShiftHandoff");
  return { default: module.ShiftHandoffActiveIncidentsPage };
});
const HelpLayout = lazy(() => import("./pages/help/HelpLayout"));
const DocsPage = lazy(() => import("./pages/help/DocsPage"));
const ShortcutsPage = lazy(() => import("./pages/help/ShortcutsPage"));
const ApiReferencePage = lazy(() => import("./pages/help/ApiReferencePage"));
const ContactSupportPage = lazy(() => import("./pages/help/ContactSupportPage"));

function RouteFallback() {
  return (
    <div className="page-frame">
      <div className="card p-6 text-sm text-on-surface-variant">Loading workspace...</div>
    </div>
  );
}

function suspense(element: ReactNode) {
  return (
    <ErrorBoundary>
      <Suspense fallback={<RouteFallback />}>{element}</Suspense>
    </ErrorBoundary>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <LanguageProvider>
          <BrowserRouter>
            <Routes>
              <Route
                path="/"
                element={
                    <RequireAuth>
                      <Layout />
                    </RequireAuth>
                }
              >
                <Route index element={suspense(<Home />)} />
                <Route path="feed" element={suspense(<Feed />)} />
                <Route path="recon" element={suspense(<Recon />)} />
                <Route path="watchlist" element={suspense(<Watchlist />)} />
                <Route path="dashboard" element={suspense(<Dashboard />)} />
                <Route
                  path="settings"
                  element={
                    <RequirePathAccess path="/settings">
                      {suspense(<SettingsLayout />)}
                    </RequirePathAccess>
                  }
                >
                  <Route index element={<Navigate to="/settings/extensions" replace />} />
                  <Route path="patterns" element={<Navigate to="/settings/extensions" replace />} />
                  <Route path="extensions" element={suspense(<ExtensionsCatalog />)} />
                  <Route path="threat-ingestion" element={suspense(<ThreatIngestion />)} />
                  <Route path="system-health" element={suspense(<SystemHealth />)} />
                  <Route path="users-roles" element={suspense(<UsersRoles />)} />
                  <Route path="security-policies" element={suspense(<SecurityPolicies />)} />
                  <Route path="api-credentials" element={suspense(<ApiCredentials />)} />
                </Route>
                <Route path="profile" element={suspense(<Profile />)} />
                <Route path="notifications" element={suspense(<Notifications />)} />
                <Route path="analyze/:target" element={suspense(<AnalysisResult />)} />
                <Route path="batch" element={suspense(<BatchAnalysis />)} />
                <Route path="socc" element={suspense(<SoccChat />)} />
                <Route path="shift-handoff" element={suspense(<ShiftHandoff />)} />
                <Route path="shift-handoff/history" element={suspense(<ShiftHandoffHistoryPage />)} />
                <Route path="shift-handoff/incidents" element={suspense(<ShiftHandoffIncidentsPage />)} />
                <Route path="help" element={suspense(<HelpLayout />)}>
                  <Route index element={<Navigate to="/help/docs" replace />} />
                  <Route path="docs" element={suspense(<DocsPage />)} />
                  <Route path="shortcuts" element={suspense(<ShortcutsPage />)} />
                  <Route path="api" element={suspense(<ApiReferencePage />)} />
                  <Route path="support" element={suspense(<ContactSupportPage />)} />
                </Route>
                <Route path="*" element={<Navigate to="/" replace />} />
              </Route>
            </Routes>
          </BrowserRouter>
        </LanguageProvider>
    </AuthProvider>
    </ThemeProvider>
  );
}
