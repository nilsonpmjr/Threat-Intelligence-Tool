import { useEffect, useState } from "react";
import API_URL from "../config";
import { useAuth } from "../context/AuthContext";

// Managed (ExtensionManager) statuses where the extension's container is
// up and reachable. Anything else (not_installed, stopped, installing,
// installing_failed, uninstalling) means the extension is effectively
// disabled and its UI surfaces should stay hidden.
const RUNNING_STATUSES = new Set(["installed_healthy", "installed_unhealthy"]);

interface ManagedExtension {
  id: string;
  status?: string;
}

/**
 * Returns whether a managed (Docker container) extension is currently
 * enabled/running. Used to gate navbar visibility for surfaces like the
 * SOC Copilot — we don't want to advertise an extension a user can't use.
 *
 * Defaults to `false` until the catalog responds so a disabled extension
 * never flashes into the sidebar.
 */
export function useExtensionEnabled(extId: string): { enabled: boolean; loading: boolean } {
  const { user, loading: authLoading } = useAuth();
  const [enabled, setEnabled] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (authLoading) return;
    if (!user) {
      setEnabled(false);
      setLoading(false);
      return;
    }

    let cancelled = false;
    setLoading(true);

    async function loadStatus() {
      try {
        const response = await fetch(`${API_URL}/api/extensions`, {
          credentials: "include",
        });
        if (!response.ok) {
          throw new Error("extensions_load_failed");
        }
        const data = (await response.json()) as { extensions?: ManagedExtension[] };
        const match = (data.extensions || []).find((ext) => ext.id === extId);
        if (!cancelled) {
          setEnabled(Boolean(match && match.status && RUNNING_STATUSES.has(match.status)));
        }
      } catch {
        if (!cancelled) {
          setEnabled(false);
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    void loadStatus();
    return () => {
      cancelled = true;
    };
  }, [authLoading, extId, user]);

  return { enabled, loading };
}
