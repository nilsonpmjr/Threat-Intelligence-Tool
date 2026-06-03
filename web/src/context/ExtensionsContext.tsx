import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import API_URL from "../config";
import { useAuth } from "./AuthContext";

type ExtensionFeature = "hunting_provider" | "exposure_provider";

interface ExtensionsContextValue {
  features: ExtensionFeature[];
  loading: boolean;
  hasFeature: (feature: ExtensionFeature) => boolean;
  refreshFeatures: () => Promise<void>;
}

const ExtensionsContext = createContext<ExtensionsContextValue | null>(null);

export function ExtensionsProvider({ children }: { children: ReactNode }) {
  const { user, loading: authLoading } = useAuth();
  const [features, setFeatures] = useState<ExtensionFeature[]>([]);
  const [loading, setLoading] = useState(true);

  const refreshFeatures = useCallback(async () => {
    if (!user) {
      setFeatures([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const response = await fetch(`${API_URL}/api/admin/extensions/features`, {
        credentials: "include",
      });
      if (!response.ok) {
        throw new Error("extension_features_load_failed");
      }
      const data = (await response.json()) as { features?: ExtensionFeature[] };
      setFeatures((data.features || []).filter(Boolean));
    } catch {
      setFeatures([]);
    } finally {
      setLoading(false);
    }
  }, [user]);

  useEffect(() => {
    if (authLoading) return;
    void refreshFeatures();
  }, [authLoading, refreshFeatures]);

  const value = useMemo<ExtensionsContextValue>(
    () => ({
      features,
      loading,
      hasFeature: (feature) => features.includes(feature),
      refreshFeatures,
    }),
    [features, loading, refreshFeatures],
  );

  return <ExtensionsContext.Provider value={value}>{children}</ExtensionsContext.Provider>;
}

export function useExtensions() {
  const context = useContext(ExtensionsContext);
  if (!context) {
    throw new Error("useExtensions must be used within ExtensionsProvider");
  }
  return context;
}

export function RequireExtensionFeature({
  children,
  feature,
}: {
  children: ReactNode;
  feature: ExtensionFeature;
}) {
  const { loading, hasFeature } = useExtensions();

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="bg-surface-container-lowest shadow-sm rounded-sm px-6 py-5 text-[11px] font-bold uppercase tracking-[0.2em] text-on-surface-variant">
          Verifying extension access
        </div>
      </div>
    );
  }

  if (!hasFeature(feature)) {
    return (
      <div className="page-frame">
        <div className="max-w-3xl rounded-sm border border-outline-variant/15 bg-surface-container-lowest p-8 shadow-sm space-y-4">
          <div className="text-[11px] font-bold uppercase tracking-[0.18em] text-outline">Extension Access</div>
          <h1 className="text-2xl font-black tracking-tight text-on-surface">This extension is not enabled</h1>
          <p className="text-sm text-on-surface-variant">
            The selected premium surface is currently disabled in the Extensions Catalog.
          </p>
          <Link to="/" className="btn btn-outline inline-flex">
            Return Home
          </Link>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}
