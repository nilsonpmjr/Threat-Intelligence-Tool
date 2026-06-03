/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Orchestrated Extensions section — renders extension cards from the
 * /api/extensions contract with lifecycle management (install, uninstall,
 * start, stop, restart), settings, secrets rotation, and live log streaming.
 * This component is embedded inside ExtensionsCatalog.tsx, NOT used as a
 * standalone page.
 */

import { useState, useEffect, useCallback } from "react";
import { Boxes, RefreshCw, AlertCircle, Search } from "lucide-react";
import { useLanguage } from "../../context/LanguageContext";
import ExtensionCard from "./ExtensionCard";
import {
  listExtensions,
  installExtension,
  uninstallExtension,
  startExtension,
  stopExtension,
  restartExtension,
  updateExtensionSettings,
  rotateExtensionSecret,
  type ExtensionManifest,
} from "./lib/api";
import { pollExtensionStatus } from "./lib/poll";
import UninstallModal from "./modals/UninstallModal";
import LogsModal from "./modals/LogsModal";
import SettingsModal from "./modals/SettingsModal";
import SecretsModal from "./modals/SecretsModal";

export default function OrchestratedExtensions() {
  const { t } = useLanguage();
  const [extensions, setExtensions] = useState<ExtensionManifest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [busyId, setBusyId] = useState<string | null>(null);

  // Modal states
  const [activeUninstall, setActiveUninstall] = useState<ExtensionManifest | null>(null);
  const [activeLogs, setActiveLogs] = useState<ExtensionManifest | null>(null);
  const [activeSettings, setActiveSettings] = useState<ExtensionManifest | null>(null);
  const [activeSecrets, setActiveSecrets] = useState<ExtensionManifest | null>(null);

  const loadData = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const data = await listExtensions();
      setExtensions(data);
      setError(null);
    } catch {
      setError(t("extensions.error.load_failed", "Failed to load extensions catalog."));
    } finally {
      if (!silent) setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  // Poll extensions in transition states (installing/uninstalling)
  useEffect(() => {
    const transitionIds = extensions
      .filter((ext) => ext.status === "installing" || ext.status === "uninstalling")
      .map((ext) => ext.id);

    transitionIds.forEach((id) => {
      void pollExtensionStatus(
        id,
        (updated) => {
          setExtensions((prev) => prev.map((ext) => ext.id === id ? updated : ext));
        },
        () => {
          // Polling completed naturally
        },
        (err) => {
          console.error(`Polling error for ${id}:`, err);
        }
      );
    });
  }, [extensions.length]);

  const handleAction = async (id: string, action: string) => {
    const ext = extensions.find(e => e.id === id);
    if (!ext) return;

    try {
      setBusyId(id);
      switch (action) {
        case "install":
          await installExtension(id);
          await loadData(true);
          break;
        case "start":
          await startExtension(id);
          await loadData(true);
          break;
        case "stop":
          await stopExtension(id);
          await loadData(true);
          break;
        case "restart":
          await restartExtension(id);
          await loadData(true);
          break;
        case "uninstall":
          setActiveUninstall(ext);
          break;
        case "logs":
          setActiveLogs(ext);
          break;
        case "settings":
          setActiveSettings(ext);
          break;
        case "secrets":
          setActiveSecrets(ext);
          break;
      }
    } catch (err) {
      console.error(`Action ${action} failed for ${id}:`, err);
    } finally {
      setBusyId(null);
    }
  };

  const confirmUninstall = async (phrase: string, destroyVolumes: boolean) => {
    if (!activeUninstall) return;
    try {
      setBusyId(activeUninstall.id);
      await uninstallExtension(activeUninstall.id, phrase, destroyVolumes);
      setActiveUninstall(null);
      await loadData(true);
    } catch (err) {
      console.error("Uninstall failed:", err);
    } finally {
      setBusyId(null);
    }
  };

  const saveSettings = async (settings: Record<string, any>) => {
    if (!activeSettings) return;
    try {
      setBusyId(activeSettings.id);
      await updateExtensionSettings(activeSettings.id, settings);
      setActiveSettings(null);
      await loadData(true);
    } catch (err) {
      console.error("Settings update failed:", err);
    } finally {
      setBusyId(null);
    }
  };

  const rotateSecret = async (secretName: string) => {
    if (!activeSecrets) return;
    try {
      setBusyId(activeSecrets.id);
      await rotateExtensionSecret(activeSecrets.id, secretName);
      const updated = await listExtensions();
      setExtensions(updated);
      const newActive = updated.find(e => e.id === activeSecrets.id);
      if (newActive) setActiveSecrets(newActive);
    } catch (err) {
      console.error("Secret rotation failed:", err);
    } finally {
      setBusyId(null);
    }
  };

  const filteredExtensions = extensions.filter(ext =>
    ext.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    ext.description.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <>
      <section className="surface-section overflow-hidden">
        <div className="surface-section-header">
          <div>
            <h3 className="surface-section-title">
              {t("extensions.title", "Extensions Platform")}
            </h3>
            <p className="mt-1 text-[10px] font-medium uppercase tracking-widest text-on-surface-variant">
              {t("extensions.subtitle", "Manage and orchestrate threat intelligence modules, connectors, and AI agents.")}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => void loadData()}
              disabled={loading}
              className="btn btn-outline btn-sm gap-2"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
              {t("common.refresh", "Refresh")}
            </button>
          </div>
        </div>

        <div className="p-6">
          {/* Search */}
          <div className="max-w-md relative mb-6">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-outline" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder={t("extensions.search_placeholder", "Search extensions...")}
              className="w-full bg-surface-container-high border border-outline-variant/10 rounded-sm pl-10 pr-4 py-2 text-sm focus:outline-none focus:border-primary/40 transition-colors"
            />
          </div>

          {/* Error */}
          {error && (
            <div className="mb-6 p-4 rounded-sm bg-error/10 border border-error/20 flex gap-3 text-error">
              <AlertCircle className="w-5 h-5 shrink-0" />
              <p className="text-sm font-medium">{error}</p>
            </div>
          )}

          {/* Content */}
          {loading && extensions.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-outline">
              <RefreshCw className="w-10 h-10 animate-spin mb-4" />
              <p className="text-sm font-bold uppercase tracking-[0.2em]">
                {t("extensions.loading", "Loading catalog...")}
              </p>
            </div>
          ) : filteredExtensions.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-outline border border-dashed border-outline-variant/20 rounded-sm">
              <Boxes className="w-14 h-14 mb-4 opacity-20" />
              <h3 className="text-base font-black uppercase tracking-tight text-on-surface-variant">
                {t("extensions.empty_title", "No Extensions Found")}
              </h3>
              <p className="text-sm mt-1 max-w-xs text-center leading-relaxed">
                {extensions.length === 0
                  ? t("extensions.empty_catalog", "No extensions are declared in backend/extensions/. Add a manifest to get started.")
                  : t("extensions.no_search_results", "Adjust your search query or refresh the catalog.")}
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
              {filteredExtensions.map((ext) => (
                <ExtensionCard
                  key={ext.id}
                  extension={ext}
                  onAction={handleAction}
                  busy={busyId === ext.id}
                />
              ))}
            </div>
          )}
        </div>
      </section>

      {/* Modals */}
      {activeUninstall && (
        <UninstallModal
          extension={activeUninstall}
          onClose={() => setActiveUninstall(null)}
          onConfirm={confirmUninstall}
          loading={busyId === activeUninstall.id}
        />
      )}

      {activeLogs && (
        <LogsModal
          extensionId={activeLogs.id}
          extensionName={activeLogs.name}
          onClose={() => setActiveLogs(null)}
        />
      )}

      {activeSettings && (
        <SettingsModal
          extension={activeSettings}
          onClose={() => setActiveSettings(null)}
          onSave={saveSettings}
          loading={busyId === activeSettings.id}
        />
      )}

      {activeSecrets && (
        <SecretsModal
          extension={activeSecrets}
          onClose={() => setActiveSecrets(null)}
          onRotate={rotateSecret}
          loadingSecret={busyId === activeSecrets.id ? "rotating" : null}
        />
      )}
    </>
  );
}
