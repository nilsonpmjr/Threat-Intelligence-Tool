import { useEffect, useMemo, useState, useCallback } from "react";
import {
  Plus,
  Network,
  Fingerprint,
  RefreshCw,
  Share2,
  Settings as SettingsIcon,
  ChevronLeft,
  ChevronRight,
  Blocks,
  ShieldAlert,
  Eye,
  ToggleLeft,
  Shield,
  Terminal,
  Play,
  Square,
  RotateCcw,
  ScrollText,
  KeyRound,
  Trash2,
  Loader2,
} from "lucide-react";
import API_URL from "../config";
import { PageHeader, PageToolbar, PageToolbarGroup } from "../components/page/PageChrome";
import { RowActionsMenu, RowPrimaryAction, type RowActionItem } from "../components/RowActions";
import { useLanguage } from "../context/LanguageContext";
import {
  listExtensions,
  installExtension,
  startExtension,
  stopExtension,
  restartExtension,
  updateExtensionSettings,
  rotateExtensionSecret,
  uninstallExtension,
  type ExtensionManifest,
  type ExtensionStatus,
} from "./extensions/lib/api";
import { pollExtensionStatus } from "./extensions/lib/poll";
import LogsModal from "./extensions/modals/LogsModal";
import SettingsModal from "./extensions/modals/SettingsModal";
import UninstallModal from "./extensions/modals/UninstallModal";
import SecretsModal from "./extensions/modals/SecretsModal";

// ── Legacy types ─────────────────────────────────────────────────────

type ExtensionItem = {
  id?: string;
  key?: string;
  name?: string;
  slug?: string;
  status?: string;
  kind?: string;
  searchRootScope?: string;
  premiumFeatureType?: string;
  providerScope?: string[];
  requiredSecrets?: string[];
  executionProfile?: string;
  version?: string;
  description?: string;
  healthScore?: number;
  runtimeOverhead?: string;
  installState?: string;
  updateAvailable?: boolean;
  operationalState?: {
    enabled?: boolean;
    hidden?: boolean;
    last_action?: string;
    last_action_at?: string;
    installed_at?: string;
    last_updated_at?: string;
  };
};

type ExtensionsPayload = {
  items: ExtensionItem[];
  core_version: string;
  search_roots: Array<{
    scope: string;
    label: string;
    repository_visibility: string;
  }>;
};

type FilterKey = "all" | "active" | "disabled" | "attention";

const PAGE_SIZE = 8;

// ── Legacy helpers ────────────────────────────────────────────────────

function normalizeStatus(value?: string) {
  return String(value || "unknown").toLowerCase();
}

function isEnabled(item: ExtensionItem) {
  return normalizeStatus(item.status) === "enabled";
}

function needsAttention(item: ExtensionItem) {
  const status = normalizeStatus(item.status);
  const version = String(item.version || "").toLowerCase();
  return (
    status.includes("update") ||
    status.includes("deprecated") ||
    status.includes("degraded") ||
    version.includes("rc") ||
    version.includes("beta") ||
    version.includes("depr")
  );
}

function statusMeta(item: ExtensionItem) {
  const status = normalizeStatus(item.status);
  if (isEnabled(item)) return { label: "ACTIVE", rowClass: "bg-primary", badgeClass: "badge-primary" };
  if (needsAttention(item)) return { label: "UPDATE", rowClass: "bg-error", badgeClass: "badge-error" };
  if (status === "disabled") return { label: "DISABLED", rowClass: "bg-outline", badgeClass: "badge-neutral" };
  return { label: status.toUpperCase() || "UNKNOWN", rowClass: "bg-surface-variant", badgeClass: "badge-neutral" };
}

function iconForExtension(item: ExtensionItem) {
  const slug = `${item.slug || ""} ${item.name || ""}`.toLowerCase();
  if (slug.includes("okta") || slug.includes("auth")) return Fingerprint;
  if (slug.includes("sync") || slug.includes("guardduty") || slug.includes("crowd")) return Share2;
  if (slug.includes("connector") || slug.includes("core")) return Network;
  return SettingsIcon;
}

function humanizeKind(item: ExtensionItem) {
  if (item.premiumFeatureType) return `Feature / ${item.premiumFeatureType}`;
  if (item.kind) return item.kind.replace(/_/g, " ");
  return "Integration";
}

function displayName(item: ExtensionItem) {
  return item.name || item.slug || item.id || "Unnamed Extension";
}

// ── Orchestrated helpers ──────────────────────────────────────────────

const ORCH_STATUS_META: Record<
  ExtensionStatus,
  { label: string; rowClass: string; badgeClass: string }
> = {
  installed_healthy:   { label: "ACTIVE",        rowClass: "bg-primary",       badgeClass: "badge-primary"  },
  installed_unhealthy: { label: "UNHEALTHY",      rowClass: "bg-error",         badgeClass: "badge-error"    },
  stopped:             { label: "STOPPED",        rowClass: "bg-outline",       badgeClass: "badge-neutral"  },
  not_installed:       { label: "NOT INSTALLED",  rowClass: "bg-surface-variant", badgeClass: "badge-neutral" },
  installing:          { label: "INSTALLING…",    rowClass: "bg-amber-500",     badgeClass: "badge-warning"  },
  uninstalling:        { label: "UNINSTALLING…",  rowClass: "bg-amber-500",     badgeClass: "badge-warning"  },
  installing_failed:   { label: "FAILED",         rowClass: "bg-error",         badgeClass: "badge-error"    },
};

function orchIsActive(ext: ExtensionManifest) {
  return ext.status === "installed_healthy";
}

function orchIsDisabled(ext: ExtensionManifest) {
  return ext.status === "stopped";
}

function orchNeedsAttention(ext: ExtensionManifest) {
  return ext.status === "installed_unhealthy" || ext.status === "installing_failed";
}

// ── Component ─────────────────────────────────────────────────────────

export default function ExtensionsCatalog() {
  const { t } = useLanguage();

  // Legacy state
  const [payload, setPayload] = useState<ExtensionsPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [filter, setFilter] = useState<FilterKey>("all");
  const [page, setPage] = useState(1);
  const [selectedId, setSelectedId] = useState("");
  const [busy, setBusy] = useState("");

  // Orchestrated state
  const [orchExtensions, setOrchExtensions] = useState<ExtensionManifest[]>([]);
  const [orchLoading, setOrchLoading] = useState(true);
  const [busyOrchId, setBusyOrchId] = useState<string | null>(null);
  const [activeUninstall, setActiveUninstall] = useState<ExtensionManifest | null>(null);
  const [activeLogs, setActiveLogs] = useState<ExtensionManifest | null>(null);
  const [activeSettings, setActiveSettings] = useState<ExtensionManifest | null>(null);
  const [activeSecrets, setActiveSecrets] = useState<ExtensionManifest | null>(null);

  // ── Data loading ────────────────────────────────────────────────────

  async function loadCatalog(refresh = false) {
    setLoading(true);
    setError("");
    try {
      const suffix = refresh ? "?refresh=true" : "";
      const response = await fetch(`${API_URL}/api/admin/extensions${suffix}`, { credentials: "include" });
      if (!response.ok) throw new Error("extensions_load_failed");
      const data = (await response.json()) as ExtensionsPayload;
      setPayload(data);
      const first = data.items?.[0];
      if (first) setSelectedId((current) => current || (first.id || first.slug || first.name || ""));
    } catch {
      setError("Não foi possível carregar o catálogo de extensões.");
    } finally {
      setLoading(false);
    }
  }

  const loadOrch = useCallback(async (silent = false) => {
    if (!silent) setOrchLoading(true);
    try {
      const data = await listExtensions();
      setOrchExtensions(data);
    } catch {
      // silent — orch extensions are best-effort
    } finally {
      if (!silent) setOrchLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadCatalog();
    void loadOrch();
  }, [loadOrch]);

  // Polling for transitioning orchestrated extensions
  useEffect(() => {
    const transitionIds = orchExtensions
      .filter((e) => e.status === "installing" || e.status === "uninstalling")
      .map((e) => e.id);

    transitionIds.forEach((id) => {
      void pollExtensionStatus(
        id,
        (updated) => setOrchExtensions((prev) => prev.map((e) => (e.id === id ? updated : e))),
        () => { void loadOrch(true); },
        (err) => console.error(`Poll error for ${id}:`, err),
      );
    });
  }, [orchExtensions.length, loadOrch]);

  // ── Legacy actions ──────────────────────────────────────────────────

  async function runExtensionAction(
    item: ExtensionItem,
    action: "install" | "enable" | "disable" | "update" | "remove",
  ) {
    const extensionKey = item.key || item.id || item.slug || item.name;
    if (!extensionKey) return;
    setBusy(`${action}-${extensionKey}`);
    setError("");
    setNotice("");
    try {
      const method = action === "remove" ? "DELETE" : "POST";
      const response = await fetch(
        `${API_URL}/api/admin/extensions/${encodeURIComponent(extensionKey)}/${action === "remove" ? "" : action}`.replace(/\/$/, ""),
        { method, credentials: "include" },
      );
      if (!response.ok) throw new Error("extension_action_failed");
      const messages: Record<typeof action, string> = {
        install: `${displayName(item)} adicionada ao catálogo operacional.`,
        enable: `${displayName(item)} ativada no catálogo operacional.`,
        disable: `${displayName(item)} desativada no catálogo operacional.`,
        update: `${displayName(item)} revisada e catálogo atualizado.`,
        remove: `${displayName(item)} removida do catálogo operacional.`,
      };
      setNotice(messages[action]);
      await loadCatalog(true);
    } catch {
      setError("Falha ao executar a ação operacional da extensão.");
    } finally {
      setBusy("");
    }
  }

  // ── Orchestrated actions ────────────────────────────────────────────

  async function handleOrchAction(id: string, action: string) {
    const ext = orchExtensions.find((e) => e.id === id);
    if (!ext) return;
    try {
      setBusyOrchId(id);
      switch (action) {
        case "install":   await installExtension(id);   await loadOrch(true); break;
        case "start":     await startExtension(id);     await loadOrch(true); break;
        case "stop":      await stopExtension(id);      await loadOrch(true); break;
        case "restart":   await restartExtension(id);   await loadOrch(true); break;
        case "uninstall": setActiveUninstall(ext); break;
        case "logs":      setActiveLogs(ext);      break;
        case "settings":  setActiveSettings(ext);  break;
        case "secrets":   setActiveSecrets(ext);   break;
      }
    } catch (err) {
      console.error(`Orch action ${action} failed for ${id}:`, err);
    } finally {
      if (!["uninstall", "logs", "settings", "secrets"].includes(action)) {
        setBusyOrchId(null);
      }
    }
  }

  async function confirmUninstall(phrase: string, destroyVolumes: boolean) {
    if (!activeUninstall) return;
    try {
      setBusyOrchId(activeUninstall.id);
      await uninstallExtension(activeUninstall.id, phrase, destroyVolumes);
      setActiveUninstall(null);
      await loadOrch(true);
    } catch (err) {
      console.error("Uninstall failed:", err);
    } finally {
      setBusyOrchId(null);
    }
  }

  async function saveSettings(settings: Record<string, any>) {
    if (!activeSettings) return;
    try {
      setBusyOrchId(activeSettings.id);
      await updateExtensionSettings(activeSettings.id, settings);
      setActiveSettings(null);
      await loadOrch(true);
    } catch (err) {
      console.error("Settings update failed:", err);
    } finally {
      setBusyOrchId(null);
    }
  }

  async function rotateSecret(secretName: string) {
    if (!activeSecrets) return;
    try {
      setBusyOrchId(activeSecrets.id);
      await rotateExtensionSecret(activeSecrets.id, secretName);
      const updated = await listExtensions();
      setOrchExtensions(updated);
      const newActive = updated.find((e) => e.id === activeSecrets.id);
      if (newActive) setActiveSecrets(newActive);
    } catch (err) {
      console.error("Secret rotation failed:", err);
    } finally {
      setBusyOrchId(null);
    }
  }

  // ── Derived / filter data ───────────────────────────────────────────

  const legacyRows = useMemo(() => payload?.items || [], [payload]);

  const counts = useMemo(() => ({
    all: legacyRows.length + orchExtensions.length,
    active:
      legacyRows.filter(isEnabled).length +
      orchExtensions.filter(orchIsActive).length,
    disabled:
      legacyRows.filter((i) => normalizeStatus(i.status) === "disabled").length +
      orchExtensions.filter(orchIsDisabled).length,
    attention:
      legacyRows.filter(needsAttention).length +
      orchExtensions.filter(orchNeedsAttention).length,
  }), [legacyRows, orchExtensions]);

  const filteredOrch = useMemo(() => {
    switch (filter) {
      case "active":    return orchExtensions.filter(orchIsActive);
      case "disabled":  return orchExtensions.filter(orchIsDisabled);
      case "attention": return orchExtensions.filter(orchNeedsAttention);
      default:          return orchExtensions;
    }
  }, [filter, orchExtensions]);

  const filteredLegacy = useMemo(() => {
    switch (filter) {
      case "active":    return legacyRows.filter(isEnabled);
      case "disabled":  return legacyRows.filter((i) => normalizeStatus(i.status) === "disabled");
      case "attention": return legacyRows.filter(needsAttention);
      default:          return legacyRows;
    }
  }, [filter, legacyRows]);

  const disabledRows = useMemo(() => legacyRows.filter((i) => normalizeStatus(i.status) === "disabled"), [legacyRows]);

  // Unified pagination over orch + legacy rows
  const allFilteredCount = filteredOrch.length + filteredLegacy.length;
  const totalPages = Math.max(1, Math.ceil(allFilteredCount / PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);

  // Paginate across both sources sequentially (orch first, then legacy)
  const startIdx = (currentPage - 1) * PAGE_SIZE;
  const endIdx = startIdx + PAGE_SIZE;
  const combined = [...filteredOrch.map((e) => ({ kind: "orch" as const, orch: e })),
                    ...filteredLegacy.map((i) => ({ kind: "legacy" as const, legacy: i }))];
  const pagedCombined = combined.slice(startIdx, endIdx);

  useEffect(() => { setPage(1); }, [filter]);

  const selectedExtension = useMemo(
    () => legacyRows.find((i) => (i.id || i.slug || i.name || "") === selectedId) || legacyRows[0] || null,
    [legacyRows, selectedId],
  );

  const activeExtensions = useMemo(() => legacyRows.filter(isEnabled).slice(0, 5), [legacyRows]);
  const configuredSecrets = useMemo(
    () => legacyRows.reduce((sum, i) => sum + (i.requiredSecrets?.length || 0), 0),
    [legacyRows],
  );

  async function refreshAll(force = false) {
    await Promise.all([loadCatalog(force), loadOrch()]);
  }

  // ── Render ───────────────────────────────────────────────────────────

  return (
    <div className="page-frame">
      <PageHeader
        title={t("settingsPages.extensionsTitle", "Extensions Catalog")}
        description={t("settingsPages.extensionsSubtitle", "Orquestre módulos, conectores e recursos adicionais em um catálogo administrativo consistente.")}
      />

      <PageToolbar label={t("settingsPages.extensionsActions", "Catalog actions")}>
        <PageToolbarGroup className="ml-auto">
          <button onClick={() => void refreshAll(true)} className="btn btn-outline">
            <span className="inline-flex items-center gap-2">
              <RefreshCw className={`w-4 h-4 ${(loading || orchLoading) ? "animate-spin" : ""}`} />
              {t("admin.refresh", "Refresh")}
            </span>
          </button>
          <button
            onClick={() => {
              setFilter("disabled");
              setPage(1);
              if (disabledRows[0]) {
                setSelectedId(disabledRows[0].id || disabledRows[0].slug || disabledRows[0].name || "");
                setNotice("Fila de adoção carregada com as extensões desabilitadas descobertas pelo registry.");
              } else {
                setNotice("Nenhuma extensão desabilitada disponível para adoção no momento.");
              }
            }}
            className="btn btn-primary uppercase tracking-widest flex items-center gap-2"
          >
            <Plus className="w-4 h-4" />
            {t("settingsPages.reviewDisabled", "Review Disabled")}
          </button>
        </PageToolbarGroup>
      </PageToolbar>

      {(error || notice) && (
        <div className="space-y-3">
          {error && <div className="rounded-sm bg-error/10 px-4 py-3 text-sm text-error">{error}</div>}
          {notice && <div className="rounded-sm bg-primary/10 px-4 py-3 text-sm text-primary">{notice}</div>}
        </div>
      )}

      {/* Filter tabs */}
      <div className="bg-surface-container-low p-3 mb-2 flex flex-wrap items-center justify-between gap-4">
        <div className="nav-pills">
          {(["all", "active", "disabled", "attention"] as FilterKey[]).map((key) => (
            <button
              key={key}
              onClick={() => setFilter(key)}
              className={`${filter === key ? "nav-pill-item nav-pill-item-active" : "nav-pill-item nav-pill-item-inactive"} flex items-center gap-2`}
            >
              {key === "all" && "All"}
              {key === "active" && "Active"}
              {key === "disabled" && "Disabled"}
              {key === "attention" && (
                <>Update Available{counts.attention > 0 && <span className="w-1.5 h-1.5 bg-error rounded-full" />}</>
              )}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2 text-on-surface-variant">
          <span className="text-[11px] font-bold uppercase tracking-widest">Showing:</span>
          <span className="text-xs font-medium text-on-surface">{allFilteredCount} Extensions</span>
        </div>
      </div>

      <div className="page-with-side-rail">
        <div className="page-main-pane space-y-6">
          {/* Stats */}
          <section className="surface-section overflow-hidden">
            <div className="surface-section-header">
              <div>
                <h3 className="surface-section-title">Catalog Overview</h3>
                <p className="mt-1 text-[10px] font-medium uppercase tracking-widest text-on-surface-variant">
                  Active coverage and extension footprint
                </p>
              </div>
            </div>
            <div className="grid gap-4 p-6 md:grid-cols-3">
              <div className="rounded-sm border border-outline-variant/15 bg-surface-container-low p-4">
                <div className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Active Extensions</div>
                <div className="mt-2 text-2xl font-black text-on-surface">{counts.active}</div>
                <div className="mt-1 text-xs text-on-surface-variant">of {counts.all} catalog entries</div>
              </div>
              <div className="rounded-sm border border-outline-variant/15 bg-surface-container-low p-4">
                <div className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Core Version</div>
                <div className="mt-2 text-2xl font-black text-on-surface">{payload?.core_version || "—"}</div>
                <div className="mt-1 text-xs text-on-surface-variant">{payload?.search_roots?.length || 0} search root(s)</div>
              </div>
              <div className="rounded-sm border border-outline-variant/15 bg-surface-container-low p-4">
                <div className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Platform Extensions</div>
                <div className="mt-2 text-2xl font-black text-on-surface">{orchExtensions.length}</div>
                <div className="mt-1 text-xs text-on-surface-variant">{orchExtensions.filter(orchIsActive).length} healthy</div>
              </div>
            </div>
          </section>

          {/* Unified table */}
          <div className="card p-0 overflow-hidden">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-surface-container-high">
                  <th className="px-6 py-3 text-[11px] font-bold text-on-surface-variant uppercase tracking-widest">Extension Name</th>
                  <th className="px-6 py-3 text-[11px] font-bold text-on-surface-variant uppercase tracking-widest text-center">Version</th>
                  <th className="px-6 py-3 text-[11px] font-bold text-on-surface-variant uppercase tracking-widest">Author / Kind</th>
                  <th className="px-6 py-3 text-[11px] font-bold text-on-surface-variant uppercase tracking-widest">Status</th>
                  <th className="px-6 py-3 text-[11px] font-bold text-on-surface-variant uppercase tracking-widest text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-container">
                {(loading && orchLoading) ? (
                  <tr>
                    <td colSpan={5} className="px-6 py-8 text-sm text-on-surface-variant">
                      Carregando catálogo de extensões...
                    </td>
                  </tr>
                ) : pagedCombined.length > 0 ? (
                  pagedCombined.map((row, idx) => {
                    if (row.kind === "orch") {
                      return (
                        <OrchExtensionRow
                          key={`orch-${row.orch.id}`}
                          ext={row.orch}
                          busy={busyOrchId === row.orch.id}
                          onAction={handleOrchAction}
                        />
                      );
                    }
                    const item = row.legacy;
                    const Icon = iconForExtension(item);
                    const meta = statusMeta(item);
                    return (
                      <ExtensionRow
                        key={item.id || item.slug || item.name || String(idx)}
                        icon={Icon}
                        name={displayName(item)}
                        id={item.id || item.slug || "catalog-item"}
                        version={item.version || "—"}
                        versionColor={needsAttention(item) ? "bg-error/10 text-error" : "bg-surface-container"}
                        author={humanizeKind(item)}
                        status={meta.label}
                        statusColor={meta.rowClass}
                        onInspect={() => setSelectedId(item.id || item.slug || item.name || "")}
                        menuItems={buildExtensionActions({
                          item,
                          onInspect: () => setSelectedId(item.id || item.slug || item.name || ""),
                          onInstall: () => void runExtensionAction(item, "install"),
                          onEnable: () => void runExtensionAction(item, "enable"),
                          onDisable: () => void runExtensionAction(item, "disable"),
                          onUpdate: () => void runExtensionAction(item, "update"),
                          onRemove: () => void runExtensionAction(item, "remove"),
                          notify: setNotice,
                        })}
                      />
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan={5} className="px-6 py-8 text-sm text-on-surface-variant">
                      Nenhuma extensão encontrada para o filtro atual.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>

            {/* Pagination */}
            <div className="bg-surface-container-low px-6 py-3 border-t border-surface-container flex items-center justify-between">
              <span className="text-[11px] font-bold text-on-surface-variant uppercase tracking-widest">
                Page {currentPage} of {totalPages}
              </span>
              <div className="flex gap-1">
                <button
                  disabled={currentPage === 1}
                  onClick={() => setPage((v) => Math.max(1, v - 1))}
                  className="p-1 text-outline hover:text-on-surface disabled:opacity-40"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>
                {Array.from({ length: totalPages }, (_, i) => i + 1)
                  .slice(0, 5)
                  .map((v) => (
                    <button
                      key={v}
                      onClick={() => setPage(v)}
                      className={
                        v === currentPage
                          ? "p-1 text-on-surface font-bold text-xs underline underline-offset-4 px-2"
                          : "p-1 text-on-surface-variant font-medium text-xs hover:text-on-surface px-2"
                      }
                    >
                      {v}
                    </button>
                  ))}
                <button
                  disabled={currentPage === totalPages}
                  onClick={() => setPage((v) => Math.min(totalPages, v + 1))}
                  className="p-1 text-outline hover:text-on-surface disabled:opacity-40"
                >
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Side rail */}
        <aside className="page-side-rail-right">
          {selectedExtension && (
            <section className="surface-section overflow-hidden">
              <div className="surface-section-header">
                <div>
                  <h3 className="surface-section-title">Selected Extension</h3>
                  <p className="mt-1 text-[10px] font-medium uppercase tracking-widest text-on-surface-variant">
                    Detail context for the selected catalog row
                  </p>
                </div>
              </div>
              <div className="space-y-4 p-6">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 bg-surface-container-high flex items-center justify-center rounded-sm">
                    {(() => { const Icon = iconForExtension(selectedExtension); return <Icon className="w-5 h-5 text-primary" />; })()}
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-on-surface">{displayName(selectedExtension)}</h3>
                    <p className="text-[10px] text-on-surface-variant uppercase tracking-widest">
                      {(selectedExtension.id || selectedExtension.slug || "catalog extension").toUpperCase()}
                    </p>
                  </div>
                </div>
                <p className="text-sm text-on-surface-variant">
                  {selectedExtension.description || "Sem descrição detalhada no catálogo atual."}
                </p>
                <MetricRow label="Version" value={selectedExtension.version || "—"} />
                <MetricRow label="Kind" value={humanizeKind(selectedExtension)} />
                <MetricRow label="Execution" value={selectedExtension.executionProfile || "default"} />
                <MetricRow label="Health Score" value={`${selectedExtension.healthScore ?? 0}/100`} />
                <MetricRow label="Operational Load" value={String(selectedExtension.runtimeOverhead || "low")} />
                <MetricRow label="Providers" value={(selectedExtension.providerScope || []).join(", ") || "—"} />
                <MetricRow label="Secrets" value={String(selectedExtension.requiredSecrets?.length || 0)} />
                <MetricRow label="Lifecycle" value={selectedExtension.installState || "detected"} />
                <MetricRow label="Last Action" value={selectedExtension.operationalState?.last_action || "—"} />
                <div className="grid grid-cols-1 gap-2 pt-2">
                  <button
                    onClick={() => void runExtensionAction(selectedExtension, isEnabled(selectedExtension) ? "disable" : "enable")}
                    className="btn btn-outline"
                  >
                    {busy === `${isEnabled(selectedExtension) ? "disable" : "enable"}-${selectedExtension.key || selectedExtension.id || selectedExtension.slug || selectedExtension.name}`
                      ? "Applying..."
                      : isEnabled(selectedExtension) ? "Disable" : "Enable"}
                  </button>
                  <button
                    onClick={() => void runExtensionAction(selectedExtension, "update")}
                    className="btn btn-primary"
                  >
                    {busy === `update-${selectedExtension.key || selectedExtension.id || selectedExtension.slug || selectedExtension.name}`
                      ? "Refreshing..."
                      : "Refresh / Update"}
                  </button>
                </div>
              </div>
            </section>
          )}

          <section className="surface-section overflow-hidden">
            <div className="surface-section-header">
              <div>
                <h3 className="surface-section-title">Active Extensions</h3>
                <p className="mt-1 text-[10px] font-medium uppercase tracking-widest text-on-surface-variant">
                  Quick navigation to enabled items
                </p>
              </div>
            </div>
            <div className="p-6">
              <ul className="space-y-4">
                {activeExtensions.length > 0 ? (
                  activeExtensions.map((item) => {
                    const meta = statusMeta(item);
                    return (
                      <ActiveExtItem
                        key={item.id || item.slug || item.name}
                        name={displayName(item)}
                        type={humanizeKind(item)}
                        status={meta.label}
                        statusColor={meta.badgeClass}
                        onClick={() => setSelectedId(item.id || item.slug || item.name || "")}
                      />
                    );
                  })
                ) : (
                  <li className="text-sm text-on-surface-variant">Nenhuma extensão ativa retornada pelo backend.</li>
                )}
              </ul>
              <div className="mt-6 rounded-sm bg-surface-container-low p-3 text-[11px] text-on-surface-variant">
                Performance telemetry per extension is not exposed by the backend yet.
              </div>
            </div>
          </section>
        </aside>
      </div>

      {/* Orchestrated modals */}
      {activeUninstall && (
        <UninstallModal
          extension={activeUninstall}
          onClose={() => setActiveUninstall(null)}
          onConfirm={confirmUninstall}
          loading={busyOrchId === activeUninstall.id}
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
          loading={busyOrchId === activeSettings.id}
        />
      )}
      {activeSecrets && (
        <SecretsModal
          extension={activeSecrets}
          onClose={() => setActiveSecrets(null)}
          onRotate={rotateSecret}
          loadingSecret={busyOrchId === activeSecrets.id ? "rotating" : null}
        />
      )}
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────

function OrchExtensionRow({
  ext,
  busy,
  onAction,
}: {
  ext: ExtensionManifest;
  busy: boolean;
  onAction: (id: string, action: string) => void;
}) {
  const meta = ORCH_STATUS_META[ext.status];
  const isTransition = ext.status === "installing" || ext.status === "uninstalling";

  // Primary action button
  let primaryLabel = "";
  let primaryIcon = <Play className="h-3.5 w-3.5" />;
  let primaryAction = "";

  if (ext.status === "not_installed" || ext.status === "installing_failed") {
    primaryLabel = "Install";
    primaryIcon = <Plus className="h-3.5 w-3.5" />;
    primaryAction = "install";
  } else if (ext.status === "stopped") {
    primaryLabel = "Start";
    primaryIcon = <Play className="h-3.5 w-3.5" />;
    primaryAction = "start";
  } else if (ext.status === "installed_healthy" || ext.status === "installed_unhealthy") {
    primaryLabel = "Logs";
    primaryIcon = <ScrollText className="h-3.5 w-3.5" />;
    primaryAction = "logs";
  }

  // Menu items
  const menuItems: RowActionItem[] = [];

  if (ext.status === "installed_healthy" || ext.status === "installed_unhealthy") {
    menuItems.push(
      { key: "logs", label: "Logs", icon: <ScrollText className="h-3.5 w-3.5" />, onSelect: () => onAction(ext.id, "logs") },
      { key: "restart", label: "Restart", icon: <RotateCcw className="h-3.5 w-3.5" />, onSelect: () => onAction(ext.id, "restart") },
    );
    if (ext.status === "installed_healthy") {
      menuItems.push({ key: "stop", label: "Stop", icon: <Square className="h-3.5 w-3.5" />, onSelect: () => onAction(ext.id, "stop") });
    }
  }

  if (ext.settings_schema?.length > 0) {
    menuItems.push({ key: "settings", label: "Settings", icon: <SettingsIcon className="h-3.5 w-3.5" />, onSelect: () => onAction(ext.id, "settings"), dividerBefore: menuItems.length > 0 });
  }

  if (ext.secrets && ext.secrets.length > 0) {
    menuItems.push({ key: "secrets", label: "Secrets", icon: <KeyRound className="h-3.5 w-3.5" />, onSelect: () => onAction(ext.id, "secrets") });
  }

  if (ext.status !== "not_installed" && ext.status !== "installing") {
    menuItems.push({
      key: "uninstall", label: "Uninstall", icon: <Trash2 className="h-3.5 w-3.5" />,
      onSelect: () => onAction(ext.id, "uninstall"),
      tone: "danger" as const,
      dividerBefore: true,
    });
  }

  return (
    <tr className="hover:bg-surface-container-low transition-colors">
      <td className="px-6 py-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 bg-primary/10 flex items-center justify-center rounded-sm">
            <Terminal className="w-4 h-4 text-primary" />
          </div>
          <div>
            <p className="text-sm font-bold text-on-surface flex items-center gap-2">
              {ext.name}
              <span className="text-[9px] font-bold uppercase tracking-widest text-primary border border-primary/30 rounded px-1 py-0.5">
                Platform
              </span>
            </p>
            <p className="text-[11px] font-mono text-on-surface-variant">{ext.id}</p>
          </div>
        </div>
      </td>
      <td className="px-6 py-4 text-center">
        <span className="inline-flex rounded-sm px-2 py-1 text-[11px] font-bold bg-surface-container">
          {ext.version}
        </span>
      </td>
      <td className="px-6 py-4">
        <span className="text-sm text-on-surface">Platform Extension</span>
      </td>
      <td className="px-6 py-4">
        <div className="space-y-1">
          <span className={`inline-flex items-center gap-2 rounded-sm px-2 py-1 text-[10px] font-bold uppercase tracking-widest text-white ${meta.rowClass}`}>
            {isTransition && <Loader2 className="w-3 h-3 animate-spin" />}
            {meta.label}
          </span>
          {ext.last_error && (ext.status === "installed_unhealthy" || ext.status === "installing_failed") && (
            <p className="text-[10px] text-error max-w-[200px] truncate" title={ext.last_error}>
              {ext.last_error}
            </p>
          )}
        </div>
      </td>
      <td className="px-6 py-4">
        <div className="flex justify-end gap-2">
          {isTransition ? (
            <span className="text-xs text-on-surface-variant flex items-center gap-1">
              <Loader2 className="w-3 h-3 animate-spin" /> Working…
            </span>
          ) : primaryAction ? (
            <>
              <RowPrimaryAction
                label={primaryLabel}
                icon={primaryIcon}
                onClick={() => onAction(ext.id, primaryAction)}
                disabled={busy}
              />
              {menuItems.length > 0 && <RowActionsMenu items={menuItems} />}
            </>
          ) : null}
        </div>
      </td>
    </tr>
  );
}

function MetricRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between items-center text-xs">
      <span className="text-on-surface-variant">{label}</span>
      <span className="font-mono font-bold text-on-surface">{value}</span>
    </div>
  );
}

function ActiveExtItem({
  name,
  type,
  status,
  statusColor,
  onClick,
}: {
  key?: string;
  name: string;
  type: string;
  status: string;
  statusColor: string;
  onClick: () => void;
}) {
  const accentClass = status === "UPDATE" ? "card-accent-error" : "card-accent-primary";
  return (
    <li
      onClick={onClick}
      className={`flex items-center justify-between p-3 bg-surface hover:bg-surface-container-low transition-all cursor-pointer card-accent-left ${accentClass}`}
    >
      <div>
        <p className="text-xs font-bold text-on-surface">{name}</p>
        <p className="text-[10px] text-on-surface-variant">{type}</p>
      </div>
      <span className={`badge ${statusColor}`}>{status}</span>
    </li>
  );
}

function ExtensionRow({
  icon: Icon,
  name,
  id,
  version,
  versionColor = "bg-surface-container",
  author,
  status,
  statusColor,
  onInspect,
  menuItems,
}: {
  key?: string;
  icon: typeof Blocks;
  name: string;
  id: string;
  version: string;
  versionColor?: string;
  author: string;
  status: string;
  statusColor: string;
  onInspect: () => void;
  menuItems: RowActionItem[];
}) {
  return (
    <tr className="hover:bg-surface-container-low transition-colors">
      <td className="px-6 py-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 bg-surface-container flex items-center justify-center rounded-sm">
            <Icon className="w-4 h-4 text-primary" />
          </div>
          <div>
            <p className="text-sm font-bold text-on-surface">{name}</p>
            <p className="text-[11px] font-mono text-on-surface-variant">{id}</p>
          </div>
        </div>
      </td>
      <td className="px-6 py-4 text-center">
        <span className={`inline-flex rounded-sm px-2 py-1 text-[11px] font-bold ${versionColor}`}>{version}</span>
      </td>
      <td className="px-6 py-4">
        <span className="text-sm text-on-surface">{author}</span>
      </td>
      <td className="px-6 py-4">
        <span className={`inline-flex items-center gap-2 rounded-sm px-2 py-1 text-[10px] font-bold uppercase tracking-widest text-white ${statusColor}`}>
          {status === "UPDATE" && <ShieldAlert className="w-3 h-3" />}
          {status}
        </span>
      </td>
      <td className="px-6 py-4">
        <div className="flex justify-end gap-2">
          <RowPrimaryAction label="Inspect" icon={<Eye className="h-3.5 w-3.5" />} onClick={onInspect} />
          <RowActionsMenu items={menuItems} />
        </div>
      </td>
    </tr>
  );
}

function buildExtensionActions({
  item,
  onInspect,
  onInstall,
  onEnable,
  onDisable,
  onUpdate,
  onRemove,
  notify,
}: {
  item: ExtensionItem;
  onInspect: () => void;
  onInstall: () => void;
  onEnable: () => void;
  onDisable: () => void;
  onUpdate: () => void;
  onRemove: () => void;
  notify: (value: string) => void;
}): RowActionItem[] {
  const enabled = isEnabled(item);
  const stale = needsAttention(item);
  const installed = item.installState === "installed";

  return [
    { key: "inspect", label: "Open details", icon: <Eye className="h-3.5 w-3.5" />, onSelect: onInspect },
    {
      key: "requirements",
      label: "Review secret requirements",
      icon: <Shield className="h-3.5 w-3.5" />,
      onSelect: () => notify(`${displayName(item)} exige ${item.requiredSecrets?.length || 0} secret(s) na configuração atual.`),
    },
    {
      key: installed ? "runtime-toggle" : "install",
      label: installed ? (enabled ? "Disable" : "Enable") : "Install",
      icon: <ToggleLeft className="h-3.5 w-3.5" />,
      onSelect: installed ? (enabled ? onDisable : onEnable) : onInstall,
      dividerBefore: stale,
    },
    ...(stale ? [{ key: "advisory", label: "Refresh catalog entry", icon: <ShieldAlert className="h-3.5 w-3.5" />, onSelect: onUpdate } satisfies RowActionItem] : []),
    ...(item.searchRootScope !== "core"
      ? [{ key: "remove", label: "Remove from catalog", icon: <Shield className="h-3.5 w-3.5" />, onSelect: onRemove, tone: "danger" as const, dividerBefore: true } satisfies RowActionItem]
      : []),
  ];
}
