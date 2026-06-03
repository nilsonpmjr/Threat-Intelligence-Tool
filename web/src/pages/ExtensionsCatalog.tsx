import { useEffect, useMemo, useState } from "react";
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
  Search,
  Eye,
  ToggleLeft,
  Shield,
} from "lucide-react";
import API_URL from "../config";
import { PageHeader, PageToolbar, PageToolbarGroup } from "../components/page/PageChrome";
import { RowActionsMenu, RowPrimaryAction, type RowActionItem } from "../components/RowActions";
import { useLanguage } from "../context/LanguageContext";
import OrchestratedExtensions from "./extensions/Extensions";

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
  if (isEnabled(item)) {
    return {
      label: "ACTIVE",
      rowClass: "bg-primary",
      badgeClass: "badge-primary",
    };
  }
  if (needsAttention(item)) {
    return {
      label: "UPDATE",
      rowClass: "bg-error",
      badgeClass: "badge-error",
    };
  }
  if (status === "disabled") {
    return {
      label: "DISABLED",
      rowClass: "bg-outline",
      badgeClass: "badge-neutral",
    };
  }
  return {
    label: status.toUpperCase() || "UNKNOWN",
    rowClass: "bg-surface-variant",
    badgeClass: "badge-neutral",
  };
}

function iconForExtension(item: ExtensionItem) {
  const slug = `${item.slug || ""} ${item.name || ""}`.toLowerCase();
  if (slug.includes("okta") || slug.includes("auth")) return Fingerprint;
  if (slug.includes("sync") || slug.includes("guardduty") || slug.includes("crowd")) return Share2;
  if (slug.includes("connector") || slug.includes("core")) return Network;
  return SettingsIcon;
}

function humanizeKind(item: ExtensionItem) {
  if (item.premiumFeatureType) {
    return `Feature / ${item.premiumFeatureType}`;
  }
  if (item.kind) {
    return item.kind.replace(/_/g, " ");
  }
  return "Integration";
}

function displayName(item: ExtensionItem) {
  return item.name || item.slug || item.id || "Unnamed Extension";
}

export default function ExtensionsCatalog() {
  const { t } = useLanguage();
  const [payload, setPayload] = useState<ExtensionsPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [filter, setFilter] = useState<FilterKey>("all");
  const [page, setPage] = useState(1);
  const [selectedId, setSelectedId] = useState("");
  const [busy, setBusy] = useState("");

  async function loadCatalog(refresh = false) {
    setLoading(true);
    setError("");

    try {
      const suffix = refresh ? "?refresh=true" : "";
      const response = await fetch(`${API_URL}/api/admin/extensions${suffix}`, {
        credentials: "include",
      });
      if (!response.ok) {
        throw new Error("extensions_load_failed");
      }
      const data = (await response.json()) as ExtensionsPayload;
      setPayload(data);
      const first = data.items?.[0];
      if (first) {
        setSelectedId((current) => current || (first.id || first.slug || first.name || ""));
      }
    } catch {
      setError("Não foi possível carregar o catálogo de extensões.");
    } finally {
      setLoading(false);
    }
  }

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
      const response = await fetch(`${API_URL}/api/admin/extensions/${encodeURIComponent(extensionKey)}/${action === "remove" ? "" : action}`.replace(/\/$/, ""), {
        method,
        credentials: "include",
      });
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

  useEffect(() => {
    void loadCatalog();
  }, []);

  const rows = useMemo(() => payload?.items || [], [payload]);
  const counts = useMemo(
    () => ({
      all: rows.length,
      active: rows.filter(isEnabled).length,
      disabled: rows.filter((item) => normalizeStatus(item.status) === "disabled").length,
      attention: rows.filter(needsAttention).length,
    }),
    [rows],
  );

  const filteredRows = useMemo(() => {
    switch (filter) {
      case "active":
        return rows.filter(isEnabled);
      case "disabled":
        return rows.filter((item) => normalizeStatus(item.status) === "disabled");
      case "attention":
        return rows.filter(needsAttention);
      default:
        return rows;
    }
  }, [filter, rows]);
  const disabledRows = useMemo(
    () => rows.filter((item) => normalizeStatus(item.status) === "disabled"),
    [rows],
  );

  const totalPages = Math.max(1, Math.ceil(filteredRows.length / PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const pagedRows = filteredRows.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  useEffect(() => {
    setPage(1);
  }, [filter]);

  const selectedExtension =
    rows.find((item) => (item.id || item.slug || item.name || "") === selectedId) ||
    pagedRows[0] ||
    rows[0] ||
    null;

  const activeExtensions = useMemo(() => rows.filter(isEnabled).slice(0, 5), [rows]);
  const premiumCount = useMemo(
    () => rows.filter((item) => item.kind === "premium_feature" || item.premiumFeatureType).length,
    [rows],
  );
  const configuredSecrets = useMemo(
    () =>
      rows.reduce((sum, item) => sum + (item.requiredSecrets?.length || 0), 0),
    [rows],
  );

  return (
    <div className="page-frame">
      <PageHeader
        title={t("settingsPages.extensionsTitle", "Extensions Catalog")}
        description={t("settingsPages.extensionsSubtitle", "Orquestre módulos, conectores e recursos adicionais em um catálogo administrativo consistente. O backend atual ainda expõe parte desse estado em modo leitura.")}
      />

      <PageToolbar label={t("settingsPages.extensionsActions", "Catalog actions")}>
        <PageToolbarGroup className="ml-auto">
          <button
            onClick={() => void loadCatalog(true)}
            className="btn btn-outline"
          >
            <span className="inline-flex items-center gap-2">
              <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
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
          {error && (
            <div className="rounded-sm bg-error/10 px-4 py-3 text-sm text-error">
              {error}
            </div>
          )}
          {notice && (
            <div className="rounded-sm bg-primary/10 px-4 py-3 text-sm text-primary">
              {notice}
            </div>
          )}
        </div>
      )}

      <div className="bg-surface-container-low p-3 mb-2 flex flex-wrap items-center justify-between gap-4">
        <div className="nav-pills">
          <button
            onClick={() => setFilter("all")}
            className={filter === "all" ? "nav-pill-item nav-pill-item-active" : "nav-pill-item nav-pill-item-inactive"}
          >
            All
          </button>
          <button
            onClick={() => setFilter("active")}
            className={filter === "active" ? "nav-pill-item nav-pill-item-active" : "nav-pill-item nav-pill-item-inactive"}
          >
            Active
          </button>
          <button
            onClick={() => setFilter("disabled")}
            className={filter === "disabled" ? "nav-pill-item nav-pill-item-active" : "nav-pill-item nav-pill-item-inactive"}
          >
            Disabled
          </button>
          <button
            onClick={() => setFilter("attention")}
            className={filter === "attention" ? "nav-pill-item nav-pill-item-active flex items-center gap-2" : "nav-pill-item nav-pill-item-inactive flex items-center gap-2"}
          >
            Update Available
            {counts.attention > 0 && <span className="w-1.5 h-1.5 bg-error rounded-full"></span>}
          </button>
        </div>
        <div className="flex items-center gap-2 text-on-surface-variant">
          <span className="text-[11px] font-bold uppercase tracking-widest">
            Showing:
          </span>
          <span className="text-xs font-medium text-on-surface">
            {filteredRows.length} Extensions
          </span>
        </div>
      </div>

      <div className="page-with-side-rail">
        <div className="page-main-pane space-y-6">
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
                <div className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Catalog Coverage</div>
                <div className="mt-2 text-2xl font-black text-on-surface">
                  {counts.all > 0 ? `${Math.round((counts.active / counts.all) * 100)}%` : "0%"}
                </div>
                <div className="mt-1 text-xs text-on-surface-variant">{configuredSecrets} required secret slot(s)</div>
              </div>
            </div>
          </section>

          <div className="card p-0 overflow-hidden">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-surface-container-high">
                  <th className="px-6 py-3 text-[11px] font-bold text-on-surface-variant uppercase tracking-widest">
                    Extension Name
                  </th>
                  <th className="px-6 py-3 text-[11px] font-bold text-on-surface-variant uppercase tracking-widest text-center">
                    Version
                  </th>
                  <th className="px-6 py-3 text-[11px] font-bold text-on-surface-variant uppercase tracking-widest">
                    Author / Kind
                  </th>
                  <th className="px-6 py-3 text-[11px] font-bold text-on-surface-variant uppercase tracking-widest">
                    Status
                  </th>
                  <th className="px-6 py-3 text-[11px] font-bold text-on-surface-variant uppercase tracking-widest text-right">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-container">
                {loading ? (
                  <tr>
                    <td colSpan={5} className="px-6 py-8 text-sm text-on-surface-variant">
                      Carregando catálogo de extensões...
                    </td>
                  </tr>
                ) : pagedRows.length > 0 ? (
                  pagedRows.map((item) => {
                    const Icon = iconForExtension(item);
                    const meta = statusMeta(item);
                    return (
                    <ExtensionRow
                        key={item.id || item.slug || item.name}
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
            <div className="bg-surface-container-low px-6 py-3 border-t border-surface-container flex items-center justify-between">
              <span className="text-[11px] font-bold text-on-surface-variant uppercase tracking-widest">
                Page {currentPage} of {totalPages}
              </span>
              <div className="flex gap-1">
                <button
                  disabled={currentPage === 1}
                  onClick={() => setPage((value) => Math.max(1, value - 1))}
                  className="p-1 text-outline hover:text-on-surface disabled:opacity-40"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>
                {Array.from({ length: totalPages }, (_, index) => index + 1).slice(0, 5).map((value) => (
                  <button
                    key={value}
                    onClick={() => setPage(value)}
                    className={
                      value === currentPage
                        ? "p-1 text-on-surface font-bold text-xs underline underline-offset-4 px-2"
                        : "p-1 text-on-surface-variant font-medium text-xs hover:text-on-surface px-2"
                    }
                  >
                    {value}
                  </button>
                ))}
                <button
                  disabled={currentPage === totalPages}
                  onClick={() => setPage((value) => Math.min(totalPages, value + 1))}
                  className="p-1 text-outline hover:text-on-surface disabled:opacity-40"
                >
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        </div>

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
                    {(() => {
                      const Icon = iconForExtension(selectedExtension);
                      return <Icon className="w-5 h-5 text-primary" />;
                    })()}
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
                    onClick={() =>
                      void runExtensionAction(
                        selectedExtension,
                        isEnabled(selectedExtension) ? "disable" : "enable",
                      )
                    }
                    className="btn btn-outline"
                  >
                    {busy === `${isEnabled(selectedExtension) ? "disable" : "enable"}-${selectedExtension.key || selectedExtension.id || selectedExtension.slug || selectedExtension.name}`
                      ? "Applying..."
                      : isEnabled(selectedExtension)
                        ? "Disable"
                        : "Enable"}
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
                  <li className="text-sm text-on-surface-variant">
                    Nenhuma extensão ativa retornada pelo backend.
                  </li>
                )}
              </ul>
              <div className="mt-6 rounded-sm bg-surface-container-low p-3 text-[11px] text-on-surface-variant">
                Performance telemetry per extension is not exposed by the backend yet. Use health score,
                runtime load, and lifecycle fields above for the current operational context.
              </div>
            </div>
          </section>
        </aside>
      </div>

      {/* Orchestrated Extensions (Phase 4) — /api/extensions contract */}
      <div className="mt-8">
        <OrchestratedExtensions />
      </div>
    </div>
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
        <span className={`inline-flex rounded-sm px-2 py-1 text-[11px] font-bold ${versionColor}`}>
          {version}
        </span>
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
    {
      key: "inspect",
      label: "Open details",
      icon: <Eye className="h-3.5 w-3.5" />,
      onSelect: onInspect,
    },
    {
      key: "requirements",
      label: "Review secret requirements",
      icon: <Shield className="h-3.5 w-3.5" />,
      onSelect: () =>
        notify(
          `${displayName(item)} exige ${item.requiredSecrets?.length || 0} secret(s) na configuração atual.`,
        ),
    },
    {
      key: installed ? "runtime-toggle" : "install",
      label: installed ? (enabled ? "Disable" : "Enable") : "Install",
      icon: <ToggleLeft className="h-3.5 w-3.5" />,
      onSelect: installed ? (enabled ? onDisable : onEnable) : onInstall,
      dividerBefore: stale,
    },
    ...(stale
      ? [
          {
            key: "advisory",
            label: "Refresh catalog entry",
            icon: <ShieldAlert className="h-3.5 w-3.5" />,
            onSelect: onUpdate,
          } satisfies RowActionItem,
        ]
      : []),
    ...(item.searchRootScope !== "core"
      ? [
          {
            key: "remove",
            label: "Remove from catalog",
            icon: <Shield className="h-3.5 w-3.5" />,
            onSelect: onRemove,
            tone: "danger",
            dividerBefore: true,
          } satisfies RowActionItem,
        ]
      : []),
  ];
}
