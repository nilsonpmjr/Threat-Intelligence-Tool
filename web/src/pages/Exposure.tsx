import { useEffect, useMemo, useState } from "react";
import { Activity, Globe, Plus, RefreshCw, Search, ShieldAlert, Siren, Layers3 } from "lucide-react";
import API_URL from "../config";
import { PageHeader, PageMetricPill, PageToolbar, PageToolbarGroup } from "../components/page/PageChrome";
import { useLanguage } from "../context/LanguageContext";

interface ExposureProvider {
  key: string;
  name: string;
  assetTypes: string[];
  providerScope: string[];
  recommendedSchedule?: string;
}

interface ExposureFinding {
  _id?: string;
  title: string;
  summary: string;
  kind: string;
  severity: string;
  timestamp?: string;
  external_ref?: string | null;
  incident_id?: string | null;
}

interface ExposureAsset {
  _id: string;
  asset_type: string;
  value: string;
  recurrence?: { mode?: string; last_status?: string; last_run_at?: string | null };
  finding_count: number;
  incident_count: number;
  recent_findings: ExposureFinding[];
  updated_at?: string;
}

interface ExposureAssetGroup {
  _id: string;
  name: string;
  assets: Array<{ monitored_asset_id: string; asset_type: string; value: string }>;
  updated_at?: string;
}

interface ExposureIncident {
  _id: string;
  title: string;
  summary: string;
  severity: string;
  status: string;
  updated_at?: string;
  related_assets?: Array<{ monitored_asset_id?: string; asset_type?: string; value?: string }>;
}

function formatTimestamp(value: string | null | undefined, locale: string) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(locale, {
    dateStyle: "short",
    timeStyle: "short",
  }).format(date);
}

function severityClasses(severity?: string) {
  if (severity === "critical" || severity === "high") {
    return "bg-error/10 text-error";
  }
  if (severity === "medium") {
    return "bg-warning/10 text-warning";
  }
  return "bg-primary/10 text-primary";
}

function severityLabel(severity: string | undefined, t: (key: string, fallback?: string) => string) {
  if (severity === "critical") return t("exposure.severityCritical", "critical");
  if (severity === "high") return t("exposure.severityHigh", "high");
  if (severity === "medium") return t("exposure.severityMedium", "medium");
  if (severity === "low") return t("exposure.severityLow", "low");
  return severity || t("exposure.unknownSeverity", "unknown");
}

function scheduleLabel(schedule: string | undefined, t: (key: string, fallback?: string) => string) {
  if (schedule === "manual") return t("exposure.scheduleManual", "manual");
  if (schedule === "daily") return t("exposure.scheduleDaily", "daily");
  if (schedule === "continuous") return t("exposure.scheduleContinuous", "continuous");
  return schedule || t("exposure.scheduleManual", "manual");
}

function incidentStatusLabel(status: string | undefined, t: (key: string, fallback?: string) => string) {
  if (status === "investigating") return t("exposure.statusInvestigating", "investigating");
  if (status === "resolved") return t("exposure.statusResolved", "resolved");
  if (status === "dismissed") return t("exposure.statusDismissed", "dismissed");
  if (status === "open") return t("exposure.statusOpen", "open");
  return status || t("exposure.statusUnknown", "unknown");
}

export default function Exposure() {
  const { locale, t } = useLanguage();
  const [providers, setProviders] = useState<ExposureProvider[]>([]);
  const [assets, setAssets] = useState<ExposureAsset[]>([]);
  const [groups, setGroups] = useState<ExposureAssetGroup[]>([]);
  const [incidents, setIncidents] = useState<ExposureIncident[]>([]);
  const [assetType, setAssetType] = useState("domain");
  const [value, setValue] = useState("");
  const [scheduleMode, setScheduleMode] = useState("daily");
  const [groupName, setGroupName] = useState("");
  const [selectedAssetIds, setSelectedAssetIds] = useState<string[]>([]);
  const [selectedAssetId, setSelectedAssetId] = useState("");
  const [selectedFindingIds, setSelectedFindingIds] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    void loadExposureRuntime();
  }, []);

  async function loadExposureRuntime() {
    setLoading(true);
    setError("");
    try {
      const [providersRes, assetsRes, groupsRes, incidentsRes] = await Promise.all([
        fetch(`${API_URL}/api/exposure/providers`, { credentials: "include" }),
        fetch(`${API_URL}/api/exposure/assets`, { credentials: "include" }),
        fetch(`${API_URL}/api/exposure/asset-groups`, { credentials: "include" }),
        fetch(`${API_URL}/api/exposure/incidents`, { credentials: "include" }),
      ]);

      if (!providersRes.ok || !assetsRes.ok || !groupsRes.ok || !incidentsRes.ok) {
        throw new Error("exposure_load_failed");
      }

      const providersData = (await providersRes.json()) as { items: ExposureProvider[] };
      const assetsData = (await assetsRes.json()) as { items: ExposureAsset[] };
      const groupsData = (await groupsRes.json()) as { items: ExposureAssetGroup[] };
      const incidentsData = (await incidentsRes.json()) as { items: ExposureIncident[] };

      const nextAssets = assetsData.items || [];
      setProviders(providersData.items || []);
      setAssets(nextAssets);
      setGroups(groupsData.items || []);
      setIncidents(incidentsData.items || []);
      setSelectedAssetIds((current) => current.filter((id) => nextAssets.some((asset) => asset._id === id)));
      setSelectedAssetId((current) => {
        if (current && nextAssets.some((asset) => asset._id === current)) return current;
        return nextAssets[0]?._id || "";
      });
    } catch {
      setError(t("exposure.loadFailed", "Could not load the exposure area."));
    } finally {
      setLoading(false);
    }
  }

  const supportedAssetTypes = useMemo(() => {
    const set = new Set<string>();
    for (const provider of providers) {
      for (const type of provider.assetTypes || []) {
        set.add(type);
      }
    }
    return Array.from(set);
  }, [providers]);

  const selectedAsset = useMemo(
    () => assets.find((asset) => asset._id === selectedAssetId) || null,
    [assets, selectedAssetId],
  );

  const selectedAssetFindings = selectedAsset?.recent_findings || [];

  const openIncidents = useMemo(
    () => incidents.filter((incident) => incident.status !== "resolved" && incident.status !== "dismissed").length,
    [incidents],
  );

  async function createAsset() {
    setBusy("create");
    setError("");
    setNotice("");
    try {
      const response = await fetch(`${API_URL}/api/exposure/assets`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          asset_type: assetType,
          value,
          schedule_mode: scheduleMode,
        }),
      });

      if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.detail || "exposure_create_failed");
      }

      setValue("");
      setNotice(t("exposure.noticeAssetCreated", "Monitored asset created."));
      await loadExposureRuntime();
    } catch (err) {
      const detail = err instanceof Error ? err.message : "";
      setError(
        detail === "exposure_asset_already_exists"
          ? t("exposure.errorAssetExists", "This asset is already being monitored.")
          : t("exposure.errorCreateAsset", "Could not create the exposure asset."),
      );
    } finally {
      setBusy("");
    }
  }

  async function scanAsset(assetId: string) {
    setBusy(assetId);
    setError("");
    setNotice("");
    try {
      const response = await fetch(`${API_URL}/api/exposure/assets/${assetId}/scan`, {
        method: "POST",
        credentials: "include",
      });

      if (!response.ok) {
        throw new Error("exposure_scan_failed");
      }

      const data = (await response.json()) as { total_results: number };
      setNotice(`${t("exposure.noticeScanComplete", "Scan completed with")} ${data.total_results || 0} ${t("exposure.findingCount", "finding(s)")}.`);
      await loadExposureRuntime();
    } catch {
      setError(t("exposure.errorScanAsset", "Could not execute the scan for this asset."));
    } finally {
      setBusy("");
    }
  }

  async function bulkScanSelected() {
    if (!selectedAssetIds.length) return;
    setBusy("bulk-scan");
    setError("");
    setNotice("");
    try {
      const response = await fetch(`${API_URL}/api/exposure/assets/bulk-scan`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ asset_ids: selectedAssetIds }),
      });
      if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.detail || "exposure_bulk_scan_failed");
      }
      const data = (await response.json()) as { assets_scanned: number; total_results: number };
      setNotice(`${data.assets_scanned} ${t("exposure.noticeAssetsScanned", "asset(s) scanned with")} ${data.total_results} ${t("exposure.findingCount", "finding(s)")}.`);
      await loadExposureRuntime();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("exposure.errorBulkScan", "Failed to orchestrate bulk scan."));
    } finally {
      setBusy("");
    }
  }

  async function createGroup() {
    if (!groupName.trim() || !selectedAssetIds.length) return;
    setBusy("create-group");
    setError("");
    setNotice("");
    try {
      const response = await fetch(`${API_URL}/api/exposure/asset-groups`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: groupName, asset_ids: selectedAssetIds }),
      });
      if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.detail || "exposure_group_create_failed");
      }
      setGroupName("");
      setNotice(t("exposure.noticeGroupCreated", "Operational group created for orchestration."));
      await loadExposureRuntime();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("exposure.errorCreateGroup", "Failed to create the group."));
    } finally {
      setBusy("");
    }
  }

  async function scanGroup(groupId: string) {
    setBusy(groupId);
    setError("");
    setNotice("");
    try {
      const response = await fetch(`${API_URL}/api/exposure/asset-groups/${groupId}/scan`, {
        method: "POST",
        credentials: "include",
      });
      if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.detail || "exposure_group_scan_failed");
      }
      const data = (await response.json()) as { assets_scanned: number; total_results: number };
      setNotice(`${t("exposure.noticeGroupExecuted", "Group executed")}: ${data.assets_scanned} ${t("exposure.assets", "assets")}, ${data.total_results} ${t("exposure.findingCount", "finding(s)")}.`);
      await loadExposureRuntime();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("exposure.errorRunGroup", "Failed to run group."));
    } finally {
      setBusy("");
    }
  }

  async function promoteSelectedFindings() {
    if (!selectedAsset || !selectedFindingIds.length) return;
    setBusy("promote");
    setError("");
    setNotice("");
    try {
      const response = await fetch(`${API_URL}/api/exposure/incidents/promote`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          asset_id: selectedAsset._id,
          finding_ids: selectedFindingIds,
        }),
      });
      if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.detail || "exposure_promote_failed");
      }
      setSelectedFindingIds([]);
      setNotice(t("exposure.noticeFindingsPromoted", "Findings promoted to incident."));
      await loadExposureRuntime();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("exposure.errorPromoteFindings", "Failed to promote findings."));
    } finally {
      setBusy("");
    }
  }

  async function updateIncidentStatus(incidentId: string, status: string) {
    setBusy(incidentId);
    setError("");
    setNotice("");
    try {
      const response = await fetch(`${API_URL}/api/exposure/incidents/${incidentId}`, {
        method: "PATCH",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status }),
      });
      if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.detail || "exposure_incident_patch_failed");
      }
      setNotice(`${t("exposure.noticeIncidentMoved", "Incident moved to")} ${status}.`);
      await loadExposureRuntime();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("exposure.errorUpdateIncident", "Failed to update incident."));
    } finally {
      setBusy("");
    }
  }

  function toggleAssetSelection(assetId: string) {
    setSelectedAssetIds((current) =>
      current.includes(assetId) ? current.filter((id) => id !== assetId) : [...current, assetId],
    );
  }

  function toggleFindingSelection(findingId: string) {
    setSelectedFindingIds((current) =>
      current.includes(findingId) ? current.filter((id) => id !== findingId) : [...current, findingId],
    );
  }

  return (
    <div className="page-frame space-y-8">
      <PageHeader
        eyebrow={t("exposure.eyebrow", "Analyst")}
        title={t("exposure.title", "External Attack Surface Management")}
        description={t("exposure.subtitle", "Monitore ativos externos com scans em massa, grupos operacionais e fluxo de incidente para findings relevantes.")}
        metrics={
          <>
            <PageMetricPill label={`${assets.length} ${t("exposure.assets", "assets")}`} dotClassName="bg-primary" tone="primary" />
            <PageMetricPill label={`${groups.length} ${t("exposure.groups", "groups")}`} dotClassName="bg-secondary" />
            <PageMetricPill label={`${openIncidents} ${t("exposure.openIncidents", "open incidents")}`} dotClassName={openIncidents > 0 ? "bg-error" : "bg-emerald-500"} tone={openIncidents > 0 ? "danger" : "success"} />
          </>
        }
      />

      <PageToolbar label={t("exposure.actions", "Exposure actions")}>
        <PageToolbarGroup className="ml-auto">
          <button onClick={loadExposureRuntime} className="btn btn-outline">
            <RefreshCw className="h-4 w-4" />
            {t("exposure.refresh", "Refresh")}
          </button>
          <button onClick={() => void bulkScanSelected()} disabled={!selectedAssetIds.length || busy === "bulk-scan"} className="btn btn-outline">
            <Search className="h-4 w-4" />
            {t("exposure.bulkScan", "Bulk Scan")}
          </button>
          <button onClick={() => void promoteSelectedFindings()} disabled={!selectedFindingIds.length || busy === "promote"} className="btn btn-primary">
            <Siren className="h-4 w-4" />
            {t("exposure.promoteIncident", "Promote Incident")}
          </button>
        </PageToolbarGroup>
      </PageToolbar>

      {(error || notice) && (
        <div className="space-y-3">
          {error && <div className="rounded-sm bg-error/10 px-4 py-3 text-sm text-error">{error}</div>}
          {notice && <div className="rounded-sm bg-primary/10 px-4 py-3 text-sm text-primary">{notice}</div>}
        </div>
      )}

      <div className="page-with-side-rail">
        <div className="page-main-pane grid grid-cols-12 gap-6">
          <div className="col-span-12 lg:col-span-4 surface-section p-6">
            <h3 className="text-xs font-bold uppercase tracking-widest text-on-surface mb-4 flex items-center gap-2">
              <Globe className="w-4 h-4 text-error" />
              {t("exposure.monitoredAsset", "Monitored Asset")}
            </h3>
            <div className="space-y-5">
              <label className="block space-y-2">
                <div className="text-[10px] font-bold uppercase tracking-[0.16em] text-outline">{t("exposure.assetType", "Asset Type")}</div>
                <select value={assetType} onChange={(event) => setAssetType(event.target.value)} className="w-full border-0 border-b-2 border-outline bg-surface-container-high px-0 py-3 text-sm text-on-surface outline-none focus:border-primary">
                  {(supportedAssetTypes.length ? supportedAssetTypes : ["domain", "subdomain", "brand_keyword"]).map((type) => (
                    <option key={type} value={type}>{type}</option>
                  ))}
                </select>
              </label>
              <label className="block space-y-2">
                <div className="text-[10px] font-bold uppercase tracking-[0.16em] text-outline">{t("exposure.assetValue", "Asset Value")}</div>
                <input value={value} onChange={(event) => setValue(event.target.value)} placeholder={t("exposure.assetPlaceholder", "example.com or your-brand")} className="w-full border-0 border-b-2 border-outline bg-surface-container-high px-0 py-3 text-sm text-on-surface outline-none focus:border-primary" />
              </label>
              <label className="block space-y-2">
                <div className="text-[10px] font-bold uppercase tracking-[0.16em] text-outline">{t("exposure.schedule", "Schedule")}</div>
                <select value={scheduleMode} onChange={(event) => setScheduleMode(event.target.value)} className="w-full border-0 border-b-2 border-outline bg-surface-container-high px-0 py-3 text-sm text-on-surface outline-none focus:border-primary">
                  <option value="manual">{t("exposure.scheduleManual", "manual")}</option>
                  <option value="daily">{t("exposure.scheduleDaily", "daily")}</option>
                  <option value="continuous">{t("exposure.scheduleContinuous", "continuous")}</option>
                </select>
              </label>
              <button onClick={() => void createAsset()} disabled={!value.trim() || busy === "create"} className="inline-flex w-full items-center justify-center gap-2 rounded-sm bg-error px-5 py-3 text-[11px] font-bold uppercase tracking-[0.18em] text-white hover:bg-error/90 disabled:cursor-not-allowed disabled:opacity-60">
                <Plus className="h-4 w-4" />
                {busy === "create" ? t("exposure.creating", "Creating") : t("exposure.createAsset", "Create Asset")}
              </button>
            </div>
          </div>

          <div className="col-span-12 lg:col-span-8 surface-section">
            <div className="surface-section-header">
              <h3 className="text-xs font-bold uppercase tracking-widest text-on-surface">{t("exposure.monitoredAssets", "Monitored Assets")}</h3>
              <span className="text-[10px] font-bold uppercase tracking-[0.16em] text-on-surface-variant">
                {selectedAssetIds.length} {t("exposure.selected", "selected")}
              </span>
            </div>
            <div className="p-6 space-y-6">
              {loading ? (
                <div className="rounded-sm bg-surface-container-low p-8 text-center text-sm text-on-surface-variant">{t("exposure.loadingData", "Loading exposure data")}</div>
              ) : assets.length === 0 ? (
                <div className="rounded-sm bg-surface-container-low p-8 text-center text-sm text-on-surface-variant">{t("exposure.noAssets", "Nenhum ativo monitorado ainda.")}</div>
              ) : (
                assets.map((asset) => (
                  <section key={asset._id} className={`rounded-sm p-5 ${selectedAssetId === asset._id ? "bg-surface-container" : "bg-surface-container-low"}`}>
                    <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                      <div className="flex items-start gap-3">
                        <input type="checkbox" checked={selectedAssetIds.includes(asset._id)} onChange={() => toggleAssetSelection(asset._id)} className="mt-1" />
                        <button type="button" onClick={() => { setSelectedAssetId(asset._id); setSelectedFindingIds([]); }} className="text-left">
                          <div className="text-sm font-bold text-on-surface">{asset.value}</div>
                          <div className="mt-1 text-[11px] uppercase tracking-[0.16em] text-on-surface-variant">
                            {asset.asset_type} · {scheduleLabel(asset.recurrence?.mode, t)} · {asset.recurrence?.last_status || t("exposure.neverRun", "never_run")}
                          </div>
                          <div className="mt-3 flex flex-wrap gap-3 text-xs text-on-surface-variant">
                            <span>{asset.finding_count} {t("exposure.findingCount", "finding(s)")}</span>
                            <span>{asset.incident_count} {t("exposure.incidentCount", "incident(s)")}</span>
                            <span>{t("exposure.updated", "Updated")} {formatTimestamp(asset.updated_at, locale)}</span>
                          </div>
                        </button>
                      </div>
                      <button onClick={() => void scanAsset(asset._id)} disabled={busy === asset._id} className="inline-flex items-center gap-2 rounded-sm bg-error px-4 py-2 text-[11px] font-bold uppercase tracking-[0.16em] text-white hover:bg-error/90 disabled:cursor-not-allowed disabled:opacity-60">
                        <Search className="h-4 w-4" />
                        {busy === asset._id ? t("exposure.scanning", "Scanning") : t("exposure.runScan", "Run Scan")}
                      </button>
                    </div>

                    <div className="mt-5 grid grid-cols-1 gap-4">
                      {asset.recent_findings.length === 0 ? (
                        <div className="rounded-sm bg-surface-container-lowest px-4 py-4 text-xs text-on-surface-variant">{t("exposure.noRecentFindings", "Nenhum finding recente registrado para este ativo.")}</div>
                      ) : (
                        asset.recent_findings.map((finding, index) => (
                          <div key={`${finding._id || finding.title}-${index}`} className="rounded-sm bg-surface-container-lowest px-4 py-4">
                            <div className="flex items-start gap-3">
                              <input
                                type="checkbox"
                                checked={Boolean(finding._id && selectedFindingIds.includes(finding._id))}
                                onChange={() => finding._id && toggleFindingSelection(finding._id)}
                                disabled={!finding._id || Boolean(finding.incident_id)}
                                className="mt-1"
                              />
                              <div className="min-w-0 flex-1">
                                <div className="flex flex-col gap-2 lg:flex-row lg:items-center lg:justify-between">
                                  <div>
                                    <div className="text-sm font-bold text-on-surface">{finding.title}</div>
                                    <div className="mt-1 text-[11px] uppercase tracking-[0.16em] text-on-surface-variant">{finding.kind}</div>
                                  </div>
                                  <span className={`inline-flex items-center whitespace-nowrap rounded-sm px-2 py-1 text-[10px] font-bold uppercase tracking-[0.16em] ${severityClasses(finding.severity)}`}>
                                    {severityLabel(finding.severity, t)}
                                  </span>
                                </div>
                                <div className="mt-3 text-xs text-on-surface-variant">{finding.summary}</div>
                                <div className="mt-3 flex items-center justify-between gap-3 text-[11px] text-on-surface-variant">
                                  <span>{finding.incident_id ? `${t("exposure.incidentPrefix", "Incident")} ${finding.incident_id}` : t("exposure.notPromoted", "Not promoted")}</span>
                                  {finding.external_ref && (
                                    <a href={finding.external_ref} target="_blank" rel="noreferrer" className="inline-flex text-xs font-bold uppercase tracking-[0.16em] text-primary hover:underline">
                                      {t("exposure.openReference", "Open reference")}
                                    </a>
                                  )}
                                </div>
                              </div>
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  </section>
                ))
              )}
            </div>
          </div>
        </div>

        <div className="page-side-rail-right space-y-6">
          <div className="surface-section">
            <div className="surface-section-header">
              <h3 className="surface-section-title">{t("exposure.assetGroups", "Asset Groups")}</h3>
            </div>
            <div className="p-6 space-y-4">
              <label className="block space-y-2">
                <div className="inline-flex items-center gap-2 text-[10px] font-bold uppercase tracking-[0.16em] text-outline">
                  <Layers3 className="h-4 w-4" />
                  {t("exposure.groupName", "Group name")}
                </div>
                <input value={groupName} onChange={(event) => setGroupName(event.target.value)} placeholder={t("exposure.groupPlaceholder", "Priority perimeter")} className="w-full border-0 border-b-2 border-outline bg-surface-container-high px-0 py-3 text-sm text-on-surface outline-none focus:border-primary" />
              </label>
              <button onClick={() => void createGroup()} disabled={!groupName.trim() || !selectedAssetIds.length || busy === "create-group"} className="btn btn-outline w-full">
                {t("exposure.createFromSelection", "Create from selection")}
              </button>
              <div className="space-y-3">
                {groups.length === 0 ? (
                  <div className="text-sm text-on-surface-variant">{t("exposure.noGroups", "Nenhum grupo criado ainda.")}</div>
                ) : (
                  groups.map((group) => (
                    <div key={group._id} className="rounded-sm bg-surface-container-low px-4 py-4">
                      <div className="flex items-center justify-between gap-3">
                        <div>
                          <div className="text-sm font-bold text-on-surface">{group.name}</div>
                          <div className="mt-1 text-[11px] text-on-surface-variant">{group.assets.length} {t("exposure.assets", "assets")}</div>
                        </div>
                          <button onClick={() => void scanGroup(group._id)} disabled={busy === group._id} className="btn btn-outline">
                          {busy === group._id ? t("exposure.running", "Running") : t("exposure.runGroup", "Run group")}
                        </button>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          <div className="surface-section">
            <div className="surface-section-header">
              <h3 className="surface-section-title">{t("exposure.incidentQueue", "Incident Queue")}</h3>
            </div>
            <div className="p-6 space-y-4">
              {incidents.length === 0 ? (
                <div className="text-sm text-on-surface-variant">{t("exposure.noIncidents", "Nenhum incidente aberto ainda.")}</div>
              ) : (
                incidents.map((incident) => (
                  <div key={incident._id} className="rounded-sm bg-surface-container-low px-4 py-4">
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <div className="text-sm font-bold text-on-surface">{incident.title}</div>
                        <div className="mt-1 text-[11px] text-on-surface-variant">{incident.summary}</div>
                      </div>
                      <span className={`inline-flex items-center whitespace-nowrap rounded-sm px-2 py-1 text-[10px] font-bold uppercase tracking-[0.16em] ${severityClasses(incident.severity)}`}>
                        {severityLabel(incident.severity, t)}
                      </span>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2">
                      <button onClick={() => void updateIncidentStatus(incident._id, "investigating")} className="btn btn-outline">
                        {t("exposure.investigate", "Investigate")}
                      </button>
                      <button onClick={() => void updateIncidentStatus(incident._id, "resolved")} className="btn btn-outline">
                        {t("exposure.resolve", "Resolve")}
                      </button>
                      <button onClick={() => void updateIncidentStatus(incident._id, "dismissed")} className="btn btn-outline">
                        {t("exposure.dismiss", "Dismiss")}
                      </button>
                    </div>
                    <div className="mt-3 text-[11px] text-on-surface-variant">
                      {incidentStatusLabel(incident.status, t)} · {t("exposure.updated", "Updated")} {formatTimestamp(incident.updated_at, locale)}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="surface-section p-6">
            <h3 className="text-xs font-bold uppercase tracking-widest text-on-surface mb-4 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-error" />
              {t("exposure.sourceInventory", "Source Inventory")}
            </h3>
            {loading ? (
              <div className="text-sm text-on-surface-variant">{t("exposure.loadingSources", "Loading sources")}</div>
            ) : (
              <div className="space-y-4">
                {providers.map((provider) => (
                  <div key={provider.key} className="rounded-sm bg-surface-container-low p-4">
                    <div className="text-sm font-bold text-on-surface">{provider.name}</div>
                    <div className="mt-1 text-[11px] text-on-surface-variant">
                      {provider.assetTypes.join(", ")} · {t("exposure.schedulePrefix", "schedule")} {scheduleLabel(provider.recommendedSchedule, t)}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
