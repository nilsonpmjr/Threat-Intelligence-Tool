import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { ChevronLeft, ChevronRight, Download, Filter, MessageSquare, RefreshCw, Rss, ShieldAlert, X } from "lucide-react";
import API_URL from "../config";
import ModalShell from "../components/modal/ModalShell";
import { PageHeader, PageToolbar, PageToolbarGroup } from "../components/page/PageChrome";
import { useLanguage } from "../context/LanguageContext";

type FeedItem = {
  _id: string;
  title: string;
  summary?: string;
  severity?: string;
  source_name?: string;
  source_type?: string;
  family?: string;
  tlp?: string;
  published_at?: string;
  sector?: string[];
  tags?: string[];
  data?: {
    link?: string;
    attributes?: {
      editorial?: {
        story_kind?: string;
        topics?: string[];
        headline_score?: number;
        is_newsworthy?: boolean;
      };
    };
  };
  editorial?: {
    story_kind?: string;
    topics?: string[];
    headline_score?: number;
    is_newsworthy?: boolean;
  };
};

type FeedModelingSnapshot = {
  phase: string;
  objective: string;
  model_status: string;
  eligible_items: number;
  newsworthy_items: number;
  feature_columns: string[];
  topic_distribution: Array<{ topic: string; count: number }>;
  story_kind_distribution: Array<{ story_kind: string; count: number }>;
  family_distribution: Array<{ family: string; count: number }>;
  priority_bands: { high: number; medium: number; low: number };
  next_steps: string[];
};

const PAGE_SIZE = 6;

function severityTone(
  severity: string | undefined,
  t: (key: string, fallback?: string) => string,
) {
  switch ((severity || "").toLowerCase()) {
    case "critical":
      return {
        label: t("feed.severityCritical", "CRITICAL"),
        className: "text-error",
        badge: "bg-error/10 text-error",
      };
    case "high":
      return {
        label: t("feed.severityHigh", "HIGH"),
        className: "text-error",
        badge: "bg-error-container/20 text-on-error-container",
      };
    case "medium":
      return {
        label: t("feed.severityMedium", "MEDIUM"),
        className: "text-amber-600",
        badge: "bg-amber-100 text-amber-700",
      };
    case "info":
      return {
        label: t("feed.severityInfo", "INFO"),
        className: "text-on-surface",
        badge: "bg-surface-container-high text-on-surface-variant",
      };
    default:
      return {
        label: t("feed.severityLow", "LOW"),
        className: "text-on-surface",
        badge: "bg-surface-container-high text-on-surface-variant",
      };
  }
}

function stripHtml(text?: string, maxChars = 320): string {
  if (!text) return "";
  const plain = text.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
  if (plain.length <= maxChars) return plain;
  return plain.slice(0, maxChars).replace(/\s+\S*$/, "") + "…";
}

function formatPublishedAt(value: string | undefined, locale: string, t: (key: string, fallback?: string) => string) {
  if (!value) return t("feed.unknown", "Unknown");
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return t("feed.unknown", "Unknown");
  return date.toLocaleString(locale);
}

export default function Feed() {
  const { t, locale } = useLanguage();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [items, setItems] = useState<FeedItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(Number(searchParams.get("page") || 1));
  const [severity, setSeverity] = useState(searchParams.get("severity") || "all");
  const [sourceType, setSourceType] = useState(searchParams.get("source_type") || "all");
  const [family, setFamily] = useState(searchParams.get("family") || "all");
  const [view, setView] = useState(searchParams.get("view") || "feed");
  const [modelingSnapshot, setModelingSnapshot] = useState<FeedModelingSnapshot | null>(null);
  const [modelingLoading, setModelingLoading] = useState(false);
  const [isModelingModalOpen, setIsModelingModalOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const lastFeedRefreshRef = useRef(0);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  const fetchFeed = useCallback(async (targetPage = page, background = false) => {
    if (!background) {
      setLoading(true);
    }
    try {
      const params = new URLSearchParams({
        limit: String(PAGE_SIZE),
        offset: String((targetPage - 1) * PAGE_SIZE),
      });
      if (severity !== "all") params.set("severity", severity);
      if (sourceType !== "all") params.set("source_type", sourceType);
      if (family !== "all") params.set("family", family);
      if (view !== "feed") params.set("view", view);

      const response = await fetch(`${API_URL}/api/feed?${params.toString()}`, {
        credentials: "include",
      });
      if (!response.ok) throw new Error("feed_fetch_failed");
      const data = await response.json();
      setItems(data.items || []);
      setTotal(data.total || 0);
    } catch {
      setItems([]);
      setTotal(0);
    } finally {
      if (!background) {
        setLoading(false);
      }
    }
  }, [page, severity, sourceType, family, view]);

  const loadModelingSnapshot = useCallback(async (background = false) => {
    if (!background) {
      setModelingLoading(true);
    }
    try {
      const response = await fetch(`${API_URL}/api/feed/modeling?window=200`, {
        credentials: "include",
      });
      if (!response.ok) throw new Error("feed_modeling_failed");
      const data = (await response.json()) as FeedModelingSnapshot;
      setModelingSnapshot(data);
    } catch {
      setModelingSnapshot(null);
    } finally {
      if (!background) {
        setModelingLoading(false);
      }
    }
  }, []);

  const refreshFeedRuntime = useCallback(async () => {
    const now = Date.now();
    if (now - lastFeedRefreshRef.current < 5000) {
      return;
    }
    lastFeedRefreshRef.current = now;
    await Promise.all([fetchFeed(page, true), loadModelingSnapshot(true)]);
  }, [fetchFeed, loadModelingSnapshot, page]);

  const refreshFeedManually = useCallback(async () => {
    setRefreshing(true);
    lastFeedRefreshRef.current = Date.now();
    try {
      await Promise.all([fetchFeed(page, true), loadModelingSnapshot(true)]);
    } finally {
      setRefreshing(false);
    }
  }, [fetchFeed, loadModelingSnapshot, page]);

  useEffect(() => {
    void fetchFeed(page);
  }, [fetchFeed, page]);

  useEffect(() => {
    const nextPage = Number(searchParams.get("page") || 1);
    const nextSeverity = searchParams.get("severity") || "all";
    const nextSourceType = searchParams.get("source_type") || "all";
    const nextFamily = searchParams.get("family") || "all";
    const nextView = searchParams.get("view") || "feed";
    setPage(Number.isFinite(nextPage) && nextPage > 0 ? nextPage : 1);
    setSeverity(nextSeverity);
    setSourceType(nextSourceType);
    setFamily(nextFamily);
    setView(nextView);
  }, [searchParams]);

  useEffect(() => {
    void loadModelingSnapshot();
  }, [loadModelingSnapshot]);

  useEffect(() => {
    const handleRefreshFeed = () => {
      void refreshFeedRuntime();
    };

    const handleInteraction = () => {
      if (document.visibilityState === "visible") {
        handleRefreshFeed();
      }
    };

    const handleVisibility = () => {
      if (document.visibilityState === "visible") {
        handleRefreshFeed();
      }
    };

    window.addEventListener("focus", handleRefreshFeed);
    window.addEventListener("vantage:feed-runtime-updated", handleRefreshFeed);
    window.addEventListener("pointerdown", handleInteraction);
    window.addEventListener("keydown", handleInteraction);
    document.addEventListener("visibilitychange", handleVisibility);
    return () => {
      window.removeEventListener("focus", handleRefreshFeed);
      window.removeEventListener("vantage:feed-runtime-updated", handleRefreshFeed);
      window.removeEventListener("pointerdown", handleInteraction);
      window.removeEventListener("keydown", handleInteraction);
      document.removeEventListener("visibilitychange", handleVisibility);
    };
  }, [refreshFeedRuntime]);

  function syncSearchParams(nextPage: number, nextSeverity: string, nextSourceType: string, nextFamily: string, nextView = view) {
    const next = new URLSearchParams();
    if (nextPage > 1) next.set("page", String(nextPage));
    if (nextSeverity !== "all") next.set("severity", nextSeverity);
    if (nextSourceType !== "all") next.set("source_type", nextSourceType);
    if (nextFamily !== "all") next.set("family", nextFamily);
    if (nextView !== "feed") next.set("view", nextView);
    setSearchParams(next, { replace: true });
  }

  const featured = useMemo(
    () => items.find((item) => item.severity === "critical" || item.severity === "high") || items[0],
    [items],
  );

  const linkedCount = useMemo(() => items.filter((item) => item.data?.link).length, [items]);
  const newsworthyCount = useMemo(
    () => items.filter((item) => item.editorial?.is_newsworthy || item.data?.attributes?.editorial?.is_newsworthy).length,
    [items],
  );

  function storyKindLabel(value?: string) {
    switch (value) {
      case "campaign":
        return t("feed.storyCampaign", "Campaign");
      case "incident":
        return t("feed.storyIncident", "Incident");
      case "research":
        return t("feed.storyResearch", "Research");
      case "advisory":
        return t("feed.storyAdvisory", "Advisory");
      default:
        return t("feed.storyBrief", "Brief");
    }
  }

  function exportCurrentView() {
    const payload = {
      page,
      severity,
      source_type: sourceType,
      family,
      total,
      exported_at: new Date().toISOString(),
      items,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `vantage-feed-page-${page}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  async function analyzeItemWithSocc(item: FeedItem) {
    try {
      const providersRes = await fetch(`${API_URL}/api/socc/providers`, { credentials: "include" });
      if (!providersRes.ok) { navigate("/socc"); return; }
      const { credentials: creds = [] } = await providersRes.json();
      if (!creds.length) { navigate("/socc"); return; }

      const sessionRes = await fetch(`${API_URL}/api/socc/session`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ credentialId: creds[0].id, analysisId: `feed:${item._id}` }),
      });
      if (!sessionRes.ok) { navigate("/socc"); return; }
      const { sessionId } = await sessionRes.json();

      await fetch(`${API_URL}/api/socc/session/${sessionId}/context`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          rawContext: [item.title, item.summary].filter(Boolean).join("\n"),
          analysisId: `feed:${item._id}`,
        }),
      });

      navigate(`/socc?sessionId=${sessionId}`);
    } catch {
      navigate("/socc");
    }
  }

  return (
    <div className="page-frame">
      <PageHeader
        title={t("feed.title", "Threat Intelligence Feed")}
        description={t("feed.subtitle", "Review operational intelligence, editorial signals, and publication context from the sources already ingested by the platform.")}
      />

      <PageToolbar className="mb-8" label={t("feed.actions", "Feed actions")}>
        <PageToolbarGroup className="ml-auto">
          <button
            type="button"
            onClick={() => setIsModelingModalOpen(true)}
            className="btn btn-outline"
          >
            {t("feed.modelingTitle", "CTI Modeling")}
          </button>
          <button
            onClick={() => {
              void refreshFeedManually();
            }}
            className="btn btn-outline"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? "animate-spin" : ""}`} />
            {t("feed.refresh", "Refresh")}
          </button>
        </PageToolbarGroup>
        <PageToolbarGroup>
          <button className="btn btn-primary" onClick={exportCurrentView}>
            <Download className="w-4 h-4" />
            {t("feed.exportReport", "Export Report")}
          </button>
        </PageToolbarGroup>
      </PageToolbar>

      <div className="grid grid-cols-12 gap-6 mb-8 lg:items-start">
        <div className="col-span-12 self-start lg:col-span-8 bg-surface-container-lowest p-6 shadow-sm border-l-4 border-error relative overflow-hidden rounded-sm">
          <div className="relative z-10">
            <span className="text-error font-bold text-[10px] uppercase tracking-[0.2em] mb-4 block">
              {t("feed.urgentDirective", "Urgent Directive")}
            </span>
            <h2 className="text-xl font-bold mb-3 tracking-tight leading-tight max-w-xl">
              {featured?.title || t("feed.noFeatured", "No feed items available in the current selection.")}
            </h2>
            <p className="text-on-surface-variant text-sm mb-6 max-w-2xl leading-relaxed">
              {stripHtml(featured?.summary) || t("feed.featuredFallback", "Adjust the filters or refresh the feed to ingest recent intelligence from the configured sources.")}
            </p>
            <div className="flex items-center gap-6 flex-wrap">
              <div className="flex flex-col">
                <span className="text-[10px] text-on-surface-variant font-bold uppercase">{t("feed.severity", "Severity")}</span>
                <span className={`text-sm font-semibold ${severityTone(featured?.severity, t).className}`}>
                  {severityTone(featured?.severity, t).label}
                </span>
              </div>
              <div className="flex flex-col">
                <span className="text-[10px] text-on-surface-variant font-bold uppercase">{t("feed.source", "Source")}</span>
                <span className="text-sm font-semibold">{featured?.source_name || featured?.source_type || "VANTAGE"}</span>
              </div>
              {(featured?.editorial?.story_kind || featured?.data?.attributes?.editorial?.story_kind) && (
                <div className="flex flex-col">
                  <span className="text-[10px] text-on-surface-variant font-bold uppercase">{t("feed.storyKind", "Story Kind")}</span>
                  <span className="text-sm font-semibold">
                    {storyKindLabel(featured?.editorial?.story_kind || featured?.data?.attributes?.editorial?.story_kind)}
                  </span>
                </div>
              )}
              <div className="flex flex-col">
                <span className="text-[10px] text-on-surface-variant font-bold uppercase">TLP</span>
                <span className="text-sm font-semibold text-error">{(featured?.tlp || "white").toUpperCase()}</span>
              </div>
            </div>
          </div>
          <ShieldAlert className="absolute -right-4 -bottom-4 w-40 h-40 opacity-[0.03] rotate-12 text-on-surface" />
        </div>
        <div className="col-span-12 lg:col-span-4 flex flex-col gap-4">
          <div className="flex-1 bg-surface-container-lowest p-4 flex flex-col justify-between shadow-sm rounded-sm">
            <span className="text-[10px] text-on-surface-variant font-bold uppercase tracking-widest">
              {t("feed.volume", "Feed Volume (page)")}
            </span>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-black tracking-tighter">{items.length}</span>
              <span className="text-xs text-emerald-500 font-bold">
                {t("feed.of", "of")} {total}
              </span>
            </div>
          </div>
          <div className="flex-1 bg-surface-container-lowest p-4 flex flex-col justify-between shadow-sm rounded-sm">
            <span className="text-[10px] text-on-surface-variant font-bold uppercase tracking-widest">
              {t("feed.editorialSignals", "Editorial Signals")}
            </span>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-black tracking-tighter">{newsworthyCount}</span>
              <span className="text-xs text-error font-bold">{linkedCount} {t("feed.externalRefs", "external refs")}</span>
            </div>
          </div>
        </div>
      </div>

      <div className="bg-surface-container-low p-3 mb-6 flex flex-wrap items-center justify-between gap-4 rounded-sm">
        <div className="flex items-center gap-3 flex-wrap">
          <Filter className="w-4 h-4 text-on-surface-variant" />
          <select
            value={severity}
            onChange={(e) => {
              syncSearchParams(1, e.target.value, sourceType, family, view);
            }}
            className="px-3 py-2 bg-surface-container-lowest border border-outline-variant/30 rounded-sm text-xs font-semibold text-on-surface"
          >
            <option value="all">{t("feed.allSeverities", "All Severities")}</option>
            <option value="critical">{t("feed.severityCritical", "Critical")}</option>
            <option value="high">{t("feed.severityHigh", "High")}</option>
            <option value="medium">{t("feed.severityMedium", "Medium")}</option>
            <option value="low">{t("feed.severityLow", "Low")}</option>
            <option value="info">{t("feed.severityInfo", "Info")}</option>
          </select>
          <select
            value={sourceType}
            onChange={(e) => {
              syncSearchParams(1, severity, e.target.value, family, view);
            }}
            className="px-3 py-2 bg-surface-container-lowest border border-outline-variant/30 rounded-sm text-xs font-semibold text-on-surface"
          >
            <option value="all">{t("feed.allSources", "All Sources")}</option>
            <option value="rss">{t("feed.sourceRss", "RSS")}</option>
            <option value="misp">{t("feed.sourceMisp", "MISP")}</option>
          </select>
          <select
            value={family}
            onChange={(e) => {
              syncSearchParams(1, severity, sourceType, e.target.value, view);
            }}
            className="px-3 py-2 bg-surface-container-lowest border border-outline-variant/30 rounded-sm text-xs font-semibold text-on-surface"
          >
            <option value="all">{t("feed.allFamilies", "All Families")}</option>
            <option value="cve">{t("feed.familyCve", "CVE")}</option>
            <option value="fortinet">{t("feed.familyFortinet", "Fortinet RSS")}</option>
            <option value="misp">{t("feed.familyMisp", "MISP")}</option>
            <option value="custom">{t("feed.familyCustom", "Custom RSS")}</option>
          </select>
        </div>
        <div className="flex items-center gap-2 text-on-surface-variant">
          <span className="text-[11px] font-bold uppercase tracking-widest">{t("feed.showing", "Showing:")}</span>
          <span className="text-xs font-medium text-on-surface">
            {items.length} {t("feed.items", "items")}
          </span>
        </div>
      </div>

      {loading ? (
        <div className="bg-surface-container-lowest rounded-sm shadow-sm p-8 text-sm text-on-surface-variant">
          {t("feed.loading", "Loading threat feed...")}
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {items.map((item) => {
            const tone = severityTone(item.severity, t);
            return (
              <article
                key={item._id}
                className={`bg-surface-container-lowest p-5 shadow-sm hover:shadow-md transition-shadow group rounded-sm flex flex-col ${item.severity === "critical" ? "border-l-4 border-error" : ""}`}
              >
                <div className="flex justify-between items-start mb-4 gap-3">
                  <div className="flex items-center gap-2">
                    <div className="w-8 h-8 bg-surface-container-high flex items-center justify-center rounded">
                      <Rss className="w-4 h-4 text-on-surface-variant" />
                    </div>
                    <div className="flex flex-col">
                      <span className="text-xs font-bold tracking-tight">{item.source_name || item.source_type || "VANTAGE"}</span>
                        <span className="text-[10px] text-outline uppercase font-semibold">
                        {item.editorial?.story_kind || item.data?.attributes?.editorial?.story_kind
                          ? `${t("feed.storyKind", "Story Kind")} / ${storyKindLabel(item.editorial?.story_kind || item.data?.attributes?.editorial?.story_kind).toUpperCase()}`
                          : `${t("feed.sourcePrefix", "Source")} / ${(item.source_type || "intel").toUpperCase()}`}
                      </span>
                    </div>
                  </div>
                  <span className={`inline-flex items-center whitespace-nowrap rounded px-2 py-0.5 text-[9px] font-black uppercase tracking-widest ${tone.badge}`}>
                    TLP: {(item.tlp || "white").toUpperCase()}
                  </span>
                </div>
                <h3 className="text-base font-bold mb-2 group-hover:text-primary transition-colors tracking-tight">
                  {item.title}
                </h3>
                <p className="text-on-surface-variant text-xs leading-relaxed mb-4 line-clamp-3">
                  {stripHtml(item.summary) || t("feed.noSummary", "No summary available for this feed item.")}
                </p>
                <div className="flex items-center justify-between mt-auto pt-4 border-t border-surface-container-low gap-3">
                  <div className="flex items-center gap-4 flex-wrap">
                    <div className="flex flex-col">
                      <span className="text-[9px] uppercase font-bold text-on-surface-variant">{t("feed.posted", "Posted")}</span>
                      <span className="text-[11px] font-semibold">{formatPublishedAt(item.published_at, locale, t)}</span>
                    </div>
                    <div className="flex flex-col">
                      <span className="text-[9px] uppercase font-bold text-on-surface-variant">
                        {t("feed.severity", "Severity")}
                      </span>
                      <span className={`text-[11px] font-semibold ${tone.className}`}>{tone.label}</span>
                    </div>
                  </div>
                  <div className="flex gap-1 flex-wrap justify-end">
                    {((item.editorial?.topics || item.data?.attributes?.editorial?.topics || item.tags || []).slice(0, 3)).map((tag) => (
                      <span
                        key={tag}
                        className="px-1.5 py-0.5 bg-surface-container-high text-on-surface-variant text-[9px] font-bold rounded"
                      >
                        {tag.toUpperCase()}
                      </span>
                    ))}
                  </div>
                </div>
                <div className="mt-4 flex items-center gap-3 flex-wrap">
                  {item.data?.link && (
                    <button
                      onClick={() => window.open(item.data?.link, "_blank", "noopener")}
                      className="text-left text-xs font-bold uppercase tracking-widest text-primary hover:underline"
                    >
                      {t("feed.openSourceReference", "Open source reference")}
                    </button>
                  )}
                  <button
                    onClick={() => void analyzeItemWithSocc(item)}
                    className="ml-auto flex items-center gap-1.5 text-xs font-bold uppercase tracking-widest text-on-surface-variant hover:text-primary transition-colors"
                    title={t("feed.analyzeWithSocc", "Analyze with SOC Copilot")}
                  >
                    <MessageSquare className="w-3.5 h-3.5" />
                    {t("feed.analyzeWithSocc", "SOCC")}
                  </button>
                </div>
              </article>
            );
          })}
        </div>
      )}

      {isModelingModalOpen && (
        <ModalShell
          title={t("feed.modelingObjective", "Story Prioritization Baseline")}
          description={t("feed.modelingSubtitle", "Use editorial CTI signals already ingested by the platform to prepare labeling and ranking experiments without exposing a fake model layer.")}
          icon={
            <>
              <Rss className="h-4 w-4 text-primary" />
              {t("feed.modelingTitle", "CTI Modeling")}
            </>
          }
          variant="editor"
          onClose={() => setIsModelingModalOpen(false)}
          ariaLabel={t("feed.closeModelingModal", "Close CTI modeling")}
        >
              {modelingLoading ? (
                <div className="text-xs text-on-surface-variant">
                  {t("feed.modelingLoading", "Loading modeling readiness...")}
                </div>
              ) : modelingSnapshot ? (
                <>
                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                    <div className="bg-surface-container-low p-3 rounded-sm">
                      <div className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">
                        {t("feed.modelingReady", "Ready Items")}
                      </div>
                      <div className="mt-2 text-2xl font-black tracking-tight">{modelingSnapshot.eligible_items}</div>
                    </div>
                    <div className="bg-surface-container-low p-3 rounded-sm">
                      <div className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">
                        {t("feed.modelingNewsworthy", "Newsworthy")}
                      </div>
                      <div className="mt-2 text-2xl font-black tracking-tight">{modelingSnapshot.newsworthy_items}</div>
                    </div>
                  </div>
                  <div className="mt-4 grid grid-cols-1 gap-2 text-xs sm:grid-cols-3">
                    <div className="bg-surface-container-low p-3 rounded-sm">
                      <div className="font-bold uppercase tracking-widest text-[10px] text-on-surface-variant">{t("feed.modelingHigh", "High")}</div>
                      <div className="mt-2 text-lg font-black">{modelingSnapshot.priority_bands.high}</div>
                    </div>
                    <div className="bg-surface-container-low p-3 rounded-sm">
                      <div className="font-bold uppercase tracking-widest text-[10px] text-on-surface-variant">{t("feed.modelingMedium", "Medium")}</div>
                      <div className="mt-2 text-lg font-black">{modelingSnapshot.priority_bands.medium}</div>
                    </div>
                    <div className="bg-surface-container-low p-3 rounded-sm">
                      <div className="font-bold uppercase tracking-widest text-[10px] text-on-surface-variant">{t("feed.modelingLow", "Low")}</div>
                      <div className="mt-2 text-lg font-black">{modelingSnapshot.priority_bands.low}</div>
                    </div>
                  </div>
                  <div className="mt-4">
                    <div className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">
                      {t("feed.modelingTopTopics", "Top Topics")}
                    </div>
                    <div className="mt-2 flex flex-wrap gap-2">
                      {modelingSnapshot.topic_distribution.slice(0, 4).map((entry) => (
                        <span
                          key={entry.topic}
                          className="rounded bg-surface-container-high px-2 py-1 text-[10px] font-bold text-on-surface-variant"
                        >
                          {entry.topic.toUpperCase()} · {entry.count}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div className="mt-4 text-xs leading-relaxed text-on-surface-variant">
                    <span className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">
                      {t("feed.modelingFeatures", "Feature Pack")}
                    </span>
                    <div className="mt-2">
                      {modelingSnapshot.feature_columns.join(", ")}
                    </div>
                  </div>
                  <div className="mt-4 space-y-2">
                    <div className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">
                      {t("feed.modelingActions", "Operational actions")}
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <button
                        className="btn btn-outline"
                        onClick={() => {
                          syncSearchParams(1, "all", "all", "all", "news");
                          setIsModelingModalOpen(false);
                        }}
                      >
                        {t("feed.modelingOpenNewsworthy", "Open newsworthy slice")}
                      </button>
                      <button
                        className="btn btn-outline"
                        onClick={() => {
                          syncSearchParams(1, severity, "rss", family, "feed");
                          setIsModelingModalOpen(false);
                        }}
                      >
                        {t("feed.modelingOpenRss", "Open RSS editorial feed")}
                      </button>
                    </div>
                  </div>
                  {modelingSnapshot.next_steps?.length ? (
                    <div className="mt-4">
                      <div className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">
                        {t("feed.modelingNextSteps", "Next steps")}
                      </div>
                      <ul className="mt-2 space-y-1 text-xs leading-relaxed text-on-surface-variant">
                        {modelingSnapshot.next_steps.slice(0, 3).map((step) => (
                          <li key={step}>• {step}</li>
                        ))}
                      </ul>
                    </div>
                  ) : null}
                </>
              ) : (
                <div className="text-xs text-on-surface-variant">
                  {t("feed.modelingUnavailable", "Modeling readiness is not available for the current feed window.")}
                </div>
              )}
        </ModalShell>
      )}

      <div className="bg-surface-container-low px-6 py-3 border-t border-surface-container flex items-center justify-between mt-6 rounded-sm">
        <span className="text-[11px] font-bold text-on-surface-variant uppercase tracking-widest">
          {t("feed.page", "Page")} {page} {t("feed.of", "of")} {totalPages}
        </span>
        <div className="flex gap-1 items-center">
          <button
            onClick={() => syncSearchParams(Math.max(1, page - 1), severity, sourceType, family)}
            disabled={page === 1}
            className="p-1 text-outline hover:text-on-surface disabled:opacity-30"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          {Array.from({ length: Math.min(totalPages, 5) }, (_, index) => {
            const pageNumber = index + 1;
            return (
              <button
                key={pageNumber}
                onClick={() => syncSearchParams(pageNumber, severity, sourceType, family)}
                className={`p-1 font-medium text-xs px-2 ${pageNumber === page ? "text-on-surface font-bold underline underline-offset-4" : "text-on-surface-variant hover:text-on-surface"}`}
              >
                {pageNumber}
              </button>
            );
          })}
          <button
            onClick={() => syncSearchParams(Math.min(totalPages, page + 1), severity, sourceType, family)}
            disabled={page === totalPages}
            className="p-1 text-outline hover:text-on-surface disabled:opacity-30"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
