import { useEffect, useState } from "react";
import { ArrowLeft, Bookmark, Search, Trash2 } from "lucide-react";
import { useNavigate } from "react-router-dom";
import API_URL from "../config";
import { PageHeader, PageMetricPill, PageToolbar, PageToolbarGroup } from "../components/page/PageChrome";
import { useLanguage } from "../context/LanguageContext";

interface SavedHuntingSearch {
  _id: string;
  name: string;
  artifact_type: string;
  query: string;
  provider_keys: string[];
  created_at: string;
  last_used_at?: string | null;
  use_count: number;
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

export default function HuntingSavedSearches() {
  const { t, locale } = useLanguage();
  const navigate = useNavigate();
  const [items, setItems] = useState<SavedHuntingSearch[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    void loadSavedSearches();
  }, []);

  async function loadSavedSearches() {
    setLoading(true);
    setError("");
    try {
      const response = await fetch(`${API_URL}/api/hunting/saved-searches`, {
        credentials: "include",
      });
      if (!response.ok) {
        throw new Error("saved_searches_load_failed");
      }
      const data = (await response.json()) as { items: SavedHuntingSearch[] };
      setItems(data.items || []);
    } catch {
      setError(t("hunting.savedSearchesLoadFailed", "Could not load saved searches."));
    } finally {
      setLoading(false);
    }
  }

  async function removeSavedSearch(savedSearchId: string) {
    setBusyId(savedSearchId);
    setError("");
    setNotice("");
    try {
      const response = await fetch(`${API_URL}/api/hunting/saved-searches/${savedSearchId}`, {
        method: "DELETE",
        credentials: "include",
      });
      if (!response.ok) {
        throw new Error("saved_search_delete_failed");
      }
      setNotice(t("hunting.savedSearchRemoved", "Saved search removed."));
      await loadSavedSearches();
    } catch {
      setError(t("hunting.savedSearchRemoveFailed", "Could not remove the saved search."));
    } finally {
      setBusyId("");
    }
  }

  function openSavedSearch(item: SavedHuntingSearch) {
    sessionStorage.setItem(
      "vantage:hunting-load-saved-search",
      JSON.stringify({
        artifactType: item.artifact_type,
        query: item.query,
        providerKeys: item.provider_keys,
        savedSearchName: item.name,
      }),
    );
    navigate("/hunting");
  }

  return (
    <div className="page-frame space-y-8">
      <PageHeader
        eyebrow={t("hunting.savedSearchesEyebrow", "Analyst")}
        title={t("hunting.savedSearchesTitle", "Saved Searches")}
        description={t(
          "hunting.savedSearchesSubtitle",
          "Review, reopen, and curate saved hunting directives without crowding the main execution surface.",
        )}
        metrics={<PageMetricPill label={`${items.length} ${t("hunting.savedSearchEntries", "entries")}`} dotClassName="bg-primary" tone="primary" />}
      />

      <PageToolbar label={t("hunting.savedSearchesActions", "Saved search actions")}>
        <PageToolbarGroup className="ml-auto">
          <button onClick={() => navigate("/hunting")} className="btn btn-outline">
            <ArrowLeft className="h-4 w-4" />
            {t("hunting.backToHunting", "Back to Hunting")}
          </button>
        </PageToolbarGroup>
      </PageToolbar>

      {(error || notice) && (
        <div className="space-y-3">
          {error && <div className="rounded-sm bg-error/10 px-4 py-3 text-sm text-error">{error}</div>}
          {notice && <div className="rounded-sm bg-primary/10 px-4 py-3 text-sm text-primary">{notice}</div>}
        </div>
      )}

      <div className="surface-section">
        <div className="surface-section-header">
          <h3 className="surface-section-title">{t("hunting.savedSearches", "Saved Searches")}</h3>
          <span className="text-[10px] font-bold uppercase tracking-[0.16em] text-on-surface-variant">
            {items.length} {t("hunting.savedSearchEntries", "entries")}
          </span>
        </div>
        <div className="p-6 space-y-4">
          {loading ? (
            <div className="text-sm text-on-surface-variant">{t("hunting.loadingSavedSearches", "Loading saved searches")}</div>
          ) : items.length === 0 ? (
            <div className="rounded-sm bg-surface-container-low p-8 text-center text-sm text-on-surface-variant">
              {t("hunting.noSavedSearchesBody", "No saved searches are available yet. Save a hunting directive from the main page to build reusable playbooks.")}
            </div>
          ) : (
            items.map((item) => (
              <div key={item._id} className="rounded-sm bg-surface-container-low p-5">
                <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <Bookmark className="h-4 w-4 text-primary" />
                      <div className="text-sm font-bold text-on-surface">{item.name}</div>
                    </div>
                    <div className="text-[11px] text-on-surface-variant">
                      {item.artifact_type} · {item.query}
                    </div>
                    <div className="grid grid-cols-1 gap-2 text-[11px] text-on-surface-variant md:grid-cols-3">
                      <div>{t("hunting.savedSearchUsage", "Used")} {item.use_count}x</div>
                      <div>{t("hunting.createdAtLabel", "Created")}: {formatTimestamp(item.created_at, locale)}</div>
                      <div>{t("hunting.lastUsedAtLabel", "Last used")}: {formatTimestamp(item.last_used_at, locale)}</div>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      className="btn btn-outline"
                      onClick={() => openSavedSearch(item)}
                    >
                      <Search className="h-4 w-4" />
                      {t("hunting.openInHunting", "Open in Hunting")}
                    </button>
                    <button
                      type="button"
                      className="btn btn-outline text-error border-error/40 hover:bg-error/10"
                      onClick={() => void removeSavedSearch(item._id)}
                      disabled={busyId === item._id}
                    >
                      <Trash2 className="h-4 w-4" />
                      {t("hunting.remove", "Remove")}
                    </button>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
