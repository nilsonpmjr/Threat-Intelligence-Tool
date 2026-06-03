import { useEffect, useMemo, useState } from "react";
import { Bookmark, Crosshair, Search, ShieldCheck, StickyNote, History } from "lucide-react";
import { useNavigate } from "react-router-dom";
import API_URL from "../config";
import { PageHeader, PageMetricPill, PageToolbar, PageToolbarGroup } from "../components/page/PageChrome";
import { useLanguage } from "../context/LanguageContext";

interface HuntingProvider {
  key: string;
  name: string;
  version?: string;
  artifactTypes: string[];
  providerScope: string[];
  executionProfile?: {
    mode?: string;
    performanceClass?: string;
    riskClass?: string;
  };
  runtimeStatus?: {
    ready?: boolean;
    state?: string;
    recommendedMode?: string;
    preferredMode?: string;
    activeMode?: string | null;
    availableModes?: string[];
    wiredModes?: string[];
    blocker?: string | null;
  };
}

interface HuntingResultDocument {
  _id?: string;
  provider_key?: string;
  title?: string;
  url?: string;
  platform?: string;
  confidence?: number;
  summary?: string;
  attributes?: Record<string, unknown>;
}

interface HuntingSearchItem {
  provider: HuntingProvider;
  status: string;
  error?: string | null;
  query?: {
    artifact_type?: string;
    query?: string;
  };
  results: HuntingResultDocument[];
}

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

interface RecentHuntingSearch {
  search_id: string;
  artifact_type: string;
  query: string;
  timestamp: string;
  providers: string[];
  result_count: number;
}

interface HuntingCaseNote {
  _id: string;
  search_id: string;
  note: string;
  created_at: string;
}

function formatTimestamp(value?: string | null) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("pt-BR", {
    dateStyle: "short",
    timeStyle: "short",
  }).format(date);
}

function inferArtifactType(query: string, supportedArtifactTypes: string[]) {
  const normalized = query.trim();
  if (!normalized) {
    return supportedArtifactTypes.includes("username") ? "username" : supportedArtifactTypes[0] || "username";
  }
  if ((normalized.startsWith("@") || normalized.includes("/")) && supportedArtifactTypes.includes("account")) {
    return "account";
  }
  if (supportedArtifactTypes.includes("username")) return "username";
  if (supportedArtifactTypes.includes("alias")) return "alias";
  return supportedArtifactTypes[0] || "username";
}

export default function Hunting() {
  const { t } = useLanguage();
  const navigate = useNavigate();
  const [providers, setProviders] = useState<HuntingProvider[]>([]);
  const [artifactType, setArtifactType] = useState("username");
  const [query, setQuery] = useState("");
  const [selectedProviderKeys, setSelectedProviderKeys] = useState<string[]>([]);
  const [items, setItems] = useState<HuntingSearchItem[]>([]);
  const [savedSearches, setSavedSearches] = useState<SavedHuntingSearch[]>([]);
  const [recentSearches, setRecentSearches] = useState<RecentHuntingSearch[]>([]);
  const [notes, setNotes] = useState<HuntingCaseNote[]>([]);
  const [searchId, setSearchId] = useState("");
  const [noteDraft, setNoteDraft] = useState("");
  const [searching, setSearching] = useState(false);
  const [savingSearch, setSavingSearch] = useState(false);
  const [savingNote, setSavingNote] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    let cancelled = false;
    async function bootstrap() {
      try {
        const [providersRes, savedRes, recentRes] = await Promise.all([
          fetch(`${API_URL}/api/hunting/providers`, { credentials: "include" }),
          fetch(`${API_URL}/api/hunting/saved-searches`, { credentials: "include" }),
          fetch(`${API_URL}/api/hunting/recent-searches`, { credentials: "include" }),
        ]);
        if (!providersRes.ok || !savedRes.ok || !recentRes.ok) {
          throw new Error("hunting_bootstrap_failed");
        }
        const providersEnvelope = (await providersRes.json()) as { items: HuntingProvider[] };
        const savedData = (await savedRes.json()) as { items: SavedHuntingSearch[] };
        const recentData = (await recentRes.json()) as { items: RecentHuntingSearch[] };
        if (cancelled) return;
        const nextProviders = providersEnvelope.items || [];
        setProviders(nextProviders);
        setSavedSearches(savedData.items || []);
        setRecentSearches(recentData.items || []);
        setSelectedProviderKeys(nextProviders.map((provider) => provider.key));
      } catch {
        if (!cancelled) {
          setError("Não foi possível carregar a área de hunting.");
        }
      }
    }

    void bootstrap();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!searchId) {
      setNotes([]);
      return;
    }
    void loadCaseNotes(searchId);
  }, [searchId]);

  useEffect(() => {
    const pending = sessionStorage.getItem("vantage:hunting-load-saved-search");
    if (!pending) return;
    sessionStorage.removeItem("vantage:hunting-load-saved-search");
    try {
      const payload = JSON.parse(pending) as {
        artifactType?: string;
        query?: string;
        providerKeys?: string[];
        savedSearchName?: string;
      };
      if (payload.artifactType) setArtifactType(payload.artifactType);
      if (payload.query) setQuery(payload.query);
      if (payload.providerKeys?.length) setSelectedProviderKeys(payload.providerKeys);
      setSearchId("");
      setNotice(
        payload.savedSearchName
          ? `${t("hunting.savedSearchLoaded", "Saved search loaded into the hunting workspace.")}: ${payload.savedSearchName}.`
          : t("hunting.savedSearchLoaded", "Saved search loaded into the hunting workspace."),
      );
    } catch {
      // Ignore malformed session payloads to keep the search surface usable.
    }
  }, [t]);

  const supportedArtifactTypes = useMemo(() => {
    const set = new Set<string>();
    for (const provider of providers) {
      for (const type of provider.artifactTypes || []) {
        set.add(type);
      }
    }
    return Array.from(set);
  }, [providers]);

  const totalResults = useMemo(
    () => items.reduce((acc, item) => acc + item.results.length, 0),
    [items],
  );

  const readyProviderCount = useMemo(
    () => providers.filter((provider) => provider.runtimeStatus?.ready).length,
    [providers],
  );

  const normalizedResults = useMemo(
    () => items.flatMap((item) => item.results),
    [items],
  );
  const searchCoveragePartial = useMemo(
    () => items.some((item) => item.status !== "ok"),
    [items],
  );
  const successfulProviderCount = useMemo(
    () => items.filter((item) => item.status === "ok").length,
    [items],
  );
  const unavailableProviderCount = useMemo(
    () => items.filter((item) => item.status === "error").length,
    [items],
  );
  const unsupportedProviderCount = useMemo(
    () => items.filter((item) => item.status === "unsupported").length,
    [items],
  );
  const noExecutableCoverage = useMemo(
    () => items.length > 0 && totalResults === 0 && successfulProviderCount === 0 && unavailableProviderCount > 0,
    [items.length, totalResults, successfulProviderCount, unavailableProviderCount],
  );
  const unsupportedOnly = useMemo(
    () =>
      items.length > 0 &&
      totalResults === 0 &&
      successfulProviderCount === 0 &&
      unavailableProviderCount === 0 &&
      unsupportedProviderCount > 0,
    [items.length, totalResults, successfulProviderCount, unavailableProviderCount, unsupportedProviderCount],
  );

  async function refreshSideData() {
    const [savedRes, recentRes] = await Promise.all([
      fetch(`${API_URL}/api/hunting/saved-searches`, { credentials: "include" }),
      fetch(`${API_URL}/api/hunting/recent-searches`, { credentials: "include" }),
    ]);
    if (savedRes.ok) {
      const savedData = (await savedRes.json()) as { items: SavedHuntingSearch[] };
      setSavedSearches(savedData.items || []);
    }
    if (recentRes.ok) {
      const recentData = (await recentRes.json()) as { items: RecentHuntingSearch[] };
      setRecentSearches(recentData.items || []);
    }
  }

  async function loadCaseNotes(nextSearchId: string) {
    try {
      const response = await fetch(`${API_URL}/api/hunting/case-notes?search_id=${encodeURIComponent(nextSearchId)}`, {
        credentials: "include",
      });
      if (!response.ok) {
        throw new Error("case_notes_load_failed");
      }
      const data = (await response.json()) as { items: HuntingCaseNote[] };
      setNotes(data.items || []);
    } catch {
      setNotes([]);
    }
  }

  async function loadPersistedSearch(nextSearchId: string) {
    setSearching(true);
    setError("");
    setNotice("");
    try {
      const response = await fetch(`${API_URL}/api/hunting/searches/${encodeURIComponent(nextSearchId)}`, {
        credentials: "include",
      });
      if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.detail || "hunting_search_load_failed");
      }
      const data = (await response.json()) as {
        search_id: string;
        query?: {
          artifact_type?: string;
          query?: string;
        } | null;
        items: HuntingSearchItem[];
        total_results: number;
      };
      setItems(data.items || []);
      setSearchId(data.search_id || nextSearchId);
      setArtifactType(data.query?.artifact_type || artifactType);
      setQuery(data.query?.query || query);
      setNotice(
        t("hunting.searchReloaded", "Persisted search reloaded with") + ` ${data.total_results || 0} ${t("hunting.results", "results")}.`,
      );
    } catch (err) {
      const detail = err instanceof Error ? err.message : "";
      setError(
        detail === "hunting_search_not_found"
          ? t("hunting.searchNotFound", "The selected search could not be reloaded from persistence.")
          : t("hunting.searchReloadFailed", "Could not reload the selected search."),
      );
    } finally {
      setSearching(false);
    }
  }

  async function runSearch(params?: {
    artifactType?: string;
    query?: string;
    providerKeys?: string[];
  }) {
    const nextArtifactType = params?.artifactType || artifactType;
    const nextQuery = params?.query || query;
    const nextProviderKeys = params?.providerKeys || selectedProviderKeys;

    setSearching(true);
    setError("");
    setNotice("");

    try {
      const response = await fetch(`${API_URL}/api/hunting/search`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          artifact_type: nextArtifactType,
          query: nextQuery,
          provider_keys: nextProviderKeys,
        }),
      });

      if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.detail || "hunting_search_failed");
      }

      const data = (await response.json()) as {
        search_id: string;
        items: HuntingSearchItem[];
        total_results: number;
      };
      setItems(data.items || []);
      setSearchId(data.search_id || "");
      setNotice(`Busca concluída com ${data.total_results || 0} resultado(s) normalizado(s).`);
      await refreshSideData();
    } catch (err) {
      const detail = err instanceof Error ? err.message : "";
      if (detail.startsWith("unknown_hunting_provider")) {
        setError("O backend recusou um provider de hunting inesperado.");
      } else if (detail === "provider_runtime_missing") {
        setError("O provider de hunting não está executável neste runtime.");
      } else if (detail === "runtime_declared_but_not_wired") {
        setError("O lane de hunting foi declarado, mas ainda não está conectado à execução real.");
      } else if (detail === "query_required") {
        setError("Informe um artefato antes de executar o hunting.");
      } else if (detail === "artifact_type_required") {
        setError("Não foi possível inferir o tipo do artefato informado.");
      } else if (detail.includes("Too many premium hunting searches")) {
        setError("Muitas buscas de hunting foram executadas em sequência. Aguarde um pouco e tente novamente.");
      } else if (detail) {
        setError(detail);
      } else {
        setError("Não foi possível executar a busca.");
      }
    } finally {
      setSearching(false);
    }
  }

  async function saveCurrentSearch() {
    if (!query.trim()) return;
    setSavingSearch(true);
    setError("");
    setNotice("");
    try {
      const response = await fetch(`${API_URL}/api/hunting/saved-searches`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: `${artifactType}:${query}`,
          artifact_type: artifactType,
          query,
          provider_keys: selectedProviderKeys,
        }),
      });
      if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.detail || "saved_hunting_search_failed");
      }
      setNotice("Busca salva para reutilização.");
      await refreshSideData();
    } catch (err) {
      const detail = err instanceof Error ? err.message : "";
      setError(detail || "Não foi possível salvar a busca.");
    } finally {
      setSavingSearch(false);
    }
  }

  async function deleteSavedSearch(savedSearchId: string) {
    setError("");
    setNotice("");
    try {
      const response = await fetch(`${API_URL}/api/hunting/saved-searches/${savedSearchId}`, {
        method: "DELETE",
        credentials: "include",
      });
      if (!response.ok) {
        throw new Error("saved_hunting_delete_failed");
      }
      setNotice("Busca salva removida.");
      await refreshSideData();
    } catch {
      setError("Não foi possível remover a busca salva.");
    }
  }

  async function saveCaseNote() {
    if (!searchId || !noteDraft.trim()) return;
    setSavingNote(true);
    setError("");
    setNotice("");
    try {
      const response = await fetch(`${API_URL}/api/hunting/case-notes`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          search_id: searchId,
          note: noteDraft,
        }),
      });
      if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.detail || "case_note_save_failed");
      }
      setNoteDraft("");
      setNotice("Nota adicionada à busca atual.");
      await loadCaseNotes(searchId);
    } catch (err) {
      const detail = err instanceof Error ? err.message : "";
      setError(detail || "Não foi possível salvar a nota.");
    } finally {
      setSavingNote(false);
    }
  }
  return (
    <div className="page-frame space-y-8">
      <PageHeader
        eyebrow={t("hunting.eyebrow", "Analyst")}
        title={t("hunting.title", "Proactive Threat Hunting")}
        description={t("hunting.subtitle", "Execute buscas por usernames, aliases, e-mails e contas com buscas salvas, comparação por fonte e notas analíticas por pesquisa.")}
        metrics={
          <>
            <PageMetricPill label={`${readyProviderCount}/${providers.length} ${t("hunting.runtimeReady", "hunting lanes ready")}`} dotClassName="bg-primary" tone="primary" />
            <PageMetricPill label={`${savedSearches.length} ${t("hunting.savedSearches", "saved searches")}`} dotClassName="bg-secondary" />
            <PageMetricPill label={`${notes.length} ${t("hunting.notes", "notes")}`} dotClassName="bg-secondary" />
          </>
        }
      />

      <PageToolbar label={t("hunting.actions", "Hunting actions")}>
        <PageToolbarGroup className="ml-auto">
          <button
            onClick={() => navigate("/hunting/saved-searches")}
            className="btn btn-outline"
          >
            <Bookmark className="h-4 w-4" />
            {t("hunting.openSavedSearches", "Saved Searches")}
          </button>
          <button
            onClick={() => void runSearch()}
            disabled={!query.trim() || searching}
            className="btn btn-primary"
          >
            <Search className="h-4 w-4" />
            {searching ? t("hunting.executing", "Executing") : t("hunting.execute", "Execute Hunting")}
          </button>
          <button
            onClick={() => void saveCurrentSearch()}
            disabled={!query.trim() || savingSearch}
            className="btn btn-outline"
          >
            <Bookmark className="h-4 w-4" />
            {savingSearch ? t("hunting.saving", "Saving") : t("hunting.saveSearch", "Save Search")}
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
          <div className="col-span-12 space-y-6">
            <div className="surface-section p-6">
              <h3 className="text-xs font-bold uppercase tracking-widest text-on-surface mb-4 flex items-center gap-2">
                <Crosshair className="w-4 h-4 text-primary" />
                {t("hunting.searchDirective", "Search Directive")}
              </h3>
              <div className="space-y-5">
                <label className="block space-y-2">
                  <div className="text-[10px] font-bold uppercase tracking-[0.16em] text-outline">
                    {t("hunting.artifactLabel", "Artifact")}
                  </div>
                  <input
                    value={query}
                    onChange={(event) => {
                      const nextQuery = event.target.value;
                      setQuery(nextQuery);
                      setArtifactType(inferArtifactType(nextQuery, supportedArtifactTypes));
                    }}
                    placeholder={t("hunting.queryPlaceholder", "analyst_01, person@example.com, johndoe")}
                    className="w-full border-0 border-b-2 border-outline bg-surface-container-high px-0 py-3 text-sm text-on-surface outline-none focus:border-primary"
                  />
                </label>
                <div className="rounded-sm bg-surface-container-low px-4 py-4 text-sm text-on-surface">
                  {t(
                    "hunting.artifactOnlyBody",
                    "A busca opera sobre o artefato informado e resolve internamente as rotas de hunting disponíveis, sem expor fontes na superfície principal.",
                  )}
                </div>
              </div>
            </div>
            <div className="surface-section">
              <div className="surface-section-header">
                <h3 className="text-xs font-bold uppercase tracking-widest text-on-surface">
                  {t("hunting.normalizedResults", "Normalized Results")}
                </h3>
                <span className="text-[10px] font-bold uppercase tracking-[0.16em] text-on-surface-variant">
                  search id {searchId || t("hunting.pending", "pending")}
                </span>
              </div>
              <div className="p-6 space-y-6">
                {items.length === 0 ? (
                  <div className="rounded-sm bg-surface-container-low p-8 text-center text-sm text-on-surface-variant">
                    {t("hunting.noSearchExecuted", "Nenhuma busca executada nesta sessão.")}
                  </div>
                ) : (
                  <>
                    {noExecutableCoverage ? (
                      <div className="rounded-sm bg-error/10 px-4 py-3 text-sm text-error">
                        {t(
                          "hunting.noExecutableCoverage",
                          "Nenhum lane de hunting executável estava disponível nesta busca. Revise o runtime e a toolchain antes de tratar este artefato como sem achados.",
                        )}
                      </div>
                    ) : unsupportedOnly ? (
                      <div className="rounded-sm bg-warning/10 px-4 py-3 text-sm text-warning">
                        {t(
                          "hunting.unsupportedArtifactCoverage",
                          "O artefato informado não é suportado pelas trilhas de hunting atualmente conectadas.",
                        )}
                      </div>
                    ) : searchCoveragePartial ? (
                      <div className="rounded-sm bg-warning/10 px-4 py-3 text-sm text-warning">
                        {t(
                          "hunting.partialCoverage",
                          "A busca retornou cobertura parcial nesta execução. Alguns lanes de hunting não estavam disponíveis, mas os resultados normalizados válidos foram preservados.",
                        )}
                      </div>
                    ) : null}
                    {normalizedResults.length === 0 ? (
                      <div className="rounded-sm bg-surface-container-low p-8 text-center text-sm text-on-surface-variant">
                        {t("hunting.noNormalizedResults", "Nenhum resultado normalizado foi encontrado para este artefato.")}
                      </div>
                    ) : (
                      <div className="grid grid-cols-1 gap-4">
                        {normalizedResults.map((result, index) => (
                          <div key={`${result.url || result.title || "result"}-${index}`} className="rounded-sm bg-surface-container-low p-5">
                            <div className="flex flex-col gap-2 lg:flex-row lg:items-center lg:justify-between">
                              <div>
                                <div className="text-sm font-bold text-on-surface">
                                  {result.title || String(result.attributes?.handle || result.platform || "Match")}
                                </div>
                                <div className="mt-1 text-[11px] text-on-surface-variant">
                                  {result.platform || String(result.attributes?.site || "Platform not informed")}
                                </div>
                              </div>
                              <span className="inline-flex items-center whitespace-nowrap rounded-sm bg-primary/10 px-2 py-1 text-[10px] font-bold uppercase tracking-[0.16em] text-primary">
                                {t("hunting.confidenceLabel", "Confidence")} {Math.round((result.confidence || 0) * 100)}%
                              </span>
                            </div>
                            <div className="mt-3 text-xs text-on-surface-variant">
                              {result.summary || t("hunting.noResultSummary", "No summary provided for this result.")}
                            </div>
                            {result.url && (
                              <a
                                href={result.url}
                                target="_blank"
                                rel="noreferrer"
                                className="mt-3 inline-flex text-xs font-bold uppercase tracking-[0.16em] text-primary hover:underline"
                              >
                                {t("hunting.openProfile", "Open profile")}
                              </a>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </>
                )}
              </div>
            </div>
          </div>
        </div>

        <div className="page-side-rail-right space-y-6">
          <div className="surface-section">
            <div className="surface-section-header">
              <h3 className="surface-section-title">{t("hunting.recentSearches", "Recent Searches")}</h3>
            </div>
            <div className="p-6 space-y-4">
              {recentSearches.length === 0 ? (
                <div className="text-sm text-on-surface-variant">
                  {t("hunting.noRecentSearches", "Nenhuma busca recente persistida.")}
                </div>
              ) : (
                recentSearches.map((search) => (
                  <button
                    key={search.search_id}
                    type="button"
                    onClick={() => {
                      setSelectedProviderKeys(search.providers.length ? search.providers : selectedProviderKeys);
                      void loadPersistedSearch(search.search_id);
                    }}
                    className="w-full rounded-sm bg-surface-container-low p-4 text-left"
                  >
                    <div className="flex items-center justify-between gap-3">
                      <div className="text-sm font-bold text-on-surface">{search.query}</div>
                      <span className="text-[10px] font-bold uppercase tracking-[0.16em] text-primary">
                        {search.result_count} {t("hunting.results", "results")}
                      </span>
                    </div>
                    <div className="mt-2 text-[11px] text-on-surface-variant">
                      {search.artifact_type} · {formatTimestamp(search.timestamp)}
                    </div>
                  </button>
                ))
              )}
            </div>
          </div>

          <div className="surface-section">
            <div className="surface-section-header">
              <h3 className="surface-section-title">{t("hunting.savedSearches", "Saved Searches")}</h3>
            </div>
            <div className="p-6 space-y-4">
              {savedSearches.length === 0 ? (
                <div className="text-sm text-on-surface-variant">{t("hunting.noSavedSearches", "Nenhuma busca salva.")}</div>
              ) : (
                savedSearches.map((saved) => (
                  <div key={saved._id} className="rounded-sm bg-surface-container-low px-4 py-4">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="text-sm font-bold text-on-surface">{saved.name}</div>
                        <div className="mt-1 text-[11px] text-on-surface-variant">
                          {saved.artifact_type} · {saved.query}
                        </div>
                      </div>
                      <button
                        type="button"
                        className="text-[10px] font-bold uppercase tracking-[0.16em] text-error"
                        onClick={() => void deleteSavedSearch(saved._id)}
                      >
                        {t("hunting.remove", "Remove")}
                      </button>
                    </div>
                    <div className="mt-3 flex items-center justify-between text-[11px] text-on-surface-variant">
                      <span>Used {saved.use_count}x</span>
                      <span>{formatTimestamp(saved.last_used_at || saved.created_at)}</span>
                    </div>
                  </div>
                ))
              )}
              <div className="rounded-sm bg-surface-container-low px-4 py-4 text-sm text-on-surface">
                {t("hunting.totalNormalizedResults", "Total normalized results")}: <strong>{totalResults}</strong>
              </div>
            </div>
          </div>

          <div className="surface-section">
            <div className="surface-section-header">
              <h3 className="surface-section-title">{t("hunting.notes", "Notes")}</h3>
            </div>
            <div className="p-6 space-y-4">
              <div className="text-[10px] font-bold uppercase tracking-[0.16em] text-outline">
                {t("hunting.activeSearch", "Active search")}
              </div>
              <div className="rounded-sm bg-surface-container-low px-4 py-3 text-sm text-on-surface">
                {searchId || t("hunting.noSearchSelected", "No search selected yet")}
              </div>
              <label className="block space-y-2">
                <div className="inline-flex items-center gap-2 text-[10px] font-bold uppercase tracking-[0.16em] text-outline">
                  <StickyNote className="h-4 w-4" />
                  {t("hunting.analystNote", "Analyst note")}
                </div>
                <textarea
                  value={noteDraft}
                  onChange={(event) => setNoteDraft(event.target.value)}
                  className="min-h-28 w-full rounded-sm border border-outline-variant/15 bg-surface-container-low px-4 py-3 text-sm text-on-surface outline-none"
                  placeholder={t("hunting.analystNotePlaceholder", "Capture rationale, escalation context or next analyst step.")}
                />
              </label>
              <button
                type="button"
                onClick={() => void saveCaseNote()}
                disabled={!searchId || !noteDraft.trim() || savingNote}
                className="btn btn-outline w-full"
              >
                {savingNote ? t("hunting.savingNote", "Saving note") : t("hunting.saveNote", "Save note")}
              </button>
              <div className="space-y-3">
                {notes.length === 0 ? (
                  <div className="text-sm text-on-surface-variant">{t("hunting.noNotes", "Nenhuma nota para esta busca.")}</div>
                ) : (
                  notes.map((note) => (
                    <div key={note._id} className="rounded-sm bg-surface-container-low px-4 py-4">
                      <div className="text-sm text-on-surface">{note.note}</div>
                      <div className="mt-2 text-[11px] text-on-surface-variant">{formatTimestamp(note.created_at)}</div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}
