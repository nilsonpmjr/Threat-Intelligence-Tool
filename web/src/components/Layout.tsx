import { useState, useRef, useEffect, useMemo, type KeyboardEvent as ReactKeyboardEvent } from "react";
import { Outlet, NavLink, Link, useLocation, useNavigate } from "react-router-dom";
import {
  Home,
  Rss,
  Radar,
  Eye,
  ShieldAlert,
  ClipboardList,
  LayoutDashboard,
  Settings,
  User,
  Zap,
  Bell,
  History,
  HelpCircle,
  Activity,
  LogOut,
  Menu,
  ChevronLeft,
  Key,
  Search,
  Terminal,
} from "lucide-react";
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import { useAuth } from "../context/AuthContext";
import { useLanguage } from "../context/LanguageContext";
import API_URL from "../config";
import { canAccessPath } from "../lib/access";
import { useExtensionEnabled } from "../hooks/useExtensionEnabled";
import { getShortcutSequenceMap, SHORTCUT_SEQUENCE_TIMEOUT_MS } from "../lib/shortcuts";
import {
  buildNavigationSearchEntries,
  filterNavigationSearchEntries,
  getNavigationSearchGroupLabel,
  resolveTopbarContext,
  type NavigationSearchEntry,
} from "../lib/navigationSearch";
import KeyboardShortcutsModal from "./help/KeyboardShortcutsModal";
import GlobalScanLauncher from "./scan/GlobalScanLauncher";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

const rootNavItems = [
  { path: "/", labelKey: "layout.nav.home", fallback: "Home", icon: Home },
  { path: "/feed", labelKey: "layout.nav.feed", fallback: "Feed", icon: Rss },
  { path: "/recon", labelKey: "layout.nav.recon", fallback: "Recon", icon: Radar },
  { path: "/watchlist", labelKey: "layout.nav.watchlist", fallback: "Watchlist", icon: Eye },
  { path: "/socc", labelKey: "socc.nav", fallback: "SOC Copilot", icon: Terminal },
  { path: "/shift-handoff", labelKey: "layout.nav.shiftHandoff", fallback: "Shift Handoff", icon: ClipboardList },
  { path: "/dashboard", labelKey: "layout.nav.dashboard", fallback: "Dashboard", icon: LayoutDashboard },
];

export default function Layout() {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const { language, t } = useLanguage();
  const [isProfileOpen, setIsProfileOpen] = useState(false);
  const [isHelpOpen, setIsHelpOpen] = useState(false);
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);
  const [isShortcutsOpen, setIsShortcutsOpen] = useState(false);
  const [isScanLauncherOpen, setIsScanLauncherOpen] = useState(false);
  const [showApiKeyToast, setShowApiKeyToast] = useState(false);
  const [topbarSearchQuery, setTopbarSearchQuery] = useState("");
  const [isTopbarSearchOpen, setIsTopbarSearchOpen] = useState(false);
  const [highlightedSearchIndex, setHighlightedSearchIndex] = useState(0);
  const profileRef = useRef<HTMLDivElement>(null);
  const helpRef = useRef<HTMLDivElement>(null);
  const topbarSearchRef = useRef<HTMLDivElement>(null);
  const topbarSearchInputRef = useRef<HTMLInputElement>(null);
  const shortcutSequenceRef = useRef<{ prefix: string | null; expiresAt: number }>({
    prefix: null,
    expiresAt: 0,
  });
  const canAccessSettings = canAccessPath(user, "/settings");
  const apiKeyToastDismissKey = `vantage.api-keys-toast.dismissed.${user?.username || "anon"}`;
  const languageLabel = language === "en" ? "EN" : language === "es" ? "ES" : "PT";
  const lastRootPathKey = "vantage.sidebar.last-root-path";
  const isSettingsContext = location.pathname.startsWith("/settings");
  const isProfileContext = location.pathname === "/profile";
  const profileTab = useMemo(() => {
    const currentTab = new URLSearchParams(location.search).get("tab");
    if (
      currentTab === "preferences" ||
      currentTab === "external_api_keys" ||
      currentTab === "audit_logs"
    ) {
      return currentTab;
    }
    return "identity";
  }, [location.search]);

  // SOC Copilot is a managed extension — keep it out of the sidebar while
  // the extension is disabled (stopped/not installed) so we never link to a
  // surface the user can't actually use.
  const { enabled: isSoccEnabled } = useExtensionEnabled("socc");
  const visibleNavItems = useMemo(
    () => rootNavItems.filter((item) => item.path !== "/socc" || isSoccEnabled),
    [isSoccEnabled],
  );

  const settingsNavItems = useMemo(
    () => [
      {
        path: "/settings/extensions",
        label: t("settings.extensions", "Extensions Catalog"),
        icon: Settings,
      },
      {
        path: "/settings/threat-ingestion",
        label: t("settings.threatIngestion", "Threat Ingestion & SMTP"),
        icon: Rss,
      },
      {
        path: "/settings/system-health",
        label: t("settings.systemHealth", "System Health"),
        icon: Activity,
      },
      {
        path: "/settings/users-roles",
        label: t("settings.usersRoles", "Users & Roles"),
        icon: User,
      },
      {
        path: "/settings/security-policies",
        label: t("settings.securityPolicies", "Security Policies"),
        icon: ShieldAlert,
      },
      {
        path: "/settings/api-credentials",
        label: t("settings.apiCredentials", "Platform Credentials"),
        icon: Key,
      },
    ],
    [t],
  );

  const profileNavItems = useMemo(
    () => [
      {
        path: "/profile",
        label: t("profile.tabs.identity", "Identity"),
        icon: User,
        active: profileTab === "identity",
      },
      {
        path: "/profile?tab=preferences",
        label: t("profile.tabs.preferences", "Preferences"),
        icon: Bell,
        active: profileTab === "preferences",
      },
      {
        path: "/profile?tab=external_api_keys",
        label: t("profile.tabs.externalApiKeys", "External API Keys"),
        icon: Key,
        active: profileTab === "external_api_keys",
      },
      {
        path: "/profile?tab=audit_logs",
        label: t("profile.tabs.auditLogs", "Audit Logs"),
        icon: History,
        active: profileTab === "audit_logs",
      },
    ],
    [profileTab, t],
  );

  const contextualNav = isSettingsContext
    ? {
        title: t("layout.nav.settings", "Settings"),
        items: settingsNavItems.map((item) => ({
          ...item,
          active: location.pathname === item.path,
        })),
      }
    : isProfileContext
      ? {
          title: t("layout.topbar.profile", "Profile"),
          items: profileNavItems,
        }
      : null;
  const contextualBackPath = sessionStorage.getItem(lastRootPathKey) || "/";
  const profileAvatarSrc =
    user?.avatar_base64 ||
    `https://api.dicebear.com/7.x/avataaars/svg?seed=${encodeURIComponent(
      user?.username || "operator",
    )}`;
  const profileAvatarObjectClass = user?.avatar_fit === "contain" ? "object-contain" : "object-cover";
  const navigationSearchEntries = useMemo(
    () => buildNavigationSearchEntries(t, canAccessSettings),
    [canAccessSettings, t],
  );
  const topbarContext = useMemo(
    () => resolveTopbarContext(location.pathname, location.search, t),
    [location.pathname, location.search, t],
  );
  const visibleNavigationResults = useMemo(
    () => filterNavigationSearchEntries(navigationSearchEntries, topbarSearchQuery),
    [navigationSearchEntries, topbarSearchQuery],
  );
  const groupedNavigationResults = useMemo(() => {
    const grouped = new Map<string, NavigationSearchEntry[]>();
    for (const entry of visibleNavigationResults) {
      if (!grouped.has(entry.group)) {
        grouped.set(entry.group, []);
      }
      grouped.get(entry.group)?.push(entry);
    }
    return grouped;
  }, [visibleNavigationResults]);

  const handleHistoryClick = () => {
    const lastSearch = localStorage.getItem("lastSearch");
    if (lastSearch) {
      navigate(`/analyze/${encodeURIComponent(lastSearch)}`);
      return;
    }
    navigate("/dashboard?view=history");
  };

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (profileRef.current && !profileRef.current.contains(event.target as Node)) {
        setIsProfileOpen(false);
      }
      if (helpRef.current && !helpRef.current.contains(event.target as Node)) {
        setIsHelpOpen(false);
      }
      if (topbarSearchRef.current && !topbarSearchRef.current.contains(event.target as Node)) {
        setIsTopbarSearchOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  useEffect(() => {
    setHighlightedSearchIndex(0);
  }, [topbarSearchQuery, isTopbarSearchOpen]);

  useEffect(() => {
    setIsTopbarSearchOpen(false);
    setTopbarSearchQuery("");
  }, [location.pathname, location.search]);

  useEffect(() => {
    function handleKeydown(e: KeyboardEvent) {
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || (e.target as HTMLElement)?.isContentEditable) return;

      const lowerKey = e.key.toLowerCase();
      const isModifier = e.metaKey || e.ctrlKey;

      if (isModifier && lowerKey === "/") {
        e.preventDefault();
        setIsShortcutsOpen((prev: boolean) => !prev);
        shortcutSequenceRef.current = { prefix: null, expiresAt: 0 };
        return;
      }

      if (isModifier && lowerKey === "l") {
        e.preventDefault();
        if (location.pathname !== "/") {
          setIsScanLauncherOpen(true);
        } else {
          sessionStorage.setItem("vantage.pending-focus-search", "true");
          window.dispatchEvent(new Event("vantage:focus-search"));
        }
        shortcutSequenceRef.current = { prefix: null, expiresAt: 0 };
        return;
      }

      if (isModifier && lowerKey === "e") {
        e.preventDefault();
        window.dispatchEvent(new Event("vantage:export-current-view"));
        shortcutSequenceRef.current = { prefix: null, expiresAt: 0 };
        return;
      }

      if (e.key === "?" && !e.ctrlKey && !e.metaKey) {
        e.preventDefault();
        setIsShortcutsOpen((prev: boolean) => !prev);
        shortcutSequenceRef.current = { prefix: null, expiresAt: 0 };
        return;
      }

      const now = Date.now();
      const sequenceMap = getShortcutSequenceMap(canAccessSettings);

      if (shortcutSequenceRef.current.prefix === "g" && now <= shortcutSequenceRef.current.expiresAt) {
        const nextPath = sequenceMap[lowerKey];
        if (nextPath) {
          e.preventDefault();
          navigate(nextPath);
          shortcutSequenceRef.current = { prefix: null, expiresAt: 0 };
          return;
        }
      }

      if (!e.metaKey && !e.ctrlKey && !e.altKey && lowerKey === "g") {
        shortcutSequenceRef.current = { prefix: "g", expiresAt: now + SHORTCUT_SEQUENCE_TIMEOUT_MS };
        return;
      }

      shortcutSequenceRef.current = { prefix: null, expiresAt: 0 };
    }
    document.addEventListener("keydown", handleKeydown);
    return () => document.removeEventListener("keydown", handleKeydown);
  }, [canAccessSettings, location.pathname, navigate]);

  useEffect(() => {
    if (isSettingsContext || isProfileContext) {
      return;
    }
    sessionStorage.setItem(lastRootPathKey, `${location.pathname}${location.search}`);
  }, [isProfileContext, isSettingsContext, lastRootPathKey, location.pathname, location.search]);

  useEffect(() => {
    if (!user) return;
    if (sessionStorage.getItem(apiKeyToastDismissKey) === "true") return;

    let cancelled = false;

    async function checkThirdPartyKeys() {
      try {
        const response = await fetch(`${API_URL}/api/users/me/third-party-keys`, {
          credentials: "include",
        });
        if (!response.ok) return;
        const payload = (await response.json()) as Record<string, { configured?: boolean }>;
        const hasConfiguredService = Object.values(payload).some((item) => item?.configured);
        if (!cancelled && !hasConfiguredService) {
          setShowApiKeyToast(true);
        }
      } catch {
        // Ignore onboarding toast failures and keep the shell stable.
      }
    }

    void checkThirdPartyKeys();
    return () => {
      cancelled = true;
    };
  }, [apiKeyToastDismissKey, user]);

  const dismissApiKeyToast = () => {
    sessionStorage.setItem(apiKeyToastDismissKey, "true");
    setShowApiKeyToast(false);
  };

  const handleNavigationSearchSelect = (entry: NavigationSearchEntry) => {
    setIsTopbarSearchOpen(false);
    setTopbarSearchQuery("");

    if (entry.kind === "route") {
      navigate(entry.href);
      return;
    }

    if (entry.actionId === "open-shortcuts") {
      setIsShortcutsOpen(true);
      return;
    }
  };

  const handleTopbarSearchKeyDown = (event: ReactKeyboardEvent<HTMLInputElement>) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      if (!isTopbarSearchOpen) {
        setIsTopbarSearchOpen(true);
        setHighlightedSearchIndex(0);
        return;
      }
      setHighlightedSearchIndex((current) =>
        visibleNavigationResults.length
          ? (current + 1) % visibleNavigationResults.length
          : 0,
      );
      return;
    }

    if (event.key === "ArrowUp") {
      event.preventDefault();
      if (!isTopbarSearchOpen) {
        setIsTopbarSearchOpen(true);
        setHighlightedSearchIndex(Math.max(visibleNavigationResults.length - 1, 0));
        return;
      }
      setHighlightedSearchIndex((current) =>
        visibleNavigationResults.length
          ? (current - 1 + visibleNavigationResults.length) % visibleNavigationResults.length
          : 0,
      );
      return;
    }

    if (event.key === "Enter") {
      if (!visibleNavigationResults.length) return;
      event.preventDefault();
      handleNavigationSearchSelect(visibleNavigationResults[highlightedSearchIndex] || visibleNavigationResults[0]);
      return;
    }

    if (event.key === "Escape") {
      event.preventDefault();
      setIsTopbarSearchOpen(false);
      topbarSearchInputRef.current?.blur();
    }
  };

  return (
    <div className="min-h-screen bg-background flex">
      <aside className={cn("fixed left-0 top-0 h-screen bg-inverse-surface flex flex-col z-50 transition-all duration-300", isSidebarCollapsed ? "w-20" : "w-64")}>
        <div className={cn("py-8 flex items-center", isSidebarCollapsed ? "px-0 justify-center" : "px-6")}>
          <div className={cn("flex items-center", isSidebarCollapsed ? "justify-center" : "w-full")}>
            <div className={cn("sidebar-brand-lockup", isSidebarCollapsed && "is-collapsed")}>
              <img
                src="/branding/vantage/app-icon-dark.svg"
                alt="VANTAGE"
                className="sidebar-brand-compact"
              />
              <div className="sidebar-brand-full-shell" aria-hidden={isSidebarCollapsed}>
                <img
                  src="/branding/vantage/logo-dark.png"
                  alt="VANTAGE"
                  className="sidebar-brand-full"
                />
              </div>
            </div>
          </div>
        </div>

        <nav className="flex-1 px-3 space-y-1 overflow-y-auto overflow-x-hidden">
          {contextualNav ? (
            <>
              <button
                type="button"
                title={isSidebarCollapsed ? t("layout.context.back", "Back to workspace") : undefined}
                onClick={() => navigate(contextualBackPath)}
                className={cn(
                  "flex w-full items-center gap-3 py-3 text-sm font-medium text-outline transition-colors rounded-sm hover:text-white hover:bg-white/5 border-l-4 border-transparent",
                  isSidebarCollapsed ? "justify-center px-0" : "px-4",
                )}
              >
                <ChevronLeft className="w-4 h-4 shrink-0" />
                {!isSidebarCollapsed && (
                  <span className="whitespace-nowrap">
                    {t("layout.context.back", "Back to workspace")}
                  </span>
                )}
              </button>

              {!isSidebarCollapsed ? (
                <div className="pt-4 pb-2 px-4 text-[10px] font-bold text-outline uppercase tracking-widest whitespace-nowrap border-t border-white/5 mt-4">
                  {contextualNav.title}
                </div>
              ) : (
                <div className="pt-4 pb-2 border-t border-white/5 mt-4"></div>
              )}

              {contextualNav.items.map((item) => (
                <button
                  key={item.path}
                  type="button"
                  title={isSidebarCollapsed ? item.label : undefined}
                  onClick={() => navigate(item.path)}
                  className={cn(
                    "flex w-full items-center gap-3 py-3 text-sm font-medium transition-colors rounded-sm",
                    item.active
                      ? "bg-primary/10 text-white border-l-4 border-primary"
                      : "text-outline hover:text-white hover:bg-white/5 border-l-4 border-transparent",
                    isSidebarCollapsed ? "justify-center px-0" : "px-4",
                  )}
                >
                  <item.icon className="w-4 h-4 shrink-0" />
                  {!isSidebarCollapsed && <span className="whitespace-nowrap">{item.label}</span>}
                </button>
              ))}
            </>
          ) : (
            <>
              {visibleNavItems.map((item) => {
                const isActive =
                  location.pathname === item.path || location.pathname.startsWith(`${item.path}/`);
                return (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    title={isSidebarCollapsed ? t(item.labelKey, item.fallback) : undefined}
                    className={cn(
                      "flex items-center gap-3 py-3 text-sm font-medium transition-colors rounded-sm",
                      isActive
                        ? "bg-primary/10 text-white border-l-4 border-primary"
                        : "text-outline hover:text-white hover:bg-white/5 border-l-4 border-transparent",
                      isSidebarCollapsed ? "justify-center px-0" : "px-4"
                    )}
                  >
                    <item.icon className="w-4 h-4 shrink-0" />
                    {!isSidebarCollapsed && <span className="whitespace-nowrap">{t(item.labelKey, item.fallback)}</span>}
                  </NavLink>
                );
              })}

              {!isSidebarCollapsed ? (
                <div className="pt-4 pb-2 px-4 text-[10px] font-bold text-outline uppercase tracking-widest whitespace-nowrap">
                  {t("layout.sections.administration", "Administration")}
                </div>
              ) : (
                <div className="pt-4 pb-2 border-t border-white/5 mt-4"></div>
              )}
              {canAccessSettings && (
                <NavLink
                  to="/settings"
                  title={isSidebarCollapsed ? t("layout.nav.settings", "Settings") : undefined}
                  className={cn(
                    "flex items-center gap-3 py-3 text-sm font-medium transition-colors rounded-sm",
                    location.pathname.startsWith("/settings")
                      ? "bg-primary/10 text-white border-l-4 border-primary"
                      : "text-outline hover:text-white hover:bg-white/5 border-l-4 border-transparent",
                    isSidebarCollapsed ? "justify-center px-0" : "px-4"
                  )}
                >
                  <Settings className="w-4 h-4 shrink-0" />
                  {!isSidebarCollapsed && <span className="whitespace-nowrap">{t("layout.nav.settings", "Settings")}</span>}
                </NavLink>
              )}
            </>
          )}
        </nav>

        <div className="p-4 border-t border-white/5 space-y-2">
          <button
            type="button"
            onClick={() => setIsScanLauncherOpen(true)}
            title={isSidebarCollapsed ? t("layout.topbar.startScan", "Start Scan") : undefined}
            className={cn(
              "btn btn-primary w-full",
              isSidebarCollapsed && "px-0"
            )}
          >
            <Zap className="w-4 h-4 shrink-0" />
            {!isSidebarCollapsed && <span className="whitespace-nowrap">{t("layout.topbar.startScan", "Start Scan")}</span>}
          </button>
        </div>
      </aside>

      <div className={cn("flex-1 flex flex-col min-h-screen transition-all duration-300", isSidebarCollapsed ? "ml-20" : "ml-64")}>
        <header className="h-14 bg-surface-container-high border-b border-outline-variant/20 flex items-center justify-between px-6 sticky top-0 z-40">
          <div className="flex min-w-0 items-center gap-4">
            <button 
              onClick={() => setIsSidebarCollapsed(!isSidebarCollapsed)}
              className="p-1.5 text-on-surface-variant hover:bg-surface-container-highest rounded transition-colors"
            >
              <Menu className="w-5 h-5" />
            </button>
            <div className="topbar-context-eyebrow">
              <span className="topbar-context-eyebrow-accent">{topbarContext.section}</span>
              <span className="text-outline">/</span>
              <span>{topbarContext.label}</span>
            </div>
          </div>
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-3">
              <div className="topbar-nav-search" ref={topbarSearchRef}>
                <Search className="topbar-nav-search-icon" />
                <input
                  ref={topbarSearchInputRef}
                  type="text"
                  value={topbarSearchQuery}
                  onFocus={() => setIsTopbarSearchOpen(true)}
                  onChange={(event) => {
                    setTopbarSearchQuery(event.target.value);
                    setIsTopbarSearchOpen(true);
                  }}
                  onKeyDown={handleTopbarSearchKeyDown}
                  placeholder={t("layout.topbar.navSearchPlaceholder", "Go to page, settings, docs...")}
                  aria-label={t("layout.topbar.navSearchLabel", "Navigation search")}
                  className="topbar-nav-search-input"
                />
                {isTopbarSearchOpen && (
                  <div className="topbar-nav-search-dropdown">
                    {visibleNavigationResults.length ? (
                      <div className="max-h-[28rem] overflow-y-auto p-1">
                        {Array.from(groupedNavigationResults.entries()).map(([group, entries]) => (
                          <div key={group} className="topbar-nav-search-group">
                            <div className="topbar-nav-search-group-label">
                              {getNavigationSearchGroupLabel(group as NavigationSearchEntry["group"], t)}
                            </div>
                            <div className="space-y-1">
                              {entries.map((entry) => {
                                const entryIndex = visibleNavigationResults.findIndex((item) => item.id === entry.id);
                                const active = entryIndex === highlightedSearchIndex;
                                return (
                                  <button
                                    key={entry.id}
                                    type="button"
                                    className={cn(
                                      "topbar-nav-search-item",
                                      active && "topbar-nav-search-item-active",
                                    )}
                                    onMouseEnter={() => setHighlightedSearchIndex(entryIndex)}
                                    onClick={() => handleNavigationSearchSelect(entry)}
                                  >
                                    <span className="topbar-nav-search-item-label">{entry.label}</span>
                                    <span className="topbar-nav-search-item-meta">{entry.section}</span>
                                  </button>
                                );
                              })}
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="topbar-nav-search-empty">
                        {t("layout.topbar.navSearchEmpty", "No navigation matches for this query.")}
                      </div>
                    )}
                  </div>
                )}
              </div>
              <div className="summary-pill-muted">{languageLabel}</div>
              <Link to="/notifications" className="p-1.5 text-on-surface-variant hover:bg-surface-container-highest rounded transition-colors relative">
                <Bell className="w-4 h-4" />
                <span className="absolute top-1 right-1 w-1.5 h-1.5 bg-error rounded-full border border-surface-container-high"></span>
              </Link>
              <button onClick={handleHistoryClick} className="p-1.5 text-on-surface-variant hover:bg-surface-container-highest rounded transition-colors">
                <History className="w-4 h-4" />
              </button>
              <div className="relative" ref={helpRef}>
                <button 
                  onClick={() => setIsHelpOpen(!isHelpOpen)}
                  className={cn(
                    "p-1.5 rounded transition-colors",
                    isHelpOpen ? "bg-surface-container-highest text-on-surface" : "text-on-surface-variant hover:bg-surface-container-highest"
                  )}
                >
                  <HelpCircle className="w-4 h-4" />
                </button>

                {isHelpOpen && (
                  <div className="absolute right-0 mt-2 w-56 bg-surface-container-high border border-outline-variant/20 rounded-md shadow-lg py-1 z-50">
                    <div className="px-4 py-2 border-b border-outline-variant/20">
                      <p className="text-xs font-bold text-on-surface uppercase tracking-widest">{t("layout.topbar.supportResources", "Support & Resources")}</p>
                    </div>
                    <button
                      className="w-full flex items-center gap-2 px-4 py-2 text-sm text-on-surface hover:bg-surface-container-highest hover:text-white transition-colors text-left"
                      onClick={() => { setIsHelpOpen(false); navigate("/help/docs"); }}
                    >
                      {t("layout.topbar.documentation", "Documentation")}
                    </button>
                    <button
                      className="w-full flex items-center gap-2 px-4 py-2 text-sm text-on-surface hover:bg-surface-container-highest hover:text-white transition-colors text-left"
                      onClick={() => { setIsHelpOpen(false); navigate("/help/shortcuts"); }}
                    >
                      {t("layout.topbar.keyboardShortcuts", "Keyboard Shortcuts")}
                    </button>
                    <button
                      className="w-full flex items-center gap-2 px-4 py-2 text-sm text-on-surface hover:bg-surface-container-highest hover:text-white transition-colors text-left"
                      onClick={() => { setIsHelpOpen(false); navigate("/help/api"); }}
                    >
                      {t("layout.topbar.apiReference", "API Reference")}
                    </button>
                    <div className="border-t border-outline-variant/20 my-1"></div>
                    <button
                      className="w-full flex items-center gap-2 px-4 py-2 text-sm text-on-surface hover:bg-surface-container-highest hover:text-white transition-colors text-left"
                      onClick={() => { setIsHelpOpen(false); navigate("/help/support"); }}
                    >
                      {t("layout.topbar.contactSupport", "Contact Support")}
                    </button>
                  </div>
                )}
              </div>
              <div className="relative ml-2" ref={profileRef}>
                <button 
                  onClick={() => setIsProfileOpen(!isProfileOpen)}
                  className="w-8 h-8 rounded bg-primary/20 flex items-center justify-center overflow-hidden border border-outline-variant/20 hover:ring-2 hover:ring-primary transition-all"
                >
                  <img
                    src={profileAvatarSrc}
                    alt="Profile"
                    className={`w-full h-full ${profileAvatarObjectClass}`}
                  />
                </button>

                {isProfileOpen && (
                  <div className="absolute right-0 mt-2 w-48 bg-surface-container-high border border-outline-variant/20 rounded-md shadow-lg py-1 z-50">
                    <div className="px-4 py-2 border-b border-outline-variant/20">
                      <p className="text-sm font-medium text-on-surface">
                        {user?.name || user?.username || "Operator"}
                      </p>
                      <p className="text-xs text-on-surface-variant">
                        {(user?.role || "tech").toUpperCase()}
                      </p>
                    </div>
                    <Link 
                      to="/profile" 
                      className="flex items-center gap-2 px-4 py-2 text-sm text-on-surface hover:bg-surface-container-highest hover:text-white transition-colors"
                      onClick={() => setIsProfileOpen(false)}
                    >
                      <User className="w-4 h-4" />
                      {t("layout.topbar.profile", "Profile")}
                    </Link>
                    {canAccessSettings && (
                      <Link 
                        to="/settings" 
                        className="flex items-center gap-2 px-4 py-2 text-sm text-on-surface hover:bg-surface-container-highest hover:text-white transition-colors"
                        onClick={() => setIsProfileOpen(false)}
                      >
                        <Settings className="w-4 h-4" />
                        {t("layout.nav.settings", "Settings")}
                      </Link>
                    )}
                    <div className="border-t border-outline-variant/20 my-1"></div>
                    <button 
                      className="w-full flex items-center gap-2 px-4 py-2 text-sm text-error hover:bg-error/10 transition-colors"
                      onClick={async () => {
                        setIsProfileOpen(false);
                        await logout();
                      }}
                    >
                      <LogOut className="w-4 h-4" />
                      {t("layout.topbar.signOut", "Sign Out")}
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>
        </header>

        <main className="flex-1 p-8 overflow-x-hidden">
          {showApiKeyToast && !location.pathname.startsWith("/profile") && (
            <div className="mb-6 rounded-sm border border-primary/20 bg-primary/10 px-4 py-4 text-sm text-on-surface">
              <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                <div>
                  <div className="text-[10px] font-black uppercase tracking-[0.18em] text-primary">
                    {t("layout.onboarding.eyebrow", "Integration onboarding")}
                  </div>
                  <p className="mt-1 text-sm text-on-surface">
                    {t("layout.onboarding.title", "Connect your own intelligence provider API keys to unlock richer analysis results.")}
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={() => {
                      dismissApiKeyToast();
                      navigate("/profile?tab=external_api_keys&source=onboarding");
                    }}
                  >
                    {t("layout.onboarding.cta", "Configure keys")}
                  </button>
                  <button
                    type="button"
                    className="btn btn-ghost"
                    onClick={dismissApiKeyToast}
                  >
                    {t("layout.onboarding.dismiss", "Dismiss")}
                  </button>
                </div>
              </div>
            </div>
          )}
          <Outlet />
        </main>
      </div>

      <KeyboardShortcutsModal
        open={isShortcutsOpen}
        onClose={() => setIsShortcutsOpen(false)}
      />
      <GlobalScanLauncher
        open={isScanLauncherOpen}
        onClose={() => setIsScanLauncherOpen(false)}
      />
    </div>
  );
}
