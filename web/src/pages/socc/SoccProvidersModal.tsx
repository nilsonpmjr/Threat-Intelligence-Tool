import { useState, useEffect, useRef } from "react";
import { Trash, CheckCircle2, XCircle, Loader2, RefreshCw, Key, Link, AlertTriangle, ExternalLink } from "lucide-react";
import ModalShell from "../../components/modal/ModalShell";
import { useLanguage } from "../../context/LanguageContext";
import API_URL from "../../config";

const OAUTH_CHANNEL = "socc-oauth";

interface ProviderCredential {
  id: string;
  provider: string;
  label: string;
  authType: "apikey" | "oauth";
  defaultModel?: string;
  createdAt: string;
}

interface Props {
  open: boolean;
  onClose: () => void;
  highlightCredentialId?: string;
}

type AddMode = "apikey" | null;

const OAUTH_PROVIDERS = [
  { id: "anthropic", labelKey: "socc.providers.connectWithClaudeAi" as const, fallback: "Connect with Claude.ai" },
  { id: "openai",    labelKey: "socc.providers.connectWithChatGPT"  as const, fallback: "Connect with ChatGPT"  },
];

export default function SoccProvidersModal({ open, onClose, highlightCredentialId }: Props) {
  const { t } = useLanguage();
  const [providers, setProviders] = useState<ProviderCredential[]>([]);
  const [loading, setLoading] = useState(false);
  const [addMode, setAddMode] = useState<AddMode>(null);
  const [oauthPending, setOauthPending] = useState<string | null>(null);
  const [oauthError, setOauthError] = useState<string | null>(null);
  const [oauthSuccess, setOauthSuccess] = useState<string | null>(null);
  const [autoHighlight, setAutoHighlight] = useState<string | null>(null);
  const channelRef = useRef<BroadcastChannel | null>(null);

  const [formData, setFormData] = useState({
    provider: "openai",
    label: "",
    apiKey: "",
    baseUrl: "",
    defaultModel: "",
  });
  const [testResult, setTestResult] = useState<{ ok: boolean; error?: string } | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (open) {
      loadProviders();
      setOauthError(null);
      setOauthSuccess(null);

      // Open the BroadcastChannel when the modal is visible.
      const channel = new BroadcastChannel(OAUTH_CHANNEL);
      channelRef.current = channel;

      channel.onmessage = (e) => {
        const { type, credentialId, provider, message } = e.data ?? {};
        setOauthPending(null);

        if (type === "socc-oauth-success") {
          setOauthSuccess(provider ?? "");
          loadProviders();
          if (credentialId) {
            setAutoHighlight(credentialId);
            setTimeout(() => setAutoHighlight(null), 4000);
          }
        } else if (type === "socc-oauth-error") {
          setOauthError(message || t("socc.providers.oauthInitiateFailed", "OAuth authorization failed."));
        }
      };

      return () => {
        channel.close();
        channelRef.current = null;
      };
    }
  }, [open]);

  async function loadProviders() {
    try {
      setLoading(true);
      const res = await fetch(`${API_URL}/api/socc/providers`, { credentials: "include" });
      if (res.ok) {
        const data = await res.json();
        setProviders(data.credentials ?? []);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }

  async function handleSaveApiKey(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setTestResult(null);

    try {
      const payload: Record<string, string> = {
        provider: formData.provider,
        label: formData.label,
        apiKey: formData.apiKey,
        defaultModel: formData.defaultModel || "default",
      };
      if (formData.baseUrl) payload.baseUrl = formData.baseUrl;

      const res = await fetch(`${API_URL}/api/socc/providers`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify(payload),
      });
      const data = await res.json();

      if (!res.ok) {
        const msg =
          data.error === "local_provider_disabled"
            ? t("socc.providers.localProviderDisabled", "Local providers are disabled by the administrator.")
            : data.error || data.message || t("socc.providers.saveFailed", "Failed to save provider.");
        setTestResult({ ok: false, error: msg });
        return;
      }

      const testRes = await fetch(`${API_URL}/api/socc/providers/${data.id}/test`, {
        method: "POST",
        credentials: "include",
      });
      const testData = await testRes.json();

      if (testRes.ok && testData.result === "ok") {
        setTestResult({ ok: true });
        setAddMode(null);
        setFormData({ provider: "openai", label: "", apiKey: "", baseUrl: "", defaultModel: "" });
        loadProviders();
      } else {
        setTestResult({ ok: false, error: testData.message || testData.error || t("socc.providers.testFailed", "Test failed.") });
        await fetch(`${API_URL}/api/socc/providers/${data.id}`, {
          method: "DELETE",
          credentials: "include",
        });
      }
    } catch (err: any) {
      setTestResult({ ok: false, error: err.message });
    } finally {
      setSaving(false);
    }
  }

  async function handleOAuthConnect(providerId: string) {
    setOauthPending(providerId);
    setOauthError(null);
    setOauthSuccess(null);

    // Open a new tab synchronously (same event-loop task as the click)
    // so browsers don't block it. We'll navigate it after the fetch.
    const newTab = window.open("about:blank", "_blank");
    if (!newTab) {
      setOauthError(t("socc.providers.tabBlocked", "Could not open a new tab. Check your browser settings."));
      setOauthPending(null);
      return;
    }

    try {
      const res = await fetch(`${API_URL}/api/socc/auth/${providerId}/initiate`, {
        credentials: "include",
      });
      if (!res.ok) {
        newTab.close();
        const data = await res.json().catch(() => ({}));
        setOauthError(
          data.error === "socc_not_installed" || res.status === 404 || res.status === 503
            ? t("socc.providers.oauthInitiateFailed", "Could not start OAuth. Check that SOC Copilot is installed.")
            : data.error || data.message || t("socc.providers.oauthInitiateFailed", "Failed to initiate OAuth.")
        );
        setOauthPending(null);
        return;
      }

      const { authUrl } = await res.json();
      // Navigate the already-open tab to the real OAuth URL.
      newTab.location.href = authUrl;
    } catch (err: any) {
      newTab.close();
      setOauthError(err.message || t("socc.providers.oauthInitiateFailed", "Failed to initiate OAuth."));
      setOauthPending(null);
    }
  }

  async function handleRevoke(id: string) {
    if (!confirm(t("socc.providers.revokeConfirm", "Revoke this provider?"))) return;
    try {
      await fetch(`${API_URL}/api/socc/providers/${id}`, {
        method: "DELETE",
        credentials: "include",
      });
      loadProviders();
    } catch (err) {
      console.error(err);
    }
  }

  if (!open) return null;

  return (
    <ModalShell
      title={t("socc.providers.title", "Personal Provider")}
      description={t("socc.providers.subtitle", "Configure your provider to use SOC Copilot.")}
      onClose={onClose}
      variant="dialog"
    >
      <div className="space-y-6">
        {/* ── Main view ── */}
        {addMode === null && (
          <>
            <div>
              <h3 className="text-sm font-bold text-on-surface uppercase tracking-widest mb-3">
                {t("socc.providers.configured", "Configured Providers")}
              </h3>

              {loading ? (
                <div className="flex justify-center p-4">
                  <Loader2 className="w-6 h-6 animate-spin text-outline" />
                </div>
              ) : providers.length === 0 ? (
                <div className="card p-6 text-center text-on-surface-variant text-sm">
                  {t("socc.providers.noProviders", "No providers configured.")}
                </div>
              ) : (
                <div className="space-y-3">
                  {providers.map((p) => {
                    const highlighted = p.id === highlightCredentialId || p.id === autoHighlight;
                    return (
                      <div
                        key={p.id}
                        className={`card p-4 flex justify-between items-center gap-3 transition-all ${highlighted ? "border border-success/50 bg-success/5" : ""}`}
                      >
                        <div className="flex-1 min-w-0">
                          <div className="font-bold text-sm text-on-surface flex items-center gap-2 flex-wrap">
                            {p.label}
                            <span className="badge badge-outline text-[10px]">{p.provider}</span>
                            <span
                              className={`badge text-[10px] flex items-center gap-1 ${p.authType === "oauth" ? "badge-primary" : "badge-outline"}`}
                            >
                              {p.authType === "oauth" ? (
                                <><Link className="w-3 h-3" />{t("socc.providers.authTypeBadgeOAuth", "OAuth")}</>
                              ) : (
                                <><Key className="w-3 h-3" />{t("socc.providers.authTypeBadgeApiKey", "API Key")}</>
                              )}
                            </span>
                          </div>
                          {p.defaultModel && (
                            <div className="text-xs text-on-surface-variant mt-1 font-mono">
                              {p.defaultModel}
                            </div>
                          )}
                        </div>
                        <div className="flex items-center gap-1 shrink-0">
                          {p.authType === "oauth" && (
                            <button
                              className="btn btn-ghost btn-sm text-on-surface-variant hover:bg-surface-container-high"
                              onClick={() => handleOAuthConnect(p.provider)}
                              disabled={oauthPending !== null}
                              title={t("socc.providers.reconnect", "Reconnect OAuth")}
                            >
                              {oauthPending === p.provider ? (
                                <Loader2 className="w-4 h-4 animate-spin" />
                              ) : (
                                <RefreshCw className="w-4 h-4" />
                              )}
                            </button>
                          )}
                          <button
                            className="btn btn-ghost btn-sm text-error hover:bg-error/10"
                            onClick={() => handleRevoke(p.id)}
                            title={t("socc.providers.revoke", "Revoke")}
                          >
                            <Trash className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* OAuth pending banner */}
            {oauthPending && (
              <div className="p-3 text-sm rounded-sm flex items-center gap-2 bg-surface-container text-on-surface-variant">
                <Loader2 className="w-4 h-4 animate-spin shrink-0" />
                <span>{t("socc.providers.oauthWaiting", "Waiting for authorization in the new tab…")}</span>
              </div>
            )}

            {/* OAuth success banner */}
            {oauthSuccess && (
              <div className="p-3 text-sm rounded-sm flex items-start gap-2 bg-success/10 text-success">
                <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5" />
                <span>
                  {t("socc.providers.oauthSuccess", "Connected via {{provider}}.").replace("{{provider}}", oauthSuccess)}
                </span>
              </div>
            )}

            {/* OAuth error banner */}
            {oauthError && (
              <div className="p-3 text-sm rounded-sm flex items-start gap-2 bg-error/10 text-error">
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                <span>{oauthError}</span>
              </div>
            )}

            {/* Add provider section */}
            <div className="space-y-2 border-t border-outline-variant/10 pt-4">
              <p className="text-xs font-bold uppercase tracking-widest text-on-surface-variant mb-2">
                {t("socc.providers.addProvider", "Add Provider")}
              </p>

              {OAUTH_PROVIDERS.map((op) => (
                <button
                  key={op.id}
                  className="btn btn-secondary w-full justify-start gap-2"
                  onClick={() => handleOAuthConnect(op.id)}
                  disabled={oauthPending !== null}
                >
                  {oauthPending === op.id ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <ExternalLink className="w-4 h-4" />
                  )}
                  {t(op.labelKey, op.fallback)}
                </button>
              ))}

              <button
                className="btn btn-ghost w-full justify-start gap-2 text-on-surface-variant"
                onClick={() => { setAddMode("apikey"); setTestResult(null); setOauthError(null); }}
              >
                <Key className="w-4 h-4" />
                {t("socc.providers.addApiKey", "Add via API Key")}
              </button>
            </div>
          </>
        )}

        {/* ── API Key form ── */}
        {addMode === "apikey" && (
          <form onSubmit={handleSaveApiKey} className="space-y-4 border border-outline-variant/20 p-4 rounded-sm">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-bold uppercase tracking-widest text-on-surface-variant mb-1">
                  {t("socc.providers.provider", "Provider")}
                </label>
                <select
                  className="input w-full"
                  value={formData.provider}
                  onChange={(e) => setFormData({ ...formData, provider: e.target.value })}
                  required
                >
                  <option value="openai">OpenAI</option>
                  <option value="anthropic">Anthropic</option>
                  <option value="gemini">Gemini</option>
                  <option value="ollama">Ollama (local)</option>
                  <option value="openai-compatible">OpenAI-compatible</option>
                </select>
              </div>
              <div>
                <label className="block text-xs font-bold uppercase tracking-widest text-on-surface-variant mb-1">
                  {t("socc.providers.label", "Label")}
                </label>
                <input
                  type="text"
                  className="input w-full"
                  value={formData.label}
                  onChange={(e) => setFormData({ ...formData, label: e.target.value })}
                  placeholder={t("socc.providers.labelPlaceholder", "e.g. My OpenAI Key")}
                  required
                />
              </div>
            </div>

            {formData.provider !== "ollama" && (
              <div>
                <label className="block text-xs font-bold uppercase tracking-widest text-on-surface-variant mb-1">
                  {t("socc.providers.apiKey", "API Key")}
                </label>
                <input
                  type="password"
                  className="input w-full font-mono text-sm"
                  value={formData.apiKey}
                  onChange={(e) => setFormData({ ...formData, apiKey: e.target.value })}
                  placeholder="sk-..."
                  required
                />
              </div>
            )}

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-bold uppercase tracking-widest text-on-surface-variant mb-1">
                  {t("socc.providers.baseUrl", "Base URL (optional)")}
                </label>
                <input
                  type="url"
                  className="input w-full"
                  value={formData.baseUrl}
                  onChange={(e) => setFormData({ ...formData, baseUrl: e.target.value })}
                  placeholder="https://..."
                />
              </div>
              <div>
                <label className="block text-xs font-bold uppercase tracking-widest text-on-surface-variant mb-1">
                  {t("socc.providers.defaultModel", "Default Model")}
                </label>
                <input
                  type="text"
                  className="input w-full"
                  value={formData.defaultModel}
                  onChange={(e) => setFormData({ ...formData, defaultModel: e.target.value })}
                  placeholder="e.g. gpt-4o"
                />
              </div>
            </div>

            {testResult && (
              <div
                className={`p-3 text-sm rounded-sm flex items-start gap-2 ${testResult.ok ? "bg-success/10 text-success" : "bg-error/10 text-error"}`}
              >
                {testResult.ok ? (
                  <CheckCircle2 className="w-5 h-5 shrink-0" />
                ) : (
                  <XCircle className="w-5 h-5 shrink-0" />
                )}
                <div>
                  {testResult.ok
                    ? t("socc.providers.testOk", "Provider successfully configured.")
                    : testResult.error}
                </div>
              </div>
            )}

            <div className="flex justify-end gap-2 pt-2 border-t border-outline-variant/10">
              <button
                type="button"
                className="btn btn-ghost"
                onClick={() => { setAddMode(null); setTestResult(null); }}
              >
                {t("common.cancel", "Cancel")}
              </button>
              <button type="submit" className="btn btn-primary" disabled={saving}>
                {saving && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                {t("socc.providers.save", "Save & Test")}
              </button>
            </div>
          </form>
        )}
      </div>
    </ModalShell>
  );
}
