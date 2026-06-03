import { useState, useEffect } from "react";
import { Trash, Plus, CheckCircle2, XCircle, Loader2 } from "lucide-react";
import ModalShell from "../../components/modal/ModalShell";
import { useLanguage } from "../../context/LanguageContext";
import API_URL from "../../config";

interface ProviderCredential {
  id: string;
  provider: string;
  label: string;
  keyPreview: string;
  createdAt: string;
  lastTestResult?: string | null;
}

interface Props {
  open: boolean;
  onClose: () => void;
}

export default function SoccProvidersModal({ open, onClose }: Props) {
  const { t } = useLanguage();
  const [providers, setProviders] = useState<ProviderCredential[]>([]);
  const [loading, setLoading] = useState(false);
  const [adding, setAdding] = useState(false);
  
  const [formData, setFormData] = useState({
    provider: "openai",
    label: "",
    apiKey: "",
    baseUrl: "",
    defaultModel: "",
  });
  const [testResult, setTestResult] = useState<{ok: boolean, error?: string} | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (open) {
      loadProviders();
    }
  }, [open]);

  async function loadProviders() {
    try {
      setLoading(true);
      const res = await fetch(`${API_URL}/api/socc/providers`, { credentials: "include" });
      if (res.ok) {
        const data = await res.json();
        setProviders(data.credentials || []);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setTestResult(null);

    try {
      const payload: any = {
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
        if (data.error === "local_provider_disabled") {
          setTestResult({ ok: false, error: t("socc.providers.localProviderDisabled", "Local providers are disabled by the administrator.") });
        } else {
          setTestResult({ ok: false, error: data.error || data.message || "Failed to create provider" });
        }
        return;
      }

      const newId = data.id;
      
      // Now test it
      const testRes = await fetch(`${API_URL}/api/socc/providers/${newId}/test`, {
        method: "POST",
        credentials: "include",
      });
      const testData = await testRes.json();
      
      if (testRes.ok && testData.result === "ok") {
        setTestResult({ ok: true });
        setAdding(false);
        setFormData({ provider: "openai", label: "", apiKey: "", baseUrl: "", defaultModel: "" });
        loadProviders();
      } else {
        setTestResult({ ok: false, error: testData.error || "Test failed" });
        // Clean up the created provider if test failed
        await fetch(`${API_URL}/api/socc/providers/${newId}`, { method: "DELETE", credentials: "include" });
      }
    } catch (err: any) {
      setTestResult({ ok: false, error: err.message });
    } finally {
      setSaving(false);
    }
  }

  async function handleRevoke(id: string) {
    if (!confirm(t("socc.providers.revokeConfirm", "Are you sure you want to revoke this provider?"))) return;
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
        {!adding && (
          <div className="flex justify-between items-center">
            <h3 className="text-sm font-bold text-on-surface uppercase tracking-widest">
              Configured Providers
            </h3>
            <button className="btn btn-primary btn-sm" onClick={() => setAdding(true)}>
              <Plus className="w-4 h-4 mr-2" />
              Add Provider
            </button>
          </div>
        )}

        {!adding && loading ? (
          <div className="flex justify-center p-4"><Loader2 className="w-6 h-6 animate-spin text-outline" /></div>
        ) : !adding && providers.length === 0 ? (
          <div className="card p-6 text-center text-on-surface-variant text-sm">
            {t("socc.providers.noProviders", "No providers configured.")}
          </div>
        ) : !adding ? (
          <div className="space-y-3">
            {providers.map(p => (
              <div key={p.id} className="card p-4 flex justify-between items-center">
                <div>
                  <div className="font-bold text-sm text-on-surface flex items-center gap-2">
                    {p.label} <span className="badge badge-outline">{p.provider}</span>
                  </div>
                  <div className="text-xs text-on-surface-variant mt-1 font-mono">
                    {p.keyPreview}
                  </div>
                  {p.lastTestResult && (
                    <div className="text-[10px] mt-2 text-outline uppercase">
                      Last test: {p.lastTestResult}
                    </div>
                  )}
                </div>
                <button className="btn btn-ghost text-error hover:bg-error/10" onClick={() => handleRevoke(p.id)}>
                  <Trash className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>
        ) : null}

        {adding && (
          <form onSubmit={handleSave} className="space-y-4 border border-outline-variant/20 p-4 rounded-sm">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-bold uppercase tracking-widest text-on-surface-variant mb-1">
                  {t("socc.providers.provider", "Provider")}
                </label>
                <select 
                  className="input w-full"
                  value={formData.provider}
                  onChange={e => setFormData({...formData, provider: e.target.value})}
                  required
                >
                  <option value="openai">OpenAI</option>
                  <option value="anthropic">Anthropic</option>
                  <option value="gemini">Gemini</option>
                  <option value="ollama">Ollama</option>
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
                  onChange={e => setFormData({...formData, label: e.target.value})}
                  placeholder="e.g. My OpenAI Key"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-bold uppercase tracking-widest text-on-surface-variant mb-1">
                {t("socc.providers.apiKey", "API Key")}
              </label>
              <input 
                type="password" 
                className="input w-full font-mono text-sm" 
                value={formData.apiKey}
                onChange={e => setFormData({...formData, apiKey: e.target.value})}
                placeholder="sk-..."
                required={formData.provider !== "ollama"}
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-bold uppercase tracking-widest text-on-surface-variant mb-1">
                  {t("socc.providers.baseUrl", "Base URL (optional)")}
                </label>
                <input 
                  type="url" 
                  className="input w-full" 
                  value={formData.baseUrl}
                  onChange={e => setFormData({...formData, baseUrl: e.target.value})}
                  placeholder="https://..."
                />
              </div>
              <div>
                <label className="block text-xs font-bold uppercase tracking-widest text-on-surface-variant mb-1">
                  {t("socc.providers.defaultModel", "Default Model (optional)")}
                </label>
                <input 
                  type="text" 
                  className="input w-full" 
                  value={formData.defaultModel}
                  onChange={e => setFormData({...formData, defaultModel: e.target.value})}
                  placeholder="e.g. gpt-4o"
                />
              </div>
            </div>

            {testResult && (
              <div className={`p-3 text-sm rounded-sm flex items-start gap-2 ${testResult.ok ? 'bg-success/10 text-success' : 'bg-error/10 text-error'}`}>
                {testResult.ok ? <CheckCircle2 className="w-5 h-5 shrink-0" /> : <XCircle className="w-5 h-5 shrink-0" />}
                <div>{testResult.ok ? t("socc.providers.testOk", "Provider successfully configured.") : testResult.error}</div>
              </div>
            )}

            <div className="flex justify-end gap-2 pt-2 border-t border-outline-variant/10">
              <button type="button" className="btn btn-ghost" onClick={() => { setAdding(false); setTestResult(null); }}>
                Cancel
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
