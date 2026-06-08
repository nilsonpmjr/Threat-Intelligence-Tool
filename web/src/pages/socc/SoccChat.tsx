import { useState, useRef, useEffect, useCallback, KeyboardEvent } from "react";
import { useSearchParams } from "react-router-dom";
import { fetchEventSource } from "@microsoft/fetch-event-source";
import { marked } from "marked";
import DOMPurify from "dompurify";
import { createHighlighter } from "shiki";
import TextareaAutosize from "react-textarea-autosize";
import {
  Settings, Plus, SendHorizontal, Square, AlertTriangle, MessageSquare,
  Terminal, Paperclip, X as XIcon, FileText, ChevronDown, Copy, Download,
  Image as ImageIcon, FileCode, ClipboardPaste, Zap,
} from "lucide-react";
import { useLanguage } from "../../context/LanguageContext";
import API_URL from "../../config";
import SoccProvidersModal from "./SoccProvidersModal";
import { highlightIocsInHtml } from "../../lib/ioc-extractor";

// ── Shiki syntax highlight ────────────────────────────────────────────
let highlighter: any = null;
createHighlighter({
  themes: ["github-dark"],
  langs: ["javascript", "typescript", "python", "bash", "json", "yaml", "markdown"],
}).then((hl) => { highlighter = hl; });

marked.setOptions({ async: false, gfm: true, breaks: true });
const renderer = new marked.Renderer();
renderer.code = ({ text, lang }) => {
  if (highlighter && lang && highlighter.getLoadedLanguages().includes(lang)) {
    try { return highlighter.codeToHtml(text, { lang, theme: "github-dark" }); } catch {}
  }
  return `<pre><code>${DOMPurify.sanitize(text)}</code></pre>`;
};
marked.use({ renderer });

// ── Types ─────────────────────────────────────────────────────────────
interface Message {
  id: string;
  role: "user" | "assistant";
  text: string;
  streaming?: boolean;
}

interface Session {
  id: string;
  createdAt: string;
  promptCount: number;
}

interface Credential {
  id: string;
  provider: string;
  label: string;
  authType: "apikey" | "oauth";
  defaultModel?: string;
}

interface PendingAttachment {
  attachmentId: string;
  filename: string;
  mimeType: string;
  uploading?: boolean;
  error?: string;
}

// ── Quick prompt templates ────────────────────────────────────────────
const QUICK_PROMPTS = [
  { icon: "🔍", key: "socc.prompts.triage",   fallback: "Triage this IOC" },
  { icon: "🛡️", key: "socc.prompts.cve",     fallback: "Explain this CVE" },
  { icon: "⚔️", key: "socc.prompts.ttps",    fallback: "What TTPs does this indicate?" },
  { icon: "📋", key: "socc.prompts.log",      fallback: "Summarize this log" },
  { icon: "🎣", key: "socc.prompts.phishing", fallback: "Is this phishing?" },
  { icon: "🔓", key: "socc.prompts.payload",  fallback: "Decode this payload" },
];

// ── IOC popover ───────────────────────────────────────────────────────
function IocPopover({
  ioc,
  type,
  rect,
  onClose,
}: {
  ioc: string;
  type: string;
  rect: DOMRect;
  onClose: () => void;
}) {
  const analyzable = ["ipv4", "ipv6", "domain", "md5", "sha1", "sha256", "sha512", "cve"].includes(type);
  return (
    <div
      className="fixed z-50 bg-surface-container-high border border-outline-variant/30 rounded-sm shadow-lg text-xs py-1 min-w-[160px]"
      style={{ top: rect.bottom + 4, left: Math.min(rect.left, window.innerWidth - 180) }}
    >
      <div className="px-3 py-1 text-on-surface-variant font-mono truncate max-w-[240px] border-b border-outline-variant/20 mb-1">
        {ioc}
        <span className="ml-1 badge badge-outline text-[9px]">{type}</span>
      </div>
      {analyzable && (
        <button
          className="w-full text-left px-3 py-1.5 hover:bg-primary/10 text-on-surface flex items-center gap-2"
          onClick={() => { window.open(`/analyze/${encodeURIComponent(ioc)}`, "_blank"); onClose(); }}
        >
          <Zap className="w-3 h-3 text-primary" /> Analyze in VANTAGE
        </button>
      )}
      <button
        className="w-full text-left px-3 py-1.5 hover:bg-surface-container-highest text-on-surface flex items-center gap-2"
        onClick={() => { navigator.clipboard.writeText(ioc); onClose(); }}
      >
        <Copy className="w-3 h-3" /> Copy
      </button>
      <button
        className="w-full text-left px-3 py-1.5 hover:bg-surface-container-highest text-on-surface-variant flex items-center gap-2"
        onClick={onClose}
      >
        <XIcon className="w-3 h-3" /> Close
      </button>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────
export default function SoccChat() {
  const { t } = useLanguage();
  const [searchParams, setSearchParams] = useSearchParams();
  const [providersModalOpen, setProvidersModalOpen] = useState(false);
  const [highlightCredentialId] = useState<string | undefined>(
    searchParams.get("credentialId") ?? undefined,
  );

  const [sessions, setSessions] = useState<Session[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [activeModel, setActiveModel] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [isStreaming, setIsStreaming] = useState(false);
  const [credentials, setCredentials] = useState<Credential[]>([]);

  // New session picker state
  const [showNewSessionPicker, setShowNewSessionPicker] = useState(false);
  const [pickerCredId, setPickerCredId] = useState("");
  const [pickerModel, setPickerModel] = useState("");
  const [availableModels, setAvailableModels] = useState<string[]>([]);
  const [loadingModels, setLoadingModels] = useState(false);

  const abortControllerRef = useRef<AbortController | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const fileInputModeRef = useRef<"any" | "image">("any");
  const attachMenuRef = useRef<HTMLDivElement | null>(null);

  const [errorToast, setErrorToast] = useState<string | null>(null);
  const [rateLimited, setRateLimited] = useState(false);
  const [crashedSession, setCrashedSession] = useState(false);
  const [pendingAttachments, setPendingAttachments] = useState<PendingAttachment[]>([]);
  const [showAttachMenu, setShowAttachMenu] = useState(false);

  // IOC popover
  const [iocPopover, setIocPopover] = useState<{ ioc: string; type: string; rect: DOMRect } | null>(null);

  // ── Lifecycle ──────────────────────────────────────────────────────
  useEffect(() => {
    loadCredentials();
    loadSessions();
    const urlSessionId = searchParams.get("sessionId");
    if (urlSessionId) {
      setActiveSessionId(urlSessionId);
      setMessages([]);
      setSearchParams({}, { replace: true });
    }
    if (highlightCredentialId) {
      setProvidersModalOpen(true);
      setSearchParams({}, { replace: true });
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages]);

  // Close attach menu on outside click
  useEffect(() => {
    function handleOutside(e: MouseEvent) {
      if (attachMenuRef.current && !attachMenuRef.current.contains(e.target as Node)) {
        setShowAttachMenu(false);
      }
    }
    document.addEventListener("mousedown", handleOutside);
    return () => document.removeEventListener("mousedown", handleOutside);
  }, []);

  // IOC click delegation
  const handleChatClick = useCallback((e: React.MouseEvent<HTMLDivElement>) => {
    const target = e.target as HTMLElement;
    const span = target.closest("[data-ioc]") as HTMLElement | null;
    if (!span) { setIocPopover(null); return; }
    setIocPopover({
      ioc: span.dataset.ioc!,
      type: span.dataset.iocType ?? "unknown",
      rect: span.getBoundingClientRect(),
    });
  }, []);

  // Paste listener for clipboard text → attachment
  useEffect(() => {
    async function handlePaste(e: ClipboardEvent) {
      if (!activeSessionId) return;
      const text = e.clipboardData?.getData("text");
      if (!text || document.activeElement?.tagName === "TEXTAREA") return;
      // Only intercept paste outside the input area and when it's a multi-line block
      if (!text.includes("\n") || text.length < 50) return;
      e.preventDefault();
      await uploadTextAsAttachment(text, "pasted-text.txt");
    }
    document.addEventListener("paste", handlePaste);
    return () => document.removeEventListener("paste", handlePaste);
  }, [activeSessionId]);

  // Drag-and-drop
  function handleDragOver(e: React.DragEvent) { e.preventDefault(); }
  async function handleDrop(e: React.DragEvent) {
    e.preventDefault();
    if (!activeSessionId) return;
    const file = e.dataTransfer.files[0];
    if (file) await uploadFile(file);
  }

  // ── Data loaders ───────────────────────────────────────────────────
  async function loadCredentials() {
    try {
      const res = await fetch(`${API_URL}/api/socc/providers`, { credentials: "include" });
      if (res.ok) {
        const data = await res.json();
        setCredentials(data.credentials ?? []);
      }
    } catch {}
  }

  async function loadSessions() {
    try {
      const res = await fetch(`${API_URL}/api/socc/session`, { credentials: "include" });
      if (res.ok) {
        const data = await res.json();
        setSessions(data.sessions ?? []);
      }
    } catch {}
  }

  async function loadModelsForCred(credId: string) {
    setLoadingModels(true);
    setAvailableModels([]);
    try {
      const res = await fetch(`${API_URL}/api/socc/providers/${credId}/models`, { credentials: "include" });
      if (res.ok) {
        const data = await res.json();
        setAvailableModels(data.models ?? []);
        const cred = credentials.find((c) => c.id === credId);
        setPickerModel(data.models[0] ?? cred?.defaultModel ?? "");
      }
    } catch {} finally {
      setLoadingModels(false);
    }
  }

  // ── New session picker ─────────────────────────────────────────────
  function openNewSessionPicker() {
    if (credentials.length === 0) { setProvidersModalOpen(true); return; }
    const firstCred = credentials[0];
    setPickerCredId(firstCred.id);
    setPickerModel(firstCred.defaultModel ?? "");
    setShowNewSessionPicker(true);
    loadModelsForCred(firstCred.id);
  }

  async function createSessionWith(credentialId: string, model: string) {
    const body: Record<string, string> = { credentialId };
    if (model) body.modelOverride = model;
    const res = await fetch(`${API_URL}/api/socc/session`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify(body),
    });
    if (res.ok) {
      const data = await res.json();
      setSessions((prev) => [
        { id: data.sessionId, createdAt: new Date().toISOString(), promptCount: 0 },
        ...prev,
      ]);
      setActiveSessionId(data.sessionId);
      setActiveModel(model || null);
      setMessages([]);
      setCrashedSession(false);
      setErrorToast(null);
    }
  }

  async function startSession() {
    setShowNewSessionPicker(false);
    try {
      await createSessionWith(pickerCredId, pickerModel);
    } catch {}
  }

  // R-5: after a worker crash, spin up a fresh session reusing the same
  // credential/model so the analyst can continue without re-picking.
  async function restartSession() {
    const credId = pickerCredId || credentials[0]?.id;
    if (!credId) { openNewSessionPicker(); return; }
    try {
      await createSessionWith(credId, activeModel || pickerModel);
    } catch {}
  }

  // ── Message send ───────────────────────────────────────────────────
  function handleKeyDown(e: KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  }

  async function sendMessage() {
    if (!input.trim() && pendingAttachments.length === 0) return;
    if (!activeSessionId || isStreaming) return;

    const text = input.trim();
    const attachmentIds = pendingAttachments
      .filter((a) => !a.uploading && !a.error)
      .map((a) => a.attachmentId);

    setInput("");
    setPendingAttachments([]);
    setErrorToast(null);
    setRateLimited(false);
    setCrashedSession(false);

    const userMsgId = Date.now().toString();
    setMessages((prev) => [...prev, { id: userMsgId, role: "user", text }]);
    const assistantMsgId = (Date.now() + 1).toString();
    setMessages((prev) => [...prev, { id: assistantMsgId, role: "assistant", text: "", streaming: true }]);
    setIsStreaming(true);
    abortControllerRef.current = new AbortController();

    try {
      await fetchEventSource(`${API_URL}/api/socc/session/${activeSessionId}/message`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text, ...(attachmentIds.length > 0 && { attachmentIds }) }),
        signal: abortControllerRef.current.signal,
        credentials: "include",
        openWhenHidden: true,
        async onopen(response) {
          if (response.status === 429) { setRateLimited(true); throw new Error("Rate limited"); }
          if (response.ok && response.headers.get("content-type")?.includes("text/event-stream")) return;
          if (response.status >= 400) {
            const body = await response.json().catch(() => ({}));
            if (body.error === "quota_exceeded") setRateLimited(true);
            throw new Error(body.message || "Server error");
          }
        },
        onmessage(msg) {
          if (msg.event === "error") {
            try {
              const data = JSON.parse(msg.data);
              if (data.code === "provider_rate_limited" || data.code === "quota_exceeded") {
                setRateLimited(true);
              } else if (data.code === "provider_unavailable" && data.reason === "token_expired") {
                setErrorToast(t("socc.chat.tokenExpired", "OAuth token expired. Reconnect the provider."));
                setProvidersModalOpen(true);
              } else if (data.code === "session_worker_crashed") {
                setCrashedSession(true);
                setErrorToast(t("socc.chat.sessionCrashed", "The session crashed. Restart to continue."));
              } else {
                setErrorToast(data.message || t("socc.chat.sessionError", "A session error occurred."));
              }
            } catch {}
            throw new Error("Stream error");
          }
          if (msg.event === "token") {
            try {
              const data = JSON.parse(msg.data);
              const chunk = data.token ?? "";
              if (chunk) {
                setMessages((prev) =>
                  prev.map((m) => m.id === assistantMsgId ? { ...m, text: m.text + chunk } : m),
                );
              }
            } catch {
              if (msg.data) {
                setMessages((prev) =>
                  prev.map((m) => m.id === assistantMsgId ? { ...m, text: m.text + msg.data } : m),
                );
              }
            }
          }
          if (msg.event === "message.end") {
            setMessages((prev) =>
              prev.map((m) => m.id === assistantMsgId ? { ...m, streaming: false } : m),
            );
          }
        },
        onclose() {
          setIsStreaming(false);
          setMessages((prev) => prev.map((m) => m.id === assistantMsgId ? { ...m, streaming: false } : m));
        },
        onerror(err) {
          setIsStreaming(false);
          setMessages((prev) => prev.map((m) => m.id === assistantMsgId ? { ...m, streaming: false } : m));
          if (!rateLimited && !errorToast) {
            setErrorToast(t("socc.chat.sessionError", "A session error occurred."));
          }
          throw err;
        },
      });
    } catch {
      setIsStreaming(false);
      setMessages((prev) => prev.map((m) => m.id === assistantMsgId ? { ...m, streaming: false } : m));
    }
  }

  async function handleAbort() {
    if (!activeSessionId) return;
    abortControllerRef.current?.abort();
    setIsStreaming(false);
    try {
      await fetch(`${API_URL}/api/socc/session/${activeSessionId}/abort`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
    } catch {}
  }

  // ── Attachments ────────────────────────────────────────────────────
  async function uploadFile(file: File) {
    if (!activeSessionId) return;
    const tempId = `upload-${Date.now()}`;
    setPendingAttachments((prev) => [
      ...prev,
      { attachmentId: tempId, filename: file.name, mimeType: file.type, uploading: true },
    ]);
    try {
      const form = new FormData();
      form.append("file", file);
      const res = await fetch(`${API_URL}/api/socc/session/${activeSessionId}/attachments`, {
        method: "POST", credentials: "include", body: form,
      });
      const data = await res.json();
      if (!res.ok) {
        setPendingAttachments((prev) =>
          prev.map((a) => a.attachmentId === tempId
            ? { ...a, uploading: false, error: data.error || `Error ${res.status}` }
            : a),
        );
        return;
      }
      setPendingAttachments((prev) =>
        prev.map((a) => a.attachmentId === tempId
          ? { attachmentId: data.attachmentId, filename: data.filename, mimeType: data.mimeType }
          : a),
      );
    } catch (err: any) {
      setPendingAttachments((prev) =>
        prev.map((a) => a.attachmentId === tempId
          ? { ...a, uploading: false, error: err.message || "Upload failed" }
          : a),
      );
    }
  }

  async function uploadTextAsAttachment(text: string, filename: string) {
    const blob = new Blob([text], { type: "text/plain" });
    await uploadFile(new File([blob], filename, { type: "text/plain" }));
  }

  function openFilePicker(mode: "any" | "image") {
    fileInputModeRef.current = mode;
    if (fileInputRef.current) {
      fileInputRef.current.accept =
        mode === "image"
          ? "image/png,image/jpeg,image/gif,image/webp"
          : "text/plain,text/csv,application/json,text/yaml,text/xml,application/pdf,.py,.js,.sh,.ps1,.log,.txt";
      fileInputRef.current.click();
    }
    setShowAttachMenu(false);
  }

  function removeAttachment(id: string) {
    setPendingAttachments((prev) => prev.filter((a) => a.attachmentId !== id));
  }

  // ── Markdown + IOC render ──────────────────────────────────────────
  function createMarkup(text: string) {
    if (!text) return { __html: "" };
    const rawMarkup = marked.parse(text) as string;
    const sanitized = DOMPurify.sanitize(rawMarkup);
    return { __html: highlightIocsInHtml(sanitized) };
  }

  // ── Export / copy ──────────────────────────────────────────────────
  function copyAsEvidence(text: string) {
    const header = `## SOC Copilot Evidence — ${new Date().toISOString()} — Session ${activeSessionId?.slice(0, 8) ?? "?"}`;
    navigator.clipboard.writeText(`${header}\n\n${text}`);
  }

  function exportSession() {
    if (!activeSessionId || messages.length === 0) return;
    const cred = credentials.find((c) => c.id === pickerCredId);
    const header = [
      `# SOC Copilot Session Export`,
      `Session: ${activeSessionId.slice(0, 8)}`,
      `Model: ${activeModel ?? cred?.defaultModel ?? "unknown"}`,
      `Provider: ${cred?.provider ?? "unknown"}`,
      `Exported: ${new Date().toISOString()}`,
      `---`,
      "",
    ].join("\n");
    const body = messages
      .map((m) => `**${m.role === "user" ? "Analyst" : "SOC Copilot"}**\n\n${m.text}`)
      .join("\n\n---\n\n");
    const blob = new Blob([header + body], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `socc-session-${activeSessionId.slice(0, 8)}-${new Date().toISOString().slice(0, 10)}.md`;
    a.click();
    URL.revokeObjectURL(url);
  }

  // ── Render ─────────────────────────────────────────────────────────
  return (
    <div
      className="flex h-[calc(100vh-4rem)] bg-background -m-8"
      onClick={() => setIocPopover(null)}
    >
      {/* ── Sidebar ── */}
      <div className="w-64 flex-shrink-0 border-r border-outline-variant/20 bg-surface-container-lowest flex flex-col">
        <div className="p-4 border-b border-outline-variant/20 flex items-center justify-between">
          <h2 className="text-sm font-bold text-on-surface uppercase tracking-widest">
            {t("socc.nav", "SOC Copilot")}
          </h2>
          <button className="btn btn-ghost !px-2" onClick={() => setProvidersModalOpen(true)} title="Providers">
            <Settings className="w-4 h-4" />
          </button>
        </div>
        <div className="p-4">
          <button className="btn btn-primary w-full" onClick={openNewSessionPicker}>
            <Plus className="w-4 h-4 mr-2" /> New Session
          </button>
        </div>

        {/* ── New session picker ── */}
        {showNewSessionPicker && (
          <div className="mx-3 mb-3 p-3 border border-outline-variant/30 rounded-sm bg-surface-container-high space-y-3 text-sm">
            {credentials.length > 1 && (
              <div>
                <label className="block text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-1">Provider</label>
                <select
                  className="input w-full text-xs"
                  value={pickerCredId}
                  onChange={(e) => {
                    setPickerCredId(e.target.value);
                    loadModelsForCred(e.target.value);
                  }}
                >
                  {credentials.map((c) => (
                    <option key={c.id} value={c.id}>{c.label} ({c.provider})</option>
                  ))}
                </select>
              </div>
            )}
            <div>
              <label className="block text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-1">Model</label>
              {availableModels.length > 0 ? (
                <select
                  className="input w-full text-xs"
                  value={pickerModel}
                  onChange={(e) => setPickerModel(e.target.value)}
                >
                  {availableModels.map((m) => (
                    <option key={m} value={m}>{m}</option>
                  ))}
                </select>
              ) : (
                <input
                  className="input w-full text-xs"
                  placeholder={loadingModels ? "Loading…" : "e.g. llama3"}
                  value={pickerModel}
                  onChange={(e) => setPickerModel(e.target.value)}
                />
              )}
            </div>
            <div className="flex gap-2">
              <button className="btn btn-primary btn-sm flex-1 text-xs" onClick={startSession}>Start</button>
              <button className="btn btn-ghost btn-sm text-xs" onClick={() => setShowNewSessionPicker(false)}>Cancel</button>
            </div>
          </div>
        )}

        <div className="flex-1 overflow-y-auto px-2 space-y-1">
          {sessions.map((s) => (
            <button
              key={s.id}
              onClick={() => { setActiveSessionId(s.id); setMessages([]); setActiveModel(null); setCrashedSession(false); setErrorToast(null); }}
              className={`w-full text-left px-3 py-2 rounded-sm text-sm transition-colors flex items-center gap-2 ${
                activeSessionId === s.id
                  ? "bg-primary/10 text-primary border-l-2 border-primary"
                  : "text-on-surface hover:bg-surface-container-highest border-l-2 border-transparent"
              }`}
            >
              <MessageSquare className="w-4 h-4 shrink-0" />
              <div className="truncate">Session {s.id.slice(0, 8)}</div>
            </button>
          ))}
        </div>
      </div>

      {/* ── Main chat ── */}
      <div
        className="flex-1 flex flex-col bg-surface-container-lowest relative overflow-hidden"
        onDragOver={handleDragOver}
        onDrop={handleDrop}
      >
        {!activeSessionId ? (
          <div className="flex-1 flex flex-col items-center justify-center text-on-surface-variant p-8 text-center">
            <Terminal className="w-12 h-12 mb-4 opacity-20" />
            <p className="max-w-md text-sm">
              {credentials.length === 0
                ? "Configure a provider to start using SOC Copilot."
                : "Select a session or start a new one."}
            </p>
            {credentials.length === 0 && (
              <button className="btn btn-primary mt-6" onClick={() => setProvidersModalOpen(true)}>
                Configure Provider
              </button>
            )}
          </div>
        ) : (
          <>
            {/* Session header */}
            <div className="flex items-center justify-between px-6 py-2 border-b border-outline-variant/10 bg-surface-container-lowest">
              <div className="flex items-center gap-2 text-xs text-on-surface-variant">
                <Terminal className="w-3.5 h-3.5" />
                <span className="font-mono">{activeSessionId.slice(0, 8)}</span>
                {activeModel && (
                  <span className="badge badge-outline text-[10px]">{activeModel}</span>
                )}
              </div>
              <button
                className="btn btn-ghost !px-2 text-on-surface-variant hover:text-on-surface"
                onClick={exportSession}
                title="Export session as Markdown"
                disabled={messages.length === 0}
              >
                <Download className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Messages */}
            <div
              className="flex-1 overflow-y-auto p-4 md:p-8 space-y-6"
              onClick={handleChatClick}
            >
              {/* Quick prompts — shown when session is empty */}
              {messages.length === 0 && (
                <div className="h-full flex flex-col items-center justify-center gap-4">
                  <p className="text-xs text-on-surface-variant/60 uppercase tracking-widest">Quick prompts</p>
                  <div className="grid grid-cols-2 gap-2 max-w-lg w-full">
                    {QUICK_PROMPTS.map((p) => (
                      <button
                        key={p.key}
                        className="text-left text-sm px-3 py-2 rounded-sm border border-outline-variant/20 hover:bg-surface-container-high text-on-surface-variant hover:text-on-surface transition-colors flex items-center gap-2"
                        onClick={() => setInput(t(p.key as any, p.fallback))}
                      >
                        <span>{p.icon}</span>
                        <span>{t(p.key as any, p.fallback)}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {messages.map((m) => (
                <div key={m.id} className={`flex gap-4 group ${m.role === "user" ? "justify-end" : "justify-start"}`}>
                  {m.role === "assistant" && (
                    <div className="w-8 h-8 rounded bg-primary/20 flex items-center justify-center shrink-0 border border-primary/30">
                      <Terminal className="w-4 h-4 text-primary" />
                    </div>
                  )}
                  <div
                    className={`max-w-[80%] rounded-sm p-4 text-sm relative ${
                      m.role === "user"
                        ? "bg-surface-container-high text-on-surface border border-outline-variant/10"
                        : "bg-transparent text-on-surface prose prose-invert prose-p:leading-relaxed prose-pre:bg-surface-container-high prose-pre:border prose-pre:border-outline-variant/20"
                    }`}
                  >
                    {m.role === "user" ? (
                      <div className="whitespace-pre-wrap">{m.text}</div>
                    ) : (
                      <>
                        <div dangerouslySetInnerHTML={createMarkup(m.text)} />
                        {m.streaming && (
                          <span className="inline-block w-2 h-4 bg-primary animate-pulse ml-1 align-middle" />
                        )}
                        {/* Copy-as-evidence button */}
                        {!m.streaming && m.text && (
                          <button
                            className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity btn btn-ghost !px-1.5 !py-1 text-on-surface-variant hover:text-on-surface"
                            onClick={(e) => { e.stopPropagation(); copyAsEvidence(m.text); }}
                            title="Copy as evidence"
                          >
                            <Copy className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </>
                    )}
                  </div>
                </div>
              ))}
              <div ref={messagesEndRef} />
            </div>

            {/* Input area */}
            <div className="p-4 border-t border-outline-variant/20 bg-surface-container-lowest">
              <div className="max-w-4xl mx-auto relative">
                {rateLimited && (
                  <div className="absolute -top-12 left-0 right-0 flex justify-center">
                    <div className="bg-error/10 border border-error/20 text-error px-4 py-2 rounded-sm text-xs flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4" />
                      {t("socc.chat.providerRateLimited", "Rate limit exceeded. Try again soon.")}
                    </div>
                  </div>
                )}
                {errorToast && !rateLimited && (
                  <div className="absolute -top-12 left-0 right-0 flex justify-center">
                    <div className="bg-error/10 border border-error/20 text-error px-4 py-2 rounded-sm text-xs flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4" />
                      {errorToast}
                      {crashedSession && (
                        <button
                          className="btn btn-sm btn-error ml-2 text-xs"
                          onClick={restartSession}
                        >
                          {t("socc.chat.restartSession", "Restart session")}
                        </button>
                      )}
                    </div>
                  </div>
                )}

                {/* Attachment chips */}
                {pendingAttachments.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 mb-2">
                    {pendingAttachments.map((att) => (
                      <div
                        key={att.attachmentId}
                        className={`flex items-center gap-1.5 border rounded px-2 py-1 text-xs ${
                          att.error
                            ? "bg-error/10 border-error/30 text-error"
                            : "bg-surface-container-high border-outline-variant/20 text-on-surface-variant"
                        }`}
                        title={att.error}
                      >
                        {att.mimeType?.startsWith("image/") ? (
                          <ImageIcon className="w-3 h-3 shrink-0" />
                        ) : (
                          <FileText className="w-3 h-3 shrink-0" />
                        )}
                        <span className="max-w-[120px] truncate">{att.filename}</span>
                        {att.uploading && (
                          <span className="w-2 h-2 rounded-full bg-current animate-pulse" />
                        )}
                        <button
                          onClick={() => removeAttachment(att.attachmentId)}
                          className="hover:text-error transition-colors"
                        >
                          <XIcon className="w-3 h-3" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}

                {/* Hidden file input */}
                <input
                  ref={fileInputRef}
                  type="file"
                  className="hidden"
                  onChange={(e) => { const f = e.target.files?.[0]; e.target.value = ""; if (f) uploadFile(f); }}
                  disabled={isStreaming || !activeSessionId}
                />

                <div className="relative flex items-end gap-2 bg-surface-container-high border border-outline-variant/20 rounded-sm p-2 focus-within:border-primary/50 focus-within:ring-1 focus-within:ring-primary/50 transition-all">
                  {/* Attach submenu */}
                  <div ref={attachMenuRef} className="relative shrink-0">
                    <button
                      className="btn btn-ghost !px-2 h-10 text-on-surface-variant hover:text-primary"
                      onClick={() => setShowAttachMenu((v) => !v)}
                      disabled={isStreaming || !activeSessionId}
                      title="Attach"
                    >
                      <Paperclip className="w-4 h-4" />
                      <ChevronDown className="w-2.5 h-2.5 ml-0.5" />
                    </button>
                    {showAttachMenu && (
                      <div className="absolute bottom-full left-0 mb-1 bg-surface-container-high border border-outline-variant/20 rounded-sm shadow-lg text-xs py-1 min-w-[160px] z-20">
                        <button
                          className="w-full text-left px-3 py-1.5 hover:bg-surface-container-highest flex items-center gap-2 text-on-surface"
                          onClick={() => openFilePicker("image")}
                        >
                          <ImageIcon className="w-3.5 h-3.5 text-primary" /> Image
                        </button>
                        <button
                          className="w-full text-left px-3 py-1.5 hover:bg-surface-container-highest flex items-center gap-2 text-on-surface"
                          onClick={() => openFilePicker("any")}
                        >
                          <FileCode className="w-3.5 h-3.5 text-primary" /> File / Log / Code
                        </button>
                        <button
                          className="w-full text-left px-3 py-1.5 hover:bg-surface-container-highest flex items-center gap-2 text-on-surface"
                          onClick={async () => {
                            setShowAttachMenu(false);
                            const text = await navigator.clipboard.readText().catch(() => "");
                            if (text.trim()) uploadTextAsAttachment(text, "pasted-text.txt");
                          }}
                        >
                          <ClipboardPaste className="w-3.5 h-3.5 text-primary" /> Paste text
                        </button>
                      </div>
                    )}
                  </div>

                  <TextareaAutosize
                    minRows={1}
                    maxRows={6}
                    placeholder={t("socc.chat.placeholder", "Send a message or IOC…")}
                    className="flex-1 bg-transparent border-0 resize-none p-2 focus:ring-0 text-sm text-on-surface placeholder:text-on-surface-variant/50"
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={handleKeyDown}
                    disabled={isStreaming}
                  />

                  {isStreaming ? (
                    <button
                      className="btn btn-ghost !px-3 h-10 shrink-0 text-error hover:bg-error/10"
                      onClick={handleAbort}
                      title={t("socc.chat.stop", "Stop")}
                    >
                      <Square className="w-4 h-4" />
                    </button>
                  ) : (
                    <button
                      className="btn btn-primary !px-3 h-10 shrink-0"
                      onClick={sendMessage}
                      disabled={!input.trim() && pendingAttachments.length === 0}
                    >
                      <SendHorizontal className="w-4 h-4" />
                    </button>
                  )}
                </div>

                <div className="text-center mt-2 text-[10px] text-outline">
                  SOC Copilot can make mistakes. Verify critical findings independently.
                </div>
              </div>
            </div>
          </>
        )}
      </div>

      {/* IOC popover */}
      {iocPopover && (
        <IocPopover
          ioc={iocPopover.ioc}
          type={iocPopover.type}
          rect={iocPopover.rect}
          onClose={() => setIocPopover(null)}
        />
      )}

      <SoccProvidersModal
        open={providersModalOpen}
        onClose={() => { setProvidersModalOpen(false); loadCredentials(); }}
        highlightCredentialId={highlightCredentialId}
      />
    </div>
  );
}
