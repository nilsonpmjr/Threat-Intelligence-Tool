import { useState, useRef, useEffect, KeyboardEvent } from "react";
import { fetchEventSource } from "@microsoft/fetch-event-source";
import { marked } from "marked";
import DOMPurify from "dompurify";
import { createHighlighter } from "shiki";
import TextareaAutosize from "react-textarea-autosize";
import { Settings, Plus, SendHorizontal, Square, AlertTriangle, MessageSquare, Terminal } from "lucide-react";
import { useLanguage } from "../../context/LanguageContext";
import API_URL from "../../config";
import SoccProvidersModal from "./SoccProvidersModal";

// Setup shiki highlight inside marked
let highlighter: any = null;
createHighlighter({
  themes: ['github-dark'],
  langs: ['javascript', 'typescript', 'python', 'bash', 'json', 'yaml', 'markdown']
}).then(hl => {
  highlighter = hl;
});

// Configure marked
marked.setOptions({
  async: false,
  gfm: true,
  breaks: true,
});

const renderer = new marked.Renderer();
renderer.code = ({ text, lang }) => {
  if (highlighter && lang && highlighter.getLoadedLanguages().includes(lang)) {
    try {
      return highlighter.codeToHtml(text, { lang, theme: 'github-dark' });
    } catch (e) {
      // fallback
    }
  }
  return `<pre><code>${DOMPurify.sanitize(text)}</code></pre>`;
};
marked.use({ renderer });

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

export default function SoccChat() {
  const { t } = useLanguage();
  const [providersModalOpen, setProvidersModalOpen] = useState(false);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [isStreaming, setIsStreaming] = useState(false);
  const [credentials, setCredentials] = useState<any[]>([]);
  const abortControllerRef = useRef<AbortController | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const [errorToast, setErrorToast] = useState<string | null>(null);
  const [rateLimited, setRateLimited] = useState(false);

  useEffect(() => {
    loadCredentials();
    loadSessions();
  }, []);

  useEffect(() => {
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages]);

  async function loadCredentials() {
    try {
      const res = await fetch(`${API_URL}/api/socc/providers`, { credentials: "include" });
      if (res.ok) {
        const data = await res.json();
        setCredentials(data.credentials || []);
      }
    } catch (err) {}
  }

  async function loadSessions() {
    try {
      const res = await fetch(`${API_URL}/api/socc/session`, { credentials: "include" });
      if (res.ok) {
        const data = await res.json();
        setSessions(data.sessions || []);
      }
    } catch (err) {}
  }

  async function handleNewSession() {
    if (credentials.length === 0) {
      setProvidersModalOpen(true);
      return;
    }
    try {
      // Use the first available credential
      const credId = credentials[0].id;
      const res = await fetch(`${API_URL}/api/socc/session`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ credentialId: credId })
      });
      if (res.ok) {
        const data = await res.json();
        setSessions([{ id: data.sessionId, createdAt: new Date().toISOString(), promptCount: 0 }, ...sessions]);
        setActiveSessionId(data.sessionId);
        setMessages([]);
      }
    } catch (err) {}
  }

  function handleKeyDown(e: KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  }

  async function sendMessage() {
    if (!input.trim() || !activeSessionId || isStreaming) return;
    const text = input.trim();
    setInput("");
    setErrorToast(null);
    setRateLimited(false);
    
    const userMsgId = Date.now().toString();
    setMessages(prev => [...prev, { id: userMsgId, role: "user", text }]);
    
    const assistantMsgId = (Date.now() + 1).toString();
    setMessages(prev => [...prev, { id: assistantMsgId, role: "assistant", text: "", streaming: true }]);
    setIsStreaming(true);

    abortControllerRef.current = new AbortController();

    try {
      await fetchEventSource(`${API_URL}/api/socc/session/${activeSessionId}/message`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ text }),
        signal: abortControllerRef.current.signal,
        openWhenHidden: true,
        async onopen(response) {
          if (response.status === 429) {
            setRateLimited(true);
            throw new Error("Rate limited");
          }
          if (response.ok && response.headers.get("content-type")?.includes("text/event-stream")) {
            return;
          }
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
              } else {
                setErrorToast(data.message || t("socc.chat.sessionError", "A session error occurred."));
              }
            } catch (e) {}
            throw new Error("Stream error");
          }
          
          if (msg.event === "content" || !msg.event) {
            try {
              const data = msg.data ? JSON.parse(msg.data) : {};
              if (data.type === "content_block_delta" || data.delta) {
                const chunk = data.delta?.text || data.text || "";
                setMessages(prev => prev.map(m => 
                  m.id === assistantMsgId ? { ...m, text: m.text + chunk } : m
                ));
              }
            } catch(e) {
              // some streams just send plain text if not structured
              if (msg.data && !msg.data.startsWith("{")) {
                setMessages(prev => prev.map(m => 
                  m.id === assistantMsgId ? { ...m, text: m.text + msg.data } : m
                ));
              }
            }
          }
          
          if (msg.event === "message.end" || msg.event === "done") {
             setMessages(prev => prev.map(m => 
                m.id === assistantMsgId ? { ...m, streaming: false } : m
             ));
          }
        },
        onclose() {
          setIsStreaming(false);
          setMessages(prev => prev.map(m => 
            m.id === assistantMsgId ? { ...m, streaming: false } : m
          ));
        },
        onerror(err) {
          setIsStreaming(false);
          setMessages(prev => prev.map(m => 
            m.id === assistantMsgId ? { ...m, streaming: false } : m
          ));
          if (!rateLimited && !errorToast) {
            setErrorToast(t("socc.chat.sessionError", "A session error occurred."));
          }
          throw err; // throw to stop retrying
        }
      });
    } catch (err) {
      setIsStreaming(false);
      setMessages(prev => prev.map(m => 
        m.id === assistantMsgId ? { ...m, streaming: false } : m
      ));
    }
  }

  async function handleAbort() {
    if (!activeSessionId) return;
    try {
      abortControllerRef.current?.abort();
      setIsStreaming(false);
      await fetch(`${API_URL}/api/socc/session/${activeSessionId}/abort`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({})
      });
    } catch (err) {}
  }

  function createMarkup(text: string) {
    if (!text) return { __html: "" };
    // marked.parse can be string or promise. with async: false it's string.
    const rawMarkup = marked.parse(text) as string;
    return { __html: DOMPurify.sanitize(rawMarkup) };
  }

  return (
    <div className="flex h-[calc(100vh-4rem)] bg-background -m-8">
      {/* Sidebar */}
      <div className="w-64 flex-shrink-0 border-r border-outline-variant/20 bg-surface-container-lowest flex flex-col">
        <div className="p-4 border-b border-outline-variant/20 flex items-center justify-between">
          <h2 className="text-sm font-bold text-on-surface uppercase tracking-widest">{t("socc.nav", "SOC Copilot")}</h2>
          <button className="btn btn-ghost !px-2" onClick={() => setProvidersModalOpen(true)} title="Providers Settings">
            <Settings className="w-4 h-4" />
          </button>
        </div>
        <div className="p-4">
          <button className="btn btn-primary w-full" onClick={handleNewSession}>
            <Plus className="w-4 h-4 mr-2" />
            New Session
          </button>
        </div>
        <div className="flex-1 overflow-y-auto px-2 space-y-1">
          {sessions.map(s => (
            <button 
              key={s.id}
              onClick={() => { setActiveSessionId(s.id); setMessages([]); }}
              className={`w-full text-left px-3 py-2 rounded-sm text-sm transition-colors flex items-center gap-2
                ${activeSessionId === s.id ? "bg-primary/10 text-primary border-l-2 border-primary" : "text-on-surface hover:bg-surface-container-highest border-l-2 border-transparent"}`}
            >
              <MessageSquare className="w-4 h-4 shrink-0" />
              <div className="truncate">
                Session {s.id.substring(0, 8)}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Main Chat Area */}
      <div className="flex-1 flex flex-col bg-surface-container-lowest relative overflow-hidden">
        {!activeSessionId ? (
          <div className="flex-1 flex flex-col items-center justify-center text-on-surface-variant p-8 text-center">
            <Terminal className="w-12 h-12 mb-4 opacity-20" />
            <p className="max-w-md">
              {credentials.length === 0 
                ? "Configure a provider in settings to start using SOC Copilot." 
                : "Select a session from the sidebar or start a new one to begin."}
            </p>
            {credentials.length === 0 && (
              <button className="btn btn-primary mt-6" onClick={() => setProvidersModalOpen(true)}>
                Configure Provider
              </button>
            )}
          </div>
        ) : (
          <>
            <div className="flex-1 overflow-y-auto p-4 md:p-8 space-y-6">
              {messages.length === 0 && (
                <div className="h-full flex items-center justify-center text-on-surface-variant opacity-50">
                  {t("socc.chat.placeholder", "Send a message or IOC...")}
                </div>
              )}
              {messages.map((m, i) => (
                <div key={m.id} className={`flex gap-4 ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                  {m.role === 'assistant' && (
                    <div className="w-8 h-8 rounded bg-primary/20 flex items-center justify-center shrink-0 border border-primary/30">
                      <Terminal className="w-4 h-4 text-primary" />
                    </div>
                  )}
                  <div className={`max-w-[80%] rounded-sm p-4 text-sm ${m.role === 'user' ? 'bg-surface-container-high text-on-surface border border-outline-variant/10' : 'bg-transparent text-on-surface prose prose-invert prose-p:leading-relaxed prose-pre:bg-surface-container-high prose-pre:border prose-pre:border-outline-variant/20'}`}>
                     {m.role === 'user' ? (
                       <div className="whitespace-pre-wrap">{m.text}</div>
                     ) : (
                       <>
                         <div dangerouslySetInnerHTML={createMarkup(m.text)} />
                         {m.streaming && <span className="inline-block w-2 h-4 bg-primary animate-pulse ml-1 align-middle" />}
                       </>
                     )}
                  </div>
                </div>
              ))}
              <div ref={messagesEndRef} />
            </div>

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
                    </div>
                  </div>
                )}
                <div className="relative flex items-end gap-2 bg-surface-container-high border border-outline-variant/20 rounded-sm p-2 focus-within:border-primary/50 focus-within:ring-1 focus-within:ring-primary/50 transition-all">
                  <TextareaAutosize
                    minRows={1}
                    maxRows={6}
                    placeholder={t("socc.chat.placeholder", "Send a message or IOC...")}
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
                      disabled={!input.trim()}
                    >
                      <SendHorizontal className="w-4 h-4" />
                    </button>
                  )}
                </div>
                <div className="text-center mt-2 text-[10px] text-outline">
                  SOC Copilot can make mistakes. Check important info.
                </div>
              </div>
            </div>
          </>
        )}
      </div>

      <SoccProvidersModal open={providersModalOpen} onClose={() => { setProvidersModalOpen(false); loadCredentials(); }} />
    </div>
  );
}
