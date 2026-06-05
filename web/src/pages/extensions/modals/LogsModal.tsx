/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, useEffect, useRef } from "react";
import { Terminal, X, Pause, Play, Copy, Check, ChevronDown, AlertTriangle } from "lucide-react";
import { fetchEventSource } from "@microsoft/fetch-event-source";
import { useLanguage } from "../../../context/LanguageContext";
import API_URL from "../../../config";

interface LogsModalProps {
  extensionId: string;
  extensionName: string;
  onClose: () => void;
}

export default function LogsModal({ extensionId, extensionName, onClose }: LogsModalProps) {
  const { t } = useLanguage();
  const [logs, setLogs] = useState<string[]>([]);
  const [isPaused, setIsPaused] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  useEffect(() => {
    if (isPaused) {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
        abortControllerRef.current = null;
      }
      return;
    }

    const controller = new AbortController();
    abortControllerRef.current = controller;

    void fetchEventSource(`${API_URL}/api/extensions/${extensionId}/logs`, {
      method: "GET",
      credentials: "include",
      signal: controller.signal,
      headers: {
        "Accept": "text/event-stream",
      },
      onmessage(ev) {
        if (ev.event === "log") {
          const rawData = ev.data.replace(/\\n/g, "\n");
          setLogs((prev) => {
            const next = [...prev, rawData];
            if (next.length > 5000) return next.slice(next.length - 5000);
            return next;
          });
        } else if (ev.event === "error") {
          try {
            const data = JSON.parse(ev.data);
            setError(data.message || t("extensions.logs.failedToStream", "Failed to stream logs"));
          } catch {
            setError(t("extensions.logs.unknownError", "Unknown error in log stream"));
          }
        }
      },
      onerror(err) {
        console.error("Log stream error:", err);
        setError(t("extensions.logs.connectionLost", "Connection lost. Retrying..."));
      },
      openWhenHidden: true,
    });

    return () => {
      controller.abort();
      abortControllerRef.current = null;
    };
  }, [extensionId, isPaused]);

  useEffect(() => {
    if (!isPaused && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs, isPaused]);

  const handleCopy = () => {
    const allLogs = logs.join("");
    void navigator.clipboard.writeText(allLogs);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <div className="card w-full max-w-4xl h-[80vh] flex flex-col overflow-hidden animate-in fade-in slide-in-from-bottom-4 duration-300">
        <div className="p-4 bg-inverse-surface border-b border-white/5 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Terminal className="w-5 h-5 text-primary" />
            <div>
              <h2 className="text-sm font-black text-white uppercase tracking-tight">
                {extensionName} — {t("extensions.logs.title", "System Logs")}
              </h2>
              <div className="flex items-center gap-2">
                <span className={`w-1.5 h-1.5 rounded-full ${isPaused ? "bg-amber-500" : "bg-green-500 animate-pulse"}`}></span>
                <span className="text-[10px] text-white/40 font-bold uppercase tracking-widest">
                  {isPaused ? t("extensions.logs.paused", "Stream Paused") : t("extensions.logs.live", "Live Stream")}
                </span>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setIsPaused(!isPaused)}
              className="p-2 rounded-sm text-white/60 hover:text-white hover:bg-white/5 transition-colors"
              title={isPaused ? t("common.resume", "Resume") : t("common.pause", "Pause")}
            >
              {isPaused ? <Play className="w-4 h-4" /> : <Pause className="w-4 h-4" />}
            </button>
            <button
              onClick={handleCopy}
              className="p-2 rounded-sm text-white/60 hover:text-white hover:bg-white/5 transition-colors"
              title={t("common.copy", "Copy")}
            >
              {copied ? <Check className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4" />}
            </button>
            <div className="w-px h-4 bg-white/10 mx-1"></div>
            <button
              onClick={onClose}
              className="p-2 rounded-sm text-white/60 hover:text-white hover:bg-white/5 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        <div 
          ref={scrollRef}
          className="flex-1 bg-black p-4 font-mono text-[11px] leading-relaxed overflow-y-auto selection:bg-primary/30"
        >
          {logs.length === 0 && !error && (
            <div className="h-full flex items-center justify-center text-white/20 uppercase tracking-[0.2em]">
              {t("extensions.logs.waiting", "Waiting for log stream...")}
            </div>
          )}
          
          {error && (
            <div className="mb-4 p-2 rounded-sm bg-error/10 border border-error/20 text-error flex items-center gap-2">
              <AlertTriangle className="w-3 h-3" />
              {error}
            </div>
          )}

          <div className="space-y-0.5 whitespace-pre-wrap break-all">
            {logs.map((log, i) => (
              <div key={i} className="text-white/80 hover:text-white transition-colors">
                <span className="text-white/30 mr-3 select-none">{(i + 1).toString().padStart(4, "0")}</span>
                {log}
              </div>
            ))}
          </div>
        </div>

        <div className="p-3 bg-inverse-surface border-t border-white/5 flex items-center justify-between">
          <p className="text-[10px] text-white/40 uppercase tracking-widest">
            {logs.length} {t("extensions.logs.lines_buffer", "lines in buffer")}
          </p>
          <button 
            onClick={() => scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" })}
            className="flex items-center gap-1.5 text-[10px] text-primary font-bold uppercase tracking-widest hover:underline"
          >
            {t("extensions.logs.scroll_to_bottom", "Scroll to bottom")}
            <ChevronDown className="w-3 h-3" />
          </button>
        </div>
      </div>
    </div>
  );
}
