/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { Package, RefreshCw, Play, Square, History, Settings, Shield, Trash2, AlertTriangle, CheckCircle2, Loader2, Pause } from "lucide-react";
import { type ExtensionManifest, type ExtensionStatus } from "./lib/api";
import { useLanguage } from "../../context/LanguageContext";
import { useAuth } from "../../context/AuthContext";
import { clsx } from "clsx";

interface ExtensionCardProps {
  extension: ExtensionManifest;
  onAction: (id: string, action: string) => void;
  busy?: boolean;
}

const statusConfig: Record<ExtensionStatus, { color: string; icon: any; labelKey: string }> = {
  not_installed: { color: "text-outline bg-surface-container", icon: Package, labelKey: "extensions.status.not_installed" },
  installing: { color: "text-amber-500 bg-amber-500/10", icon: Loader2, labelKey: "extensions.status.installing" },
  installed_healthy: { color: "text-green-500 bg-green-500/10", icon: CheckCircle2, labelKey: "extensions.status.healthy" },
  installed_unhealthy: { color: "text-amber-500 bg-amber-500/10", icon: AlertTriangle, labelKey: "extensions.status.unhealthy" },
  stopped: { color: "text-outline bg-surface-container", icon: Pause, labelKey: "extensions.status.stopped" },
  installing_failed: { color: "text-error bg-error/10", icon: AlertTriangle, labelKey: "extensions.status.failed" },
  uninstalling: { color: "text-amber-500 bg-amber-500/10", icon: Loader2, labelKey: "extensions.status.uninstalling" },
};

export default function ExtensionCard({ extension, onAction, busy }: ExtensionCardProps) {
  const { t } = useLanguage();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const status = statusConfig[extension.status] || statusConfig.not_installed;
  const StatusIcon = status.icon;

  const isTransitioning = extension.status === "installing" || extension.status === "uninstalling";
  const proxyDown = extension.requires.docker_socket_proxy && 
    (extension.last_error?.toLowerCase().includes("docker proxy unreachable") || 
     extension.last_error?.toLowerCase().includes("docker-socket-proxy unreachable"));

  return (
    <div className="card flex flex-col h-full group transition-all hover:border-primary/30">
      <div className="p-5 flex-1">
        <div className="flex items-start justify-between mb-4">
          <div className="w-12 h-12 rounded-sm bg-surface-container-high flex items-center justify-center text-primary border border-outline-variant/10">
            <Package className="w-6 h-6" />
          </div>
          <div className="flex flex-col items-end gap-2">
            <span className="badge badge-neutral text-[10px] px-2 py-0.5">v{extension.version}</span>
            <div className={clsx("flex items-center gap-1.5 px-2 py-1 rounded-sm text-[10px] font-bold uppercase tracking-wider", status.color)}>
              <StatusIcon className={clsx("w-3 h-3", extension.status === "installing" || extension.status === "uninstalling" ? "animate-spin" : "")} />
              {t(status.labelKey, extension.status.replace("_", " "))}
            </div>
          </div>
        </div>

        <h3 className="text-base font-bold text-on-surface mb-1 group-hover:text-primary transition-colors">
          {extension.name}
        </h3>
        <p className="text-sm text-on-surface-variant line-clamp-2 mb-4 h-10">
          {extension.description}
        </p>

        {extension.last_health_ts && (
          <div className="flex items-center gap-2 text-[10px] text-outline uppercase tracking-widest mt-auto">
            <History className="w-3 h-3" />
            {t("extensions.last_seen", "Last seen")}: {new Date(extension.last_health_ts).toLocaleString()}
          </div>
        )}

        {extension.last_error && !isTransitioning && (
          <div className="mt-3 p-2 rounded-sm bg-error/5 border border-error/10 text-[10px] text-error flex gap-2">
            <AlertTriangle className="w-3 h-3 shrink-0" />
            <span className="line-clamp-2">{extension.last_error}</span>
          </div>
        )}
      </div>

      <div className="p-4 border-t border-outline-variant/10 bg-surface-container-low flex flex-wrap gap-2">
        {extension.status === "not_installed" || extension.status === "installing_failed" ? (
          <div className="w-full relative group/tooltip">
            <button
              onClick={() => onAction(extension.id, "install")}
              disabled={busy || isTransitioning || !isAdmin || proxyDown}
              className="btn btn-primary w-full gap-2"
            >
              <Play className="w-3.5 h-3.5" />
              {t("extensions.actions.install", "Install")}
            </button>
            {proxyDown && (
              <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-3 py-2 bg-inverse-surface text-inverse-on-surface text-[10px] rounded shadow-lg invisible group-hover/tooltip:visible w-48 text-center z-50">
                {t("extensions.error.proxy_down", "Docker Socket Proxy unreachable. Installation disabled.")}
                <div className="absolute top-full left-1/2 -translate-x-1/2 border-8 border-transparent border-t-inverse-surface"></div>
              </div>
            )}
          </div>
        ) : (
          <>
            {extension.status === "stopped" && isAdmin && (
              <button
                onClick={() => onAction(extension.id, "start")}
                disabled={busy || isTransitioning}
                className="btn btn-primary btn-sm flex-1 gap-1.5"
                title={t("extensions.actions.start", "Start")}
              >
                <Play className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">{t("extensions.actions.start", "Start")}</span>
              </button>
            )}
            
            {extension.status.startsWith("installed_healthy") && isAdmin && (
              <button
                onClick={() => onAction(extension.id, "stop")}
                disabled={busy || isTransitioning}
                className="btn btn-outline btn-sm flex-1 gap-1.5"
                title={t("extensions.actions.stop", "Stop")}
              >
                <Square className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">{t("extensions.actions.stop", "Stop")}</span>
              </button>
            )}

            {(extension.status.startsWith("installed") || extension.status === "stopped") && (
              <>
                {isAdmin && (
                  <button
                    onClick={() => onAction(extension.id, "restart")}
                    disabled={busy || isTransitioning}
                    className="btn btn-outline btn-sm p-2"
                    title={t("extensions.actions.restart", "Restart")}
                  >
                    <RefreshCw className={clsx("w-3.5 h-3.5", busy && "animate-spin")} />
                  </button>
                )}
                
                <button
                  onClick={() => onAction(extension.id, "logs")}
                  disabled={busy || isTransitioning}
                  className="btn btn-outline btn-sm p-2"
                  title={t("extensions.actions.logs", "Logs")}
                >
                  <History className="w-3.5 h-3.5" />
                </button>

                {isAdmin && (
                  <button
                    onClick={() => onAction(extension.id, "settings")}
                    disabled={busy || isTransitioning}
                    className="btn btn-outline btn-sm p-2"
                    title={t("extensions.actions.settings", "Settings")}
                  >
                    <Settings className="w-3.5 h-3.5" />
                  </button>
                )}

                {isAdmin && extension.secrets && extension.secrets.length > 0 && (
                  <button
                    onClick={() => onAction(extension.id, "secrets")}
                    disabled={busy || isTransitioning}
                    className="btn btn-outline btn-sm p-2"
                    title={t("extensions.actions.secrets", "Secrets")}
                  >
                    <Shield className="w-3.5 h-3.5" />
                  </button>
                )}

                {isAdmin && (
                  <button
                    onClick={() => onAction(extension.id, "uninstall")}
                    disabled={busy || isTransitioning}
                    className="btn btn-ghost btn-sm p-2 text-error hover:bg-error/10 ml-auto"
                    title={t("extensions.actions.uninstall", "Uninstall")}
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                )}
              </>
            )}
          </>
        )}

        {isTransitioning && (
          <div className="w-full flex items-center justify-center py-2 text-[10px] text-amber-500 font-bold uppercase tracking-widest gap-2">
            <Loader2 className="w-3 h-3 animate-spin" />
            {t("extensions.transitioning", "Action in progress...")}
          </div>
        )}
      </div>
    </div>
  );
}
