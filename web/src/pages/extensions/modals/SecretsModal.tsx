/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { Shield, X, RefreshCw, Loader2, AlertCircle } from "lucide-react";
import { useLanguage } from "../../../context/LanguageContext";
import { type ExtensionManifest } from "../lib/api";

interface SecretsModalProps {
  extension: ExtensionManifest;
  onClose: () => void;
  onRotate: (secretName: string) => void;
  loadingSecret?: string | null;
}

export default function SecretsModal({ extension, onClose, onRotate, loadingSecret }: SecretsModalProps) {
  const { t } = useLanguage();

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <div className="card w-full max-w-lg flex flex-col overflow-hidden animate-in fade-in zoom-in duration-200">
        <div className="p-4 bg-surface-container-high border-b border-outline-variant/10 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-5 h-5 text-primary" />
            <div>
              <h2 className="text-sm font-black uppercase tracking-tight">
                {t("extensions.secrets.title", "Extension Secrets")}
              </h2>
              <p className="text-[10px] text-on-surface-variant font-bold uppercase tracking-widest">
                {extension.name}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-sm hover:bg-surface-container-highest text-on-surface-variant transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="flex-1 p-6 space-y-4 overflow-y-auto">
          <div className="p-3 rounded-sm bg-primary/5 border border-primary/10 flex gap-3">
            <AlertCircle className="w-4 h-4 text-primary shrink-0" />
            <p className="text-[10px] text-on-surface-variant leading-relaxed">
              {t("extensions.secrets.warning", "Secrets are managed securely by the backend. You can only trigger a rotation; the current values are never exposed to the UI.")}
            </p>
          </div>

          <div className="divide-y divide-outline-variant/10">
            {extension.secrets?.map((secret) => {
              const lastRotated = extension.secrets_present?.[secret.name];
              const isRotating = loadingSecret === secret.name;
              
              return (
                <div key={secret.name} className="py-4 first:pt-0 last:pb-0 flex items-center justify-between">
                  <div>
                    <p className="text-sm font-bold text-on-surface">{secret.name}</p>
                    <p className="text-[10px] text-outline font-medium uppercase tracking-widest mt-1">
                      {lastRotated 
                        ? `${t("extensions.secrets.last_rotated", "Last rotated")}: ${new Date(lastRotated).toLocaleString()}`
                        : t("extensions.secrets.not_rotated", "Never rotated")}
                    </p>
                  </div>
                  <button
                    onClick={() => onRotate(secret.name)}
                    disabled={!!loadingSecret}
                    className="btn btn-outline btn-sm gap-2"
                  >
                    {isRotating ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
                    {t("extensions.actions.rotate", "Rotate")}
                  </button>
                </div>
              );
            })}

            {(!extension.secrets || extension.secrets.length === 0) && (
              <div className="text-center py-8">
                <p className="text-sm text-on-surface-variant italic">
                  {t("extensions.secrets.none", "This extension requires no secrets.")}
                </p>
              </div>
            )}
          </div>
        </div>

        <div className="p-4 bg-surface-container-low border-t border-outline-variant/10">
          <button
            onClick={onClose}
            className="btn btn-ghost w-full"
          >
            {t("common.close", "Close")}
          </button>
        </div>
      </div>
    </div>
  );
}
