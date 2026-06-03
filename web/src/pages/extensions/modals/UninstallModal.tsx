/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState } from "react";
import { AlertTriangle, Loader2 } from "lucide-react";
import { useLanguage } from "../../../context/LanguageContext";
import { type ExtensionManifest } from "../lib/api";

interface UninstallModalProps {
  extension: ExtensionManifest;
  onClose: () => void;
  onConfirm: (confirmPhrase: string, destroyVolumes: boolean) => void;
  loading?: boolean;
}

export default function UninstallModal({ extension, onClose, onConfirm, loading }: UninstallModalProps) {
  const { t } = useLanguage();
  const [phrase, setPhrase] = useState("");
  const [destroyVolumes, setDestroyVolumes] = useState(extension.uninstall.destroy_volumes_by_default);

  const isValid = phrase === extension.uninstall.confirm_phrase;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <div className="card w-full max-w-md border-error/20 overflow-hidden animate-in fade-in zoom-in duration-200">
        <div className="p-6">
          <div className="flex items-center gap-3 text-error mb-4">
            <AlertTriangle className="w-6 h-6" />
            <h2 className="text-lg font-black uppercase tracking-tight">
              {t("extensions.uninstall.title", "Confirm Uninstall")}
            </h2>
          </div>

          <p className="text-sm text-on-surface-variant mb-6">
            {t("extensions.uninstall.warning", "This action is destructive. All running processes for this extension will be stopped.")}
          </p>

          <div className="space-y-4">
            <div>
              <label className="block text-[10px] font-bold text-outline uppercase tracking-widest mb-1.5">
                {t("extensions.uninstall.phrase_label", "Confirmation Phrase")}
              </label>
              <input
                type="text"
                value={phrase}
                onChange={(e) => setPhrase(e.target.value)}
                placeholder={extension.uninstall.confirm_phrase}
                className="w-full bg-surface-container-high border border-outline-variant/20 rounded-sm px-3 py-2 text-sm focus:outline-none focus:border-error/50 transition-colors"
                autoFocus
              />
              <p className="mt-1.5 text-[10px] text-on-surface-variant">
                {t("extensions.uninstall.phrase_hint", "Type the phrase above to confirm.")}
              </p>
            </div>

            <label className="flex items-center gap-3 p-3 rounded-sm bg-surface-container-high border border-outline-variant/10 cursor-pointer hover:bg-surface-container-highest transition-colors">
              <input
                type="checkbox"
                checked={destroyVolumes}
                onChange={(e) => setDestroyVolumes(e.target.checked)}
                className="w-4 h-4 rounded-sm border-outline-variant bg-surface text-primary focus:ring-primary focus:ring-offset-surface-container-high"
              />
              <div className="flex-1">
                <p className="text-xs font-bold text-on-surface">
                  {t("extensions.uninstall.destroy_volumes", "Destroy persistent data volumes")}
                </p>
                <p className="text-[10px] text-error font-medium">
                  {t("extensions.uninstall.destroy_volumes_warning", "Warning: This will delete all saved data for this extension.")}
                </p>
              </div>
            </label>
          </div>
        </div>

        <div className="p-4 bg-surface-container-low border-t border-outline-variant/10 flex gap-3">
          <button
            onClick={onClose}
            disabled={loading}
            className="btn btn-ghost flex-1"
          >
            {t("common.cancel", "Cancel")}
          </button>
          <button
            onClick={() => onConfirm(phrase, destroyVolumes)}
            disabled={!isValid || loading}
            className="btn btn-primary bg-error hover:bg-error-dark flex-1 gap-2"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
            {t("extensions.actions.uninstall", "Uninstall")}
          </button>
        </div>
      </div>
    </div>
  );
}
