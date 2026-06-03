/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState } from "react";
import { Settings, X, Loader2, Save } from "lucide-react";
import { useLanguage } from "../../../context/LanguageContext";
import { type ExtensionManifest } from "../lib/api";

interface SettingsModalProps {
  extension: ExtensionManifest;
  onClose: () => void;
  onSave: (settings: Record<string, any>) => void;
  loading?: boolean;
}

export default function SettingsModal({ extension, onClose, onSave, loading }: SettingsModalProps) {
  const { t } = useLanguage();
  const [values, setValues] = useState<Record<string, any>>(extension.settings || {});

  const handleToggle = (key: string) => {
    setValues((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const handleChange = (key: string, value: any) => {
    setValues((prev) => ({ ...prev, [key]: value }));
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <div className="card w-full max-w-lg flex flex-col overflow-hidden animate-in fade-in zoom-in duration-200">
        <div className="p-4 bg-surface-container-high border-b border-outline-variant/10 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Settings className="w-5 h-5 text-primary" />
            <div>
              <h2 className="text-sm font-black uppercase tracking-tight">
                {t("extensions.settings.title", "Extension Settings")}
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

        <div className="flex-1 p-6 space-y-6 overflow-y-auto">
          {extension.settings_schema.map((field) => (
            <div key={field.key} className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-sm font-bold text-on-surface">
                  {field.label}
                </label>
                <code className="text-[10px] text-outline px-1.5 py-0.5 bg-surface-container rounded-sm">
                  {field.key}
                </code>
              </div>

              {field.type === "boolean" && (
                <button
                  type="button"
                  onClick={() => handleToggle(field.key)}
                  disabled={loading}
                  className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 ${
                    values[field.key] ? "bg-primary" : "bg-outline-variant"
                  }`}
                >
                  <span
                    className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                      values[field.key] ? "translate-x-5" : "translate-x-0"
                    }`}
                  />
                </button>
              )}

              {field.type === "string" && (
                <input
                  type="text"
                  value={values[field.key] ?? ""}
                  onChange={(e) => handleChange(field.key, e.target.value)}
                  disabled={loading}
                  className="w-full bg-surface-container-high border border-outline-variant/20 rounded-sm px-3 py-2 text-sm focus:outline-none focus:border-primary/50 transition-colors"
                />
              )}

              {field.type === "integer" && (
                <input
                  type="number"
                  value={values[field.key] ?? 0}
                  onChange={(e) => handleChange(field.key, parseInt(e.target.value, 10))}
                  disabled={loading}
                  className="w-full bg-surface-container-high border border-outline-variant/20 rounded-sm px-3 py-2 text-sm focus:outline-none focus:border-primary/50 transition-colors"
                />
              )}
            </div>
          ))}

          {extension.settings_schema.length === 0 && (
            <div className="text-center py-8">
              <p className="text-sm text-on-surface-variant italic">
                {t("extensions.settings.no_schema", "This extension has no configurable settings.")}
              </p>
            </div>
          )}
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
            onClick={() => onSave(values)}
            disabled={loading}
            className="btn btn-primary flex-1 gap-2"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
            {t("common.save", "Save Changes")}
          </button>
        </div>
      </div>
    </div>
  );
}
