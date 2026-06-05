import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { CheckCircle2, XCircle, Loader2 } from "lucide-react";
import { useLanguage } from "../../context/LanguageContext";
import API_URL from "../../config";

const CHANNEL_NAME = "socc-oauth";

function decodeStateProvider(state: string): string | null {
  try {
    const parts = state.split(".");
    if (parts.length !== 3) return null;
    const padded = parts[1]
      .replace(/-/g, "+")
      .replace(/_/g, "/")
      .padEnd(parts[1].length + ((4 - (parts[1].length % 4)) % 4), "=");
    const payload = JSON.parse(atob(padded));
    return payload.provider ?? null;
  } catch {
    return null;
  }
}

type Status = "exchanging" | "success" | "error";

export default function SoccOAuthCallback() {
  const { t } = useLanguage();
  const [params] = useSearchParams();
  const handled = useRef(false);
  const [status, setStatus] = useState<Status>("exchanging");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    if (handled.current) return;
    handled.current = true;

    const code = params.get("code");
    const state = params.get("state");
    const channel = new BroadcastChannel(CHANNEL_NAME);

    async function run() {
      if (!code || !state) {
        const msg = t("socc.callback.missingParams", "Missing OAuth parameters in callback URL.");
        channel.postMessage({ type: "socc-oauth-error", message: msg });
        setStatus("error");
        setErrorMsg(msg);
        channel.close();
        return;
      }

      const provider = decodeStateProvider(state);
      if (!provider) {
        const msg = t("socc.callback.invalidState", "Invalid OAuth state.");
        channel.postMessage({ type: "socc-oauth-error", message: msg });
        setStatus("error");
        setErrorMsg(msg);
        channel.close();
        return;
      }

      try {
        const res = await fetch(`${API_URL}/api/socc/auth/${provider}/callback`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({ code, state }),
        });
        const data = await res.json();

        if (!res.ok) {
          const msg = data.error || data.message || t("socc.callback.exchangeFailed", "Authorization failed.");
          channel.postMessage({ type: "socc-oauth-error", message: msg });
          setStatus("error");
          setErrorMsg(msg);
          channel.close();
          return;
        }

        channel.postMessage({ type: "socc-oauth-success", credentialId: data.credentialId, provider });
        setStatus("success");
        channel.close();

        // Brief visual confirmation before the tab closes itself.
        setTimeout(() => window.close(), 1200);
      } catch (err: any) {
        const msg = err.message || t("socc.callback.exchangeFailed", "Authorization failed.");
        channel.postMessage({ type: "socc-oauth-error", message: msg });
        setStatus("error");
        setErrorMsg(msg);
        channel.close();
      }
    }

    run();
  }, []);

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-8">
      <div className="card p-8 max-w-sm w-full text-center space-y-4">
        {status === "exchanging" && (
          <>
            <Loader2 className="w-10 h-10 mx-auto animate-spin text-primary" />
            <p className="text-sm text-on-surface-variant">
              {t("socc.callback.loading", "Finalizing authorization…")}
            </p>
          </>
        )}
        {status === "success" && (
          <>
            <CheckCircle2 className="w-10 h-10 mx-auto text-success" />
            <p className="text-sm font-medium text-on-surface">
              {t("socc.callback.success", "Authorization successful.")}
            </p>
            <p className="text-xs text-on-surface-variant">
              {t("socc.callback.closing", "This tab will close automatically.")}
            </p>
          </>
        )}
        {status === "error" && (
          <>
            <XCircle className="w-10 h-10 mx-auto text-error" />
            <p className="text-sm font-medium text-on-surface">
              {t("socc.callback.errorTitle", "Authorization failed.")}
            </p>
            {errorMsg && (
              <p className="text-xs text-on-surface-variant">{errorMsg}</p>
            )}
            <p className="text-xs text-on-surface-variant">
              {t("socc.callback.closeManually", "You may close this tab.")}
            </p>
          </>
        )}
      </div>
    </div>
  );
}
