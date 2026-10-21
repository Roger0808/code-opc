import { useState } from "react";
import { LoginPage } from "@multica/views/auth";
import { useT } from "@multica/views/i18n";
import { DragStrip } from "@multica/views/platform";
import { Button } from "@multica/ui/components/ui/button";
import { MulticaIcon } from "@multica/ui/components/common/multica-icon";
import {
  beginEnterpriseLogin,
  EnterpriseLoginError,
  exchangeEnterpriseCode,
  runEnterpriseLogin,
} from "../platform/enterprise-login";
import { establishEnterpriseSession } from "../platform/enterprise-session";

function requireRuntimeAppUrl(): string {
  const runtimeConfig = window.desktopAPI.runtimeConfig;
  if (!runtimeConfig.ok) {
    throw new Error(
      "Invariant violated: DesktopLoginPage rendered before App accepted runtime config",
    );
  }
  return runtimeConfig.config.appUrl;
}

export function DesktopLoginPage() {
  const { t } = useT("auth");
  const webUrl = requireRuntimeAppUrl();
  const apiUrl = window.desktopAPI.runtimeConfig.ok
    ? window.desktopAPI.runtimeConfig.config.apiUrl
    : "";
  const platformUrl = window.desktopAPI.runtimeConfig.ok
    ? window.desktopAPI.runtimeConfig.config.platformUrl
    : undefined;
  const [enterprisePending, setEnterprisePending] = useState(false);
  const [enterpriseError, setEnterpriseError] = useState<string | null>(null);

  const handleGoogleLogin = () => {
    // Open web login page in the default browser with platform=desktop flag.
    // The web callback will redirect back via multica:// deep link with the token.
    window.desktopAPI.openExternal(
      `${webUrl}/login?platform=desktop`,
    );
  };

  const handleEnterpriseLogin = async () => {
    if (!platformUrl || enterprisePending) return;
    setEnterprisePending(true);
    setEnterpriseError(null);
    try {
      const session = await runEnterpriseLogin({
        beginAuth: () => window.enterpriseAPI.beginAuth(),
        cancelAuth: () => window.enterpriseAPI.cancelAuth(),
        onAuthCallback: (callback) =>
          window.enterpriseAPI.onAuthCallback(callback),
        openExternal: (url) => window.desktopAPI.openExternal(url),
        exchange: (code, codeVerifier) =>
          exchangeEnterpriseCode(apiUrl, code, codeVerifier),
        begin: (input) => beginEnterpriseLogin(apiUrl, input),
      });
      // Publishes the session and seals the token in the main-process vault.
      await establishEnterpriseSession(session.token, session.user);
      // Auth store update triggers AppContent re-render → shows DesktopShell.
    } catch (err) {
      if (err instanceof EnterpriseLoginError) {
        setEnterpriseError(err.message);
      } else {
        setEnterpriseError(
          err instanceof Error ? err.message : t(($) => $.desktop.enterprise.failed),
        );
      }
    } finally {
      setEnterprisePending(false);
    }
  };

  return (
    <div className="flex h-screen flex-col">
      <DragStrip />
      <LoginPage
        logo={<MulticaIcon bordered size="lg" />}
        onSuccess={() => {
          // Auth store update triggers AppContent re-render → shows DesktopShell.
          // Initial workspace navigation happens in routes.tsx via IndexRedirect.
        }}
        onGoogleLogin={handleGoogleLogin}
        extra={
          platformUrl ? (
            <div className="w-full space-y-2">
              <Button
                type="button"
                variant="outline"
                className="w-full"
                size="lg"
                onClick={() => void handleEnterpriseLogin()}
                disabled={enterprisePending}
              >
                {enterprisePending
                  ? t(($) => $.desktop.enterprise.waiting)
                  : t(($) => $.desktop.enterprise.button)}
              </Button>
              {enterpriseError && (
                <p className="text-body text-destructive">{enterpriseError}</p>
              )}
            </div>
          ) : undefined
        }
      />
    </div>
  );
}
