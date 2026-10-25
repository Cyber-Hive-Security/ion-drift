import { useEffect, useRef, useState, type KeyboardEvent, type MouseEvent } from "react";
import { useAuth } from "@/hooks/use-auth";
import { useAdvisoryFeedStatus, useSetAdvisoryFeedConsent } from "@/api/queries";

/** The only hosts the feed contacts. Keep in sync with tasks/advisory_feed.rs. */
export const FEED_HOSTS = ["services.nvd.nist.gov", "www.cisa.gov"] as const;

export const FEED_OFF_WARNING =
  "Turning this off means Ion Drift stops downloading vulnerability data and will not learn about new vulnerabilities. Checks continue against data already downloaded (if any), but newly published or newly exploited RouterOS vulnerabilities will not be learned, so they will not be reported for your devices.";

/**
 * Blocks administrators until they answer the vulnerability-feed question.
 * The server is the only record of the answer — there is no client-side
 * "seen" flag — so a reload or another browser shows it again until answered.
 */
export function AdvisoryFeedConsentGate() {
  const { user } = useAuth();
  const { data } = useAdvisoryFeedStatus();
  if (!data || data.consent !== "unanswered") return null;
  if (!user?.is_admin) {
    return (
      <div role="status" className="border-b border-amber-500/40 bg-amber-500/10 px-4 py-2 text-sm text-amber-200">
        Vulnerability feed awaiting administrator confirmation.
      </div>
    );
  }
  return <ConsentDialog />;
}

const FOCUSABLE =
  'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

function ConsentDialog() {
  const [step, setStep] = useState<"choose" | "confirm-off">("choose");
  const setConsent = useSetAdvisoryFeedConsent();
  const dialogRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    dialogRef.current?.focus();
  }, [step]);

  // Once focus reaches <body> (a backdrop click, or a disabled button losing
  // focus after a failed save) the dialog's keydown handler no longer sees
  // Tab. Catch focus wherever it lands outside the dialog and pull it back.
  useEffect(() => {
    const onFocusIn = (e: FocusEvent) => {
      const dialog = dialogRef.current;
      if (dialog && e.target instanceof Node && !dialog.contains(e.target)) {
        dialog.focus();
      }
    };
    document.addEventListener("focusin", onFocusIn, true);
    return () => document.removeEventListener("focusin", onFocusIn, true);
  }, []);

  const refocusFromBackdrop = (e: MouseEvent) => {
    const dialog = dialogRef.current;
    if (dialog && e.target instanceof Node && !dialog.contains(e.target)) {
      e.preventDefault();
      dialog.focus();
    }
  };

  // No close button, no backdrop dismissal, no Escape, and Tab cannot leave:
  // the only exits are the two answers.
  const onKeyDown = (e: KeyboardEvent) => {
    if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      return;
    }
    if (e.key !== "Tab") return;
    const dialog = dialogRef.current;
    if (!dialog) return;
    const focusable = Array.from(dialog.querySelectorAll<HTMLElement>(FOCUSABLE));
    if (focusable.length === 0) {
      e.preventDefault();
      dialog.focus();
      return;
    }
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    const active = document.activeElement;
    if (e.shiftKey && (active === first || active === dialog || !dialog.contains(active))) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && (active === last || !dialog.contains(active))) {
      e.preventDefault();
      first.focus();
    }
  };

  return (
    <div
      data-testid="feed-consent-backdrop"
      role="presentation"
      onMouseDown={refocusFromBackdrop}
      onClick={refocusFromBackdrop}
      className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70">
      {/* eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions -- dialog handles Escape and focus trapping */}
      <div
        ref={dialogRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-labelledby="feed-consent-title"
        onKeyDown={onKeyDown}
        className="mx-4 w-full max-w-lg rounded-lg border border-border bg-card p-6 shadow-xl outline-none"
      >
        {step === "choose" ? (
          <>
            <h2 id="feed-consent-title" className="text-lg font-semibold">Vulnerability feed</h2>
            <p className="mt-3 text-sm text-muted-foreground">
              Ion Drift checks your RouterOS devices against published vulnerabilities. To learn about new
              ones, it downloads public vulnerability data once a day from:
            </p>
            <ul className="mt-2 list-disc pl-5 text-sm">
              {FEED_HOSTS.map((h) => (
                <li key={h}><code>{h}</code></li>
              ))}
            </ul>
            <p className="mt-3 text-sm text-muted-foreground">
              These are plain downloads. Nothing about this installation, your network, or your devices is sent.
            </p>
            {setConsent.isError && (
              <p role="alert" className="mt-3 text-sm text-red-400">Could not save your choice. Try again.</p>
            )}
            <div className="mt-6 flex justify-end gap-3">
              <button type="button" onClick={() => setStep("confirm-off")} disabled={setConsent.isPending}
                className="rounded-md border border-border px-4 py-2 text-sm hover:bg-muted">
                Turn off
              </button>
              <button type="button" onClick={() => setConsent.mutate("on")} disabled={setConsent.isPending}
                className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90">
                Keep on (recommended)
              </button>
            </div>
          </>
        ) : (
          <>
            <h2 id="feed-consent-title" className="text-lg font-semibold">Turn off the vulnerability feed?</h2>
            <p className="mt-3 text-sm text-amber-200">{FEED_OFF_WARNING}</p>
            <p className="mt-3 text-sm text-muted-foreground">You can turn it back on at any time in Settings → Security.</p>
            {setConsent.isError && (
              <p role="alert" className="mt-3 text-sm text-red-400">Could not save your choice. Try again.</p>
            )}
            <div className="mt-6 flex justify-end gap-3">
              <button type="button" onClick={() => setStep("choose")} disabled={setConsent.isPending}
                className="rounded-md border border-border px-4 py-2 text-sm hover:bg-muted">
                Back
              </button>
              <button type="button" onClick={() => setConsent.mutate("off")} disabled={setConsent.isPending}
                className="rounded-md bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-600/90">
                Turn off anyway
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
