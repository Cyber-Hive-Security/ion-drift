import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useLicenseStatus } from "@/api/queries";

export function SettingsLicense() {
  const { data: license, isLoading } = useLicenseStatus();
  const queryClient = useQueryClient();
  const [showKeyForm, setShowKeyForm] = useState(false);
  const [licenseKey, setLicenseKey] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [keyError, setKeyError] = useState<string | null>(null);
  const [keySuccess, setKeySuccess] = useState(false);

  const handleSubmitKey = async (e: React.FormEvent) => {
    e.preventDefault();
    setKeyError(null);
    setKeySuccess(false);
    setSubmitting(true);
    try {
      const res = await fetch("/api/license/key", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ key: licenseKey.trim() }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({ error: "Failed to submit license key" }));
        throw new Error(data.error || `HTTP ${res.status}`);
      }
      setKeySuccess(true);
      setLicenseKey("");
      setShowKeyForm(false);
      queryClient.invalidateQueries({ queryKey: ["license"] });
    } catch (err) {
      setKeyError(err instanceof Error ? err.message : "Failed to submit license key");
    } finally {
      setSubmitting(false);
    }
  };

  if (isLoading) {
    return (
      <div className="rounded-lg border border-border bg-card p-6">
        <p className="text-sm text-muted-foreground">Loading license information...</p>
      </div>
    );
  }

  if (!license) {
    return (
      <div className="rounded-lg border border-border bg-card p-6">
        <p className="text-sm text-muted-foreground">Unable to load license information.</p>
      </div>
    );
  }

  const isLicensed = license.mode === "licensed";

  const modeLabel = isLicensed
    ? `Licensed \u2014 ${license.licensee ?? "Unknown"}, ${capitalize(license.tier ?? "business")} tier${license.expires ? `, expires ${license.expires}` : ""}`
    : license.mode === "evaluation"
      ? "Evaluation"
      : "Community Edition";

  const licenseLabel = isLicensed
    ? "Cyber Hive Security Commercial License"
    : "PolyForm Shield 1.0.0 + CHS Use Agreement";

  const statusLabel = isLicensed
    ? `Licensed${license.days_remaining != null ? `, ${license.days_remaining} days remaining` : ""}`
    : license.acknowledged
      ? "Acknowledged \u2014 personal home use"
      : license.mode === "evaluation"
        ? `Evaluation${license.days_remaining != null ? `, ${license.days_remaining} days remaining` : ""}`
        : "Not yet acknowledged";

  return (
    <div className="space-y-6">
      <div className="rounded-lg border border-border bg-card p-6">
        <h2 className="text-lg font-semibold text-foreground mb-4">License</h2>

        <div className="space-y-3">
          <div className="flex items-baseline gap-3">
            <span className="text-sm font-medium text-muted-foreground w-20 flex-shrink-0">Mode:</span>
            <span className="text-sm text-foreground">{modeLabel}</span>
          </div>
          <div className="flex items-baseline gap-3">
            <span className="text-sm font-medium text-muted-foreground w-20 flex-shrink-0">License:</span>
            <span className="text-sm text-foreground">{licenseLabel}</span>
          </div>
          <div className="flex items-baseline gap-3">
            <span className="text-sm font-medium text-muted-foreground w-20 flex-shrink-0">Status:</span>
            <span className="text-sm text-foreground">{statusLabel}</span>
          </div>
          <div className="flex items-baseline gap-3">
            <span className="text-sm font-medium text-muted-foreground w-20 flex-shrink-0">Devices:</span>
            <span className="text-sm text-foreground">1 Router (full NDR) &middot; Unlimited infrastructure devices</span>
          </div>
        </div>
      </div>

      {/* Actions */}
      <div className="rounded-lg border border-border bg-card p-6 space-y-4">
        <div className="flex flex-wrap gap-3">
          <button
            onClick={() => { setShowKeyForm(!showKeyForm); setKeyError(null); setKeySuccess(false); }}
            className="rounded-md border border-input bg-background px-4 py-2 text-sm font-medium text-foreground hover:bg-accent hover:text-accent-foreground transition-colors"
          >
            Enter Commercial License Key
          </button>
          <a
            href="https://polyformproject.org/licenses/shield/1.0.0"
            target="_blank"
            rel="noopener noreferrer"
            className="rounded-md border border-input bg-background px-4 py-2 text-sm font-medium text-foreground hover:bg-accent hover:text-accent-foreground transition-colors"
          >
            View PolyForm Shield 1.0.0 License
          </a>
          <a
            href="/USE-AGREEMENT"
            target="_blank"
            rel="noopener noreferrer"
            className="rounded-md border border-input bg-background px-4 py-2 text-sm font-medium text-foreground hover:bg-accent hover:text-accent-foreground transition-colors"
          >
            View Cyber Hive Security Use Agreement
          </a>
        </div>

        {showKeyForm && (
          <form onSubmit={handleSubmitKey} className="space-y-3">
            <div>
              <label htmlFor="license-key" className="block text-sm font-medium text-foreground mb-1.5">
                License Key
              </label>
              <textarea
                id="license-key"
                value={licenseKey}
                onChange={(e) => setLicenseKey(e.target.value)}
                rows={4}
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring font-mono"
                placeholder="Paste your license key here..."
                required
              />
            </div>
            {keyError && (
              <div className="rounded-md bg-destructive/10 border border-destructive/20 p-3 text-sm text-destructive">
                {keyError}
              </div>
            )}
            {keySuccess && (
              <div className="rounded-md bg-emerald-500/10 border border-emerald-500/20 p-3 text-sm text-emerald-400">
                License key accepted successfully.
              </div>
            )}
            <div className="flex gap-2">
              <button
                type="submit"
                disabled={submitting || !licenseKey.trim()}
                className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {submitting ? "Submitting..." : "Submit"}
              </button>
              <button
                type="button"
                onClick={() => { setShowKeyForm(false); setKeyError(null); }}
                className="rounded-md border border-input bg-background px-4 py-2 text-sm font-medium text-foreground hover:bg-accent hover:text-accent-foreground transition-colors"
              >
                Cancel
              </button>
            </div>
          </form>
        )}
      </div>

      {/* Privacy notice */}
      <p className="text-xs text-muted-foreground italic">
        Ion Drift does not collect telemetry or communicate externally.
      </p>
    </div>
  );
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
